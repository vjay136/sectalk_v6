import type { LocalDevice } from './device-identity'

const storeName = 'records'
const databaseName = 'sectalk-encrypted-group-search'
const sessionGroupLimit = 20
const messagesPerGroup = 200
const encoder = new TextEncoder()
const decoder = new TextDecoder('utf-8', { fatal: true })

export type LocalSearchMessage = { id: string; sent: string; epoch: number; text: string }
export type GroupSearchMetadata = { device: string; messages: Array<Omit<LocalSearchMessage, 'text'>> }
type IndexEntry = {
  owner: string; device: string; group: string; id: string; epoch: number; sent: string
  iv: Uint8Array<ArrayBuffer>; sealed: ArrayBuffer
}

function openIndex() {
  return new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(databaseName, 1)
    request.onupgradeneeded = () => {
      const store = request.result.createObjectStore(storeName, { keyPath: ['owner', 'device', 'group', 'id'] })
      store.createIndex('owner', 'owner')
      store.createIndex('group', ['owner', 'device', 'group'])
    }
    request.onerror = () => reject(request.error)
    request.onsuccess = () => {
      request.result.onversionchange = () => request.result.close()
      resolve(request.result)
    }
  })
}

function result<T>(request: IDBRequest<T>) {
  return new Promise<T>((resolve, reject) => {
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error)
  })
}

function complete(transaction: IDBTransaction) {
  return new Promise<void>((resolve, reject) => {
    transaction.oncomplete = () => resolve()
    transaction.onabort = () => reject(transaction.error ?? new Error('Encrypted search index transaction aborted'))
  })
}

async function useStore<T>(mode: IDBTransactionMode, work: (store: IDBObjectStore) => T | Promise<T>) {
  const database = await openIndex()
  try {
    const transaction = database.transaction(storeName, mode)
    const done = complete(transaction)
    const value = Promise.resolve().then(() => work(transaction.objectStore(storeName)))
    const [answer] = await Promise.all([value, done])
    return answer
  } finally {
    database.close()
  }
}

function additionalData(entry: Omit<IndexEntry, 'sealed' | 'iv'>) {
  return encoder.encode(JSON.stringify(['sectalk-index-entry-v1', entry.owner, entry.device, entry.group, entry.id, entry.epoch, entry.sent]))
}

async function indexKey(device: LocalDevice, group: string) {
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: device.agreement.publicKey },
    device.agreement.privateKey, 256)
  try {
    const input = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey'])
    return await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256',
      salt: encoder.encode('sectalk-local-encrypted-group-search-v1'),
      info: encoder.encode(JSON.stringify([device.owner, device.id, group])),
    }, input, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
  } finally {
    new Uint8Array(shared).fill(0)
  }
}

async function records(device: LocalDevice, group: string) {
  return useStore('readonly', store => result<IndexEntry[]>(store.index('group').getAll([device.owner, device.id, group])))
}

function entryKey(entry: IndexEntry) {
  return [entry.owner, entry.device, entry.group, entry.id]
}

function newestFirst(first: Pick<IndexEntry, 'sent' | 'id'>, second: Pick<IndexEntry, 'sent' | 'id'>) {
  return second.sent.localeCompare(first.sent) || second.id.localeCompare(first.id)
}

export async function rememberGroupMessages(device: LocalDevice, group: string, rows: LocalSearchMessage[]) {
  const cached = await records(device, group)
  const present = new Set(cached.map(entry => entry.id))
  const fresh = rows.filter(row => !present.has(row.id))
  if (!fresh.length) return
  const key = await indexKey(device, group)
  const sealed = await Promise.all(fresh.map(async ({ id, sent, epoch, text }): Promise<IndexEntry> => {
    const identity = { owner: device.owner, device: device.id, group, id, epoch, sent }
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: additionalData(identity) },
      key, encoder.encode(text))
    return { ...identity, iv, sealed: encrypted }
  }))
  await useStore('readwrite', async store => {
    for (const entry of sealed) store.put(entry)
    const entries = await result<IndexEntry[]>(store.index('owner').getAll(device.owner))
    const groups = [...new Set(entries.filter(entry => entry.device === device.id).sort(newestFirst).map(entry => entry.group))]
    const keep = new Set(groups.slice(0, sessionGroupLimit))
    const allForGroup = entries.filter(entry => entry.device === device.id && entry.group === group).sort(newestFirst)
    for (const entry of allForGroup.slice(messagesPerGroup)) store.delete(entryKey(entry))
    for (const entry of entries) if (entry.device === device.id && !keep.has(entry.group)) store.delete(entryKey(entry))
  })
}

export async function pruneGroupIndex(owner: string, allowed: ReadonlySet<string>) {
  await useStore('readwrite', async store => {
    const keys = await result<IDBValidKey[]>(store.index('owner').getAllKeys(owner))
    for (const key of keys) {
      if (Array.isArray(key) && typeof key[2] === 'string' && !allowed.has(key[2])) store.delete(key)
    }
  })
}

export async function clearGroupIndex(owner: string, group: string) {
  await useStore('readwrite', async store => {
    const keys = await result<IDBValidKey[]>(store.index('owner').getAllKeys(owner))
    for (const key of keys) if (Array.isArray(key) && key[2] === group) store.delete(key)
  })
}

function searchable(text: string) {
  return text.normalize('NFKC').replace(/\p{Cf}/gu, '').toLowerCase()
}

export async function findGroupMessages(device: LocalDevice, group: string, query: string, scope: GroupSearchMetadata) {
  if (scope.device !== device.id || !Array.isArray(scope.messages) || scope.messages.length > messagesPerGroup) {
    throw new Error('Encrypted search access changed')
  }
  const normalized = searchable(query).trim()
  if (normalized.length < 2 || query.length > 120) return []
  const terms = normalized.split(/\s+/)
  const allowed = new Map(scope.messages.map(item => [item.id, item]))
  const all = await records(device, group)
  const local = all.filter(entry => {
    const metadata = allowed.get(entry.id)
    return metadata?.epoch === entry.epoch && metadata.sent === entry.sent
  }).sort(newestFirst)
  const retained = new Set(local.map(entry => entry.id))
  const stale = all.filter(entry => !retained.has(entry.id))
  if (stale.length) await useStore('readwrite', store => {
    for (const entry of stale) store.delete(entryKey(entry))
  })
  if (!local.length) return []
  const key = await indexKey(device, group)
  const matches: LocalSearchMessage[] = []
  for (const entry of local) {
    try {
      const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: entry.iv, additionalData: additionalData(entry) }, key, entry.sealed)
      const text = decoder.decode(plain)
      if (terms.every(term => searchable(text).includes(term))) matches.push({ id: entry.id, sent: entry.sent, epoch: entry.epoch, text })
    } catch { /* Stale or corrupt local ciphertext supplies no search result. */ }
    if (matches.length === 25) break
  }
  return matches
}
