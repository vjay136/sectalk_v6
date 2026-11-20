import { base64urlToBinary, binaryToBase64url, deviceBundleTranscript } from './device-bundle'
import { keyStore, openDeviceStore, type LocalDevice } from './device-identity'
import type { ManifestEntry } from './contact-key-verification'

const encoder = new TextEncoder()
const decoder = new TextDecoder('utf-8', { fatal: true })
const signingAlgorithm = { name: 'ECDSA', hash: 'SHA-256' }
const agreementAlgorithm = { name: 'ECDH', namedCurve: 'P-256' }
const data = (fields: unknown[]) => encoder.encode(JSON.stringify(['sectalk-group-chat-v1', ...fields]))

export type GroupEnvelope = { epoch: number; sealed: string; ephemeral: string }
export type GroupCiphertext = {
  id: string; epoch: number; actor: string; device: string; signing: string; payload: string; signature: string; sent: string
}

export async function groupLocalDevice(owner: string, id: string) {
  const store = await openDeviceStore()
  try {
    const device = await new Promise<LocalDevice | undefined>((resolve, reject) => {
      const request = store.transaction(keyStore).objectStore(keyStore).get(owner)
      request.onsuccess = () => resolve(request.result)
      request.onerror = () => reject(request.error)
    })
    if (!device || device.id !== id) throw new Error('This signed-in device has no local group keys.')
    return device
  } finally {
    store.close()
  }
}

async function wrappingKey(privateKey: CryptoKey, publicKey: CryptoKey, context: Uint8Array<ArrayBuffer>) {
  const bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256)
  const input = await crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey'])
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: context },
    input, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
}

async function seal(key: CryptoKey, cleartext: Uint8Array<ArrayBuffer>, additionalData: Uint8Array<ArrayBuffer>) {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData }, key, cleartext)
  const out = new Uint8Array(iv.length + encrypted.byteLength)
  out.set(iv)
  out.set(new Uint8Array(encrypted), iv.length)
  return binaryToBase64url(out.buffer)
}

async function unseal(key: CryptoKey, blob: string, additionalData: Uint8Array<ArrayBuffer>) {
  const bytes = base64urlToBinary(blob)
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.subarray(0, 12), additionalData }, key, bytes.subarray(12))
}

export async function rotateGroupKey(group: string, epoch: number, entries: ManifestEntry[]) {
  const shared = crypto.getRandomValues(new Uint8Array(32))
  const keyPair = await crypto.subtle.generateKey(agreementAlgorithm, false, ['deriveBits'])
  const ephemeral = binaryToBase64url(await crypto.subtle.exportKey('raw', keyPair.publicKey))
  try {
    return Object.fromEntries(await Promise.all(entries.map(async entry => {
      const signing = await crypto.subtle.importKey('raw', base64urlToBinary(entry.signing_key),
        { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
      const valid = await crypto.subtle.verify(signingAlgorithm, signing, base64urlToBinary(entry.bundle_signature),
        deviceBundleTranscript({ owner: entry.owner_id, device: entry.device, signing: entry.signing_key, agreement: entry.agreement_key }))
      if (!valid) throw new Error('An approved device bundle failed signature validation.')
      const peer = await crypto.subtle.importKey('raw', base64urlToBinary(entry.agreement_key), agreementAlgorithm, false, [])
      const context = data(['wrap', group, epoch, entry.owner_id, entry.device, ephemeral])
      return [entry.device, { ephemeral, sealed: await seal(await wrappingKey(keyPair.privateKey, peer, context), shared, context) }]
    })))
  } finally {
    shared.fill(0)
  }
}

export async function openGroupKey(group: string, device: LocalDevice, envelope: GroupEnvelope) {
  const publicKey = await crypto.subtle.importKey('raw', base64urlToBinary(envelope.ephemeral), agreementAlgorithm, false, [])
  const context = data(['wrap', group, envelope.epoch, device.owner, device.id, envelope.ephemeral])
  const raw = await unseal(await wrappingKey(device.agreement.privateKey, publicKey, context), envelope.sealed, context)
  try {
    return await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt'])
  } finally {
    new Uint8Array(raw).fill(0)
  }
}

export async function encryptGroupMessage(group: string, epoch: number, device: LocalDevice, key: CryptoKey, message: string) {
  const bytes = encoder.encode(message)
  if (!message.trim() || bytes.length > 4000) throw new Error('Enter a message of up to 4,000 UTF-8 bytes.')
  const id = crypto.randomUUID()
  const header = [group, epoch, id, device.owner, device.id]
  const payload = await seal(key, bytes, data(['message', ...header]))
  const signature = binaryToBase64url(await crypto.subtle.sign(signingAlgorithm, device.signing.privateKey, data(['sign', ...header, payload])))
  return { id, epoch, payload, signature }
}

export async function decryptGroupMessage(group: string, key: CryptoKey, message: GroupCiphertext) {
  const header = [group, message.epoch, message.id, message.actor, message.device]
  const signingKey = await crypto.subtle.importKey('raw', base64urlToBinary(message.signing),
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
  if (!await crypto.subtle.verify(signingAlgorithm, signingKey, base64urlToBinary(message.signature),
    data(['sign', ...header, message.payload]))) throw new Error('Message signature verification failed.')
  return decoder.decode(await unseal(key, message.payload, data(['message', ...header])))
}
