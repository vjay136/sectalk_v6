import { db } from './data'
import { binaryToBase64url } from './device-bundle'
import { groupLocalDevice } from './group-chat-crypto'
import { reputationLinkTranscript, type ReputationLinkProof } from './reputation-link-proof'

async function browserAlias(): Promise<CryptoKeyPair> {
  const candidate = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify'])
  return new Promise((resolve, reject) => {
    const open = indexedDB.open('sectalk-consented-browser-alias', 1)
    open.onupgradeneeded = () => { open.result.createObjectStore('keys') }
    open.onerror = () => reject(open.error)
    open.onsuccess = () => {
      const transaction = open.result.transaction('keys', 'readwrite')
      const store = transaction.objectStore('keys')
      const read = store.get('installation')
      let chosen = candidate
      read.onsuccess = () => {
        if (read.result) chosen = read.result as CryptoKeyPair
        else store.put(candidate, 'installation')
      }
      transaction.oncomplete = () => { open.result.close(); resolve(chosen) }
      transaction.onabort = () => { open.result.close(); reject(transaction.error) }
    }
  })
}

export async function verifyReputationBrowserLink() {
  const { data } = await db!.auth.getSession()
  if (!data.session) throw new Error('Sign in on an approved browser')
  const alias = await browserAlias()
  const aliasPublic = binaryToBase64url(await crypto.subtle.exportKey('raw', alias.publicKey))
  const reply = await db!.rpc('st_v7_manage_browser_reputation_link', { p_action: 'begin', p_alias: aliasPublic })
  const proof = reply.data as ReputationLinkProof | null
  if (reply.error || !proof || proof.owner !== data.session.user.id || proof.alias !== aliasPublic) throw new Error('Approved device required')
  const device = await groupLocalDevice(proof.owner, proof.device)
  const algorithm = { name: 'ECDSA', hash: 'SHA-256' }
  const input = reputationLinkTranscript(proof)
  const [identity, installation] = await Promise.all([
    crypto.subtle.sign(algorithm, device.signing.privateKey, input).then(binaryToBase64url),
    crypto.subtle.sign(algorithm, alias.privateKey, input).then(binaryToBase64url),
  ])
  const response = await fetch('/api/account/devices/reputation-link', { method: 'POST',
    headers: { Authorization: 'Bearer ' + data.session.access_token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ challenge: proof.challenge, identity, installation }),
  })
  if (!response.ok) throw new Error('Browser verification failed')
}
