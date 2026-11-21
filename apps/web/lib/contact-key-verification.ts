import { base64urlToBinary, deviceBundleContract, deviceBundleTranscript } from './device-bundle'

export type ManifestEntry = {
  owner_id: string; device: string; signing_key: string; agreement_key: string; bundle_signature: string
}
const ECDSA = { name: 'ECDSA', hash: 'SHA-256' }

export const contactKeyStorage=(owner:string,peer:string)=>`sectalk:verified-contact-keys:v1:${owner}:${peer}`

function formatOrder(first: ManifestEntry, second: ManifestEntry) {
  const a = first.owner_id + ':' + first.device
  const b = second.owner_id + ':' + second.device
  return a < b ? -1 : a > b ? 1 : 0
}

export async function contactSafetyNumber(entries: ManifestEntry[], owner: string, peer: string) {
  if (owner === peer || entries.length > 128 || !entries.some(entry => entry.owner_id === owner)
    || !entries.some(entry => entry.owner_id === peer)
    || new Set(entries.map(entry => entry.device)).size !== entries.length) return null
  const ordered = [...entries].sort(formatOrder)
  const verified = await Promise.all(ordered.map(async entry => {
    if ((entry.owner_id !== owner && entry.owner_id !== peer)
      || !deviceBundleContract.uuid.test(entry.device) || !deviceBundleContract.key.test(entry.signing_key)
      || !deviceBundleContract.key.test(entry.agreement_key) || !deviceBundleContract.signature.test(entry.bundle_signature)) return false
    try {
      const key = await crypto.subtle.importKey('raw', base64urlToBinary(entry.signing_key),
        { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
      return await crypto.subtle.verify(ECDSA, key, base64urlToBinary(entry.bundle_signature), deviceBundleTranscript({
        owner: entry.owner_id, device: entry.device, signing: entry.signing_key, agreement: entry.agreement_key,
      }))
    } catch { return false }
  }))
  if (verified.some(result => !result)) throw new Error('Invalid signed device key bundle.')
  const transcript = JSON.stringify(['sectalk-contact-safety-v1',
    ordered.map(entry => [entry.owner_id, entry.device, entry.signing_key, entry.agreement_key])])
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(transcript))
  const fingerprint = [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('')
  const number = (BigInt('0x' + fingerprint) % 10n ** 60n).toString().padStart(60, '0').match(/.{5}/g)!.join(' ')
  return { fingerprint, number, qrValue: 'SECTALK-KEYS-V1:' + fingerprint.toUpperCase() }
}
