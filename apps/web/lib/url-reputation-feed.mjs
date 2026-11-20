import { createPublicKey, verify } from 'node:crypto'
import { inspectionHostname } from './url-inspection-policy.mjs'

const day = 86400000

export function verifiedUrlReputation(document, publicKey, now = Date.now()) {
  try {
    if (typeof document !== 'string' || document.length > 524288 || !publicKey) return null
    const envelope = JSON.parse(document)
    if (typeof envelope?.payload !== 'string' || typeof envelope?.signature !== 'string' ||
        !/^[A-Za-z0-9_-]{86}$/.test(envelope.signature)) return null
    const key = createPublicKey(publicKey)
    const signature = Buffer.from(envelope.signature, 'base64url')
    if (key.asymmetricKeyType !== 'ed25519' || !verify(null, Buffer.from(envelope.payload), key, signature)) return null
    const { source, issued, expires, domains } = JSON.parse(envelope.payload)
    const start = Date.parse(issued)
    const end = Date.parse(expires)
    if (typeof source !== 'string' || !/^[a-zA-Z0-9 ._-]{1,60}$/.test(source) ||
        !Number.isFinite(start) || !Number.isFinite(end) || start > now || end <= now || end - start > 30 * day ||
        end <= start || !Array.isArray(domains) || domains.length > 4096) return null
    const entries = new Map()
    for (const item of domains) {
      if (!inspectionHostname(item?.domain) || entries.has(item.domain) ||
          !['risk-listed', 'observed'].includes(item.reputation) ||
          (item.registered !== null && (!/^\d{4}-\d{2}-\d{2}$/.test(item.registered) ||
            !Number.isFinite(Date.parse(item.registered)) || Date.parse(item.registered) > start ||
            new Date(item.registered).toISOString().slice(0,10) !== item.registered))) return null
      entries.set(item.domain, { reputation: item.reputation, registered: item.registered })
    }
    return { source, start, end, entries }
  } catch { return null }
}

export function urlReputation(host, feed, now = Date.now()) {
  if (!feed || feed.end <= now || now < feed.start) return { status: 'unavailable' }
  const labels = host.split('.')
  for (let start = 0; start < labels.length - 1; start++) {
    const domain = labels.slice(start).join('.')
    const entry = feed.entries.get(domain)
    if (entry) return { status: entry.reputation, source: feed.source, domain, registered: entry.registered,
      recent: entry.registered !== null && now - Date.parse(entry.registered) < 30 * day }
  }
  return { status: 'unlisted', source: feed.source }
}
