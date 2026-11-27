import { createHmac } from 'node:crypto'
import { isIP } from 'node:net'

const maxLeaseSeconds = 5 * 60
const turnixTimeoutMs = 3000

type IceConfiguration = {
  iceServers: RTCIceServer[]
  iceTransportPolicy: RTCIceTransportPolicy
  ttlSeconds: number | null
}

function validIceUrl(value: string, relay: boolean) {
  const match = /^(stuns?|turns?):(\[[a-f0-9.:]+\]|[a-z0-9][a-z0-9.-]*)(?::(\d{1,5}))?(?:\?transport=(udp|tcp))?$/i.exec(value)
  if (!match) return false
  const [, scheme, host, port, transport] = match
  if (host.startsWith('[') && isIP(host.slice(1, -1)) !== 6) return false
  if (port && (+port < 1 || +port > 65535)) return false
  if (!relay) return /^stuns?$/i.test(scheme) && !transport
  return /^turns?$/i.test(scheme) && !(scheme.toLowerCase() === 'turns' && transport?.toLowerCase() === 'udp')
}

async function turnixRelay(token: string, ttl: number, request: typeof fetch) {
  const response = await request('https://turnix.io/api/v1/credentials/ice', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ ttl }),
    redirect: 'error',
    cache: 'no-store',
    signal: AbortSignal.timeout(turnixTimeoutMs),
  })
  if (response.status !== 200) throw new Error('TURN provider unavailable')
  const data = await response.json()
  const expiresAt = typeof data?.expiresAt === 'string' ? Date.parse(data.expiresAt) : NaN
  if (!Array.isArray(data?.iceServers) || !Number.isFinite(expiresAt)) throw new Error('Invalid TURN provider response')
  const relays: RTCIceServer[] = []
  for (const server of data.iceServers) {
    if (typeof server?.username !== 'string' || !/^[!-~]{1,512}$/.test(server.username) ||
      typeof server.credential !== 'string' || !/^[!-~]{1,512}$/.test(server.credential) ||
      server.username.includes(token) || server.credential.includes(token)) continue
    const urls = (Array.isArray(server.urls) ? server.urls : [server.urls]).filter((value: unknown): value is string =>
      typeof value === 'string' && /^(turn:[a-z0-9-]+\.turnix\.io:3478\?transport=(?:udp|tcp)|turns:[a-z0-9-]+\.turnix\.io:443\?transport=tcp)$/i.test(value))
    if (urls.length) relays.push({ urls: [...new Set<string>(urls)], username: server.username, credential: server.credential })
  }
  if (!relays.length) throw new Error('TURN provider returned no usable relays')
  return { relays, expiresAt }
}

export async function callIceServers(expiresAt: number, scope: string, env = process.env, request = fetch): Promise<IceConfiguration> {
  const started = Date.now()
  const now = Math.floor(started / 1000)
  const expiry = Math.min(now + maxLeaseSeconds, Math.floor(expiresAt / 1000))
  const stun = env.STUN_URL || 'stun:stun.l.google.com:19302'
  if (!Number.isFinite(expiry) || expiry <= now || !validIceUrl(stun, false)) throw new Error('Invalid call ICE configuration')
  const iceServers: RTCIceServer[] = [{ urls: stun }]
  const secret = env.TURN_SHARED_SECRET
  const turnUrls = env.TURN_URLS?.trim()
  const urls = turnUrls ? turnUrls.split(',').map(value => value.trim()) : []
  const coturn = Boolean(secret || urls.length)
  const turnixToken = env.TURNIX_API_TOKEN
  if (coturn && turnixToken) throw new Error('Configure one TURN provider')
  if (coturn) {
    if (!secret?.trim() || !urls.length || !urls.every(value => validIceUrl(value, true))) throw new Error('Invalid Coturn configuration')
    const principal = createHmac('sha256', secret).update(scope).digest('hex').slice(0, 32)
    const username = expiry + ':' + principal
    iceServers.push({ urls, username, credential: createHmac('sha1', secret).update(username).digest('base64') })
    return { iceServers, iceTransportPolicy: 'relay', ttlSeconds: expiry - now }
  }
  if (turnixToken) {
    if (!/^[!-~]{1,512}$/.test(turnixToken)) throw new Error('Invalid Turnix configuration')
    // Turnix starts the lease when it receives the request. Reserve time for the network hop.
    const authorizedUntil = Math.min(started + maxLeaseSeconds * 1000, expiresAt)
    const ttl = Math.floor((authorizedUntil - started - turnixTimeoutMs) / 1000)
    if (ttl < 1) throw new Error('Call is ending')
    const relay = await turnixRelay(turnixToken, ttl, request)
    const issued = Date.now()
    if (relay.expiresAt > authorizedUntil) throw new Error('Invalid TURN provider expiry')
    const ttlSeconds = Math.floor((relay.expiresAt - issued) / 1000)
    if (ttlSeconds < 1) throw new Error('Call is ending')
    return { iceServers: [...iceServers, ...relay.relays], iceTransportPolicy: 'relay', ttlSeconds }
  }
  return { iceServers, iceTransportPolicy: 'all', ttlSeconds: null }
}
