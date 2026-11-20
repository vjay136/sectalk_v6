import { createHmac } from 'node:crypto'
import { isIP } from 'node:net'
import { createClient } from '@supabase/supabase-js'
import { logProviderFailure } from '../../../lib/provider-log.mjs'

export const runtime = 'nodejs'

const maxLeaseSeconds = 5 * 60
const uuid = /^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/i
const headers = { 'Cache-Control': 'private, no-store', Vary: 'Authorization' }

function validIceUrl(value: string, relay: boolean) {
  const match = /^(stuns?|turns?):(\[[a-f0-9.:]+\]|[a-z0-9][a-z0-9.-]*)(?::(\d{1,5}))?(?:\?transport=(udp|tcp))?$/i.exec(value)
  if (!match) return false
  const [, scheme, host, port, transport] = match
  if (host.startsWith('[') && isIP(host.slice(1, -1)) !== 6) return false
  if (port && (+port < 1 || +port > 65535)) return false
  if (!relay) return /^stuns?$/i.test(scheme) && !transport
  return /^turns?$/i.test(scheme) && !(scheme.toLowerCase() === 'turns' && transport?.toLowerCase() === 'udp')
}

export async function GET(request: Request) {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL
  const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY
  const token = request.headers.get('Authorization')?.match(/^Bearer (\S+)$/i)?.[1]
  if (!token) return Response.json({ error: 'Sign in required' }, { status: 401, headers })
  const call = new URL(request.url).searchParams.get('call')
  if (!call || !uuid.test(call)) return Response.json({ error: 'Valid call required' }, { status: 400, headers })
  if (!url || !key) return Response.json({ error: 'Call networking unavailable' }, { status: 503, headers })
  const client = createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
    global: { headers: { Authorization: 'Bearer ' + token } },
  })
  const identity = await client.auth.getUser(token)
  if (identity.error || !identity.data.user) return Response.json({ error: 'Sign in required' }, { status: 401, headers })

  const access = await client.rpc('st_v6_call_ice_session', { p_call: call })
  if (access.error?.code === 'PT429') {
    return Response.json({ error: 'Try again in a minute' }, { status: 429, headers: { ...headers, 'Retry-After': '60' } })
  }
  if (access.error) {
    logProviderFailure('call_networking','unavailable')
    return Response.json({ error: 'Call networking unavailable' }, { status: 503, headers })
  }
  const now = Math.floor(Date.now() / 1000)
  const callEnd = typeof access.data === 'string' ? Math.floor(Date.parse(access.data) / 1000) : NaN
  if (!Number.isFinite(callEnd) || callEnd <= now) return Response.json({ error: 'Call unavailable' }, { status: 403, headers })

  const turnSecret = process.env.TURN_SHARED_SECRET
  const turnUrls = process.env.TURN_URLS?.trim()
  const urls = turnUrls ? turnUrls.split(',').map(value => value.trim()) : []
  const stun = process.env.STUN_URL || 'stun:stun.l.google.com:19302'
  const relay = Boolean(turnSecret || urls.length)
  if (!validIceUrl(stun, false) || (relay && (!turnSecret?.trim() || !urls.length || !urls.every(value => validIceUrl(value, true))))) {
    return Response.json({ error: 'Call networking unavailable' }, { status: 503, headers })
  }

  const iceServers: RTCIceServer[] = [{ urls: stun }]
  let ttlSeconds: number | null = null
  if (turnSecret) {
    const expiry = Math.min(now + maxLeaseSeconds, callEnd)
    const principal = createHmac('sha256', turnSecret)
      .update('sectalk:turn:' + call.toLowerCase() + ':' + identity.data.user.id)
      .digest('hex').slice(0, 32)
    const username = expiry + ':' + principal
    const credential = createHmac('sha1', turnSecret).update(username).digest('base64')
    iceServers.push({ urls, username, credential })
    ttlSeconds = expiry - now
  }
  return Response.json({ iceServers, iceTransportPolicy: relay ? 'relay' : 'all', ttlSeconds }, { headers })
}
