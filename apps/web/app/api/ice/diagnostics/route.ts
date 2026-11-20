import { createHmac, randomUUID } from 'node:crypto'
import { isIP } from 'node:net'
import { createClient } from '@supabase/supabase-js'
import type { DiagnosticConfiguration, RelayKind } from '../../../../lib/network-diagnostics'

export const runtime = 'nodejs'
const headers = { 'Cache-Control': 'private, no-store', Vary: 'Authorization' }
const leaseSeconds = 90

function parsedEndpoint(value: string) {
  const match = /^(stun|turn|turns):(\[[a-f0-9.:]+\]|[a-z0-9][a-z0-9.-]*)(?::(\d{1,5}))?(?:\?transport=(udp|tcp))?$/i.exec(value)
  if (!match) return null
  const [, rawScheme, rawHost, rawPort, rawTransport] = match
  const scheme = rawScheme.toLowerCase()
  const host = rawHost.toLowerCase()
  const port = rawPort ? Number(rawPort) : scheme === 'turns' ? 5349 : 3478
  const transport = rawTransport?.toLowerCase()
  if (port < 1 || port > 65535 || (host.startsWith('[') && isIP(host.slice(1, -1)) !== 6)) return null
  if ((scheme === 'stun' && transport) || (scheme === 'turns' && transport === 'udp')) return null
  return { scheme, host, port, transport }
}

function relayKind(endpoint: NonNullable<ReturnType<typeof parsedEndpoint>>): RelayKind | undefined {
  if (endpoint.scheme === 'turns') return endpoint.port === 443 ? 'tls' : undefined
  if (endpoint.scheme === 'turn') return endpoint.transport === 'tcp' ? 'tcp' : 'udp'
}

function fail(error: string, status: number, retry = false) {
  return Response.json({ error }, { status, headers: retry ? { ...headers, 'Retry-After': '60' } : headers })
}

export async function POST(request: Request) {
  const token = request.headers.get('Authorization')?.match(/^Bearer (\S+)$/i)?.[1]
  if (!token) return fail('Sign in to run network diagnostics.', 401)
  const { NEXT_PUBLIC_SUPABASE_URL: url, NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: key,
    CALL_DIAGNOSTICS_STUN_URL: diagnosticStun, STUN_URL: standardStun,
    CALL_DIAGNOSTICS_TURN_SECRET: secret, TURN_SHARED_SECRET: standardSecret } = process.env
  if (!url || !key) return fail('Network diagnostics are temporarily unavailable.', 503)
  const client = createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
    global: { headers: { Authorization: 'Bearer ' + token } },
  })
  const auth = await client.auth.getUser(token)
  if (auth.error || !auth.data.user) return fail('Sign in to run network diagnostics.', 401)
  const access = await client.rpc('st_v6_network_diagnostic_run')
  if (access.error?.code === 'PT429') return fail('Too many diagnostic runs. Try again in a minute.', 429, true)
  if (access.error) return fail('Network diagnostics are temporarily unavailable.', 503)
  if (!access.data) return fail('Network diagnostics are unavailable for this account.', 403)

  const stunUrl = diagnosticStun ?? standardStun ?? 'stun:stun.l.google.com:19302'
  const stun = parsedEndpoint(stunUrl)
  const result: DiagnosticConfiguration = {
    stun: stun?.scheme === 'stun' ? { urls: stunUrl } : null, relays: {}, bandwidth: false,
  }
  const regular = (process.env.TURN_URLS ?? '').split(',').flatMap(value => {
    const endpoint = parsedEndpoint(value.trim())
    return endpoint ? [endpoint.host + ':' + endpoint.port] : []
  })
  if (secret?.trim() && secret !== standardSecret) {
    for (const value of (process.env.CALL_DIAGNOSTICS_TURN_URLS ?? '').split(',')) {
      const candidate = value.trim()
      const endpoint = parsedEndpoint(candidate)
      const kind = endpoint && relayKind(endpoint)
      if (!endpoint || !kind || result.relays[kind] || regular.includes(endpoint.host + ':' + endpoint.port)) continue
      const expiry = Math.floor(Date.now() / 1000) + leaseSeconds
      const principal = createHmac('sha256', secret)
        .update('sectalk:diagnostics:' + kind + ':' + auth.data.user.id + ':' + randomUUID()).digest('hex').slice(0, 32)
      const username = expiry + ':' + principal
      result.relays[kind] = { urls: candidate, username, credential: createHmac('sha1', secret).update(username).digest('base64') }
    }
  }
  result.bandwidth = process.env.CALL_DIAGNOSTICS_BANDWIDTH === '1' && Object.keys(result.relays).length > 0
  return Response.json(result, { headers })
}
