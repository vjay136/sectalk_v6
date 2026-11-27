import { withOperationalMetrics } from '../../../lib/operational-metrics-server'
import { createClient } from '@supabase/supabase-js'
import { logProviderFailure } from '../../../lib/provider-log.mjs'
import { callIceServers } from '../../../lib/turn-ice-servers'

export const runtime = 'nodejs'

const uuid = /^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/i
const headers = { 'Cache-Control': 'private, no-store', Vary: 'Authorization' }

async function handleGet(request: Request) {
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
  const callEnd = typeof access.data === 'string' ? Date.parse(access.data) : NaN
  if (!Number.isFinite(callEnd) || Math.floor(callEnd / 1000) <= Math.floor(Date.now() / 1000)) {
    return Response.json({ error: 'Call unavailable' }, { status: 403, headers })
  }
  try {
    const config = await callIceServers(callEnd, 'sectalk:turn:' + call.toLowerCase() + ':' + identity.data.user.id)
    return Response.json(config, { headers })
  } catch {
    logProviderFailure('call_networking', 'unavailable')
    return Response.json({ error: 'Call networking unavailable' }, { status: 503, headers })
  }
}

export async function GET(request: Request) {
  return withOperationalMetrics('call_ice', () => handleGet(request))
}
