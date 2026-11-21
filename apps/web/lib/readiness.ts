import { supabaseApiFetch } from './supabase-api-fetch.mjs'

type DatabaseProbeConfig = { url?: string; key?: string }
type Surface = 'web' | 'admin' | 'workers'

export async function checkReadiness(config: DatabaseProbeConfig, request: typeof fetch = fetch, surface: Surface = 'web') {
  return checkDatabaseProbe(config, 'st_v8_release_ready', {p_surface: surface}, request)
}

export async function checkSignupServiceReadiness(config: DatabaseProbeConfig, request: typeof fetch = fetch) {
  return checkDatabaseProbe(config, 'st_v8_signup_service_ready', {}, request)
}

export async function attachmentReadinessStatus(
  config: DatabaseProbeConfig & { publishableKey?: string; ticketSecret?: string }, request: typeof fetch = fetch,
) {
  const {url, key, publishableKey, ticketSecret}=config
  if (!ticketSecret || Buffer.byteLength(ticketSecret)<32 || ticketSecret===key) return 'invalid_ticket_secret'
  if (!url || !key || key===publishableKey || key.startsWith('sb_publishable_')) return 'invalid_storage_configuration'
  try {
    const endpoint=new URL('/storage/v1/bucket/sectalk-chat-files',url)
    if (!['http:','https:'].includes(endpoint.protocol)) return 'invalid_storage_configuration'
    const response=await supabaseApiFetch(key,request)(endpoint,{
      method:'GET',cache:'no-store',headers:{apikey:key,Authorization:`Bearer ${key}`},
      signal:AbortSignal.timeout(2500),
    })
    if (response.status===401 || response.status===403) return 'storage_key_rejected'
    if (!response.ok) return 'storage_unavailable'
    const bucket=await response.json()
    return bucket?.id==='sectalk-chat-files' && bucket.public===false ? 'ready' : 'private_bucket_not_verified'
  } catch {
    return 'storage_unavailable'
  }
}

async function checkDatabaseProbe(config: DatabaseProbeConfig, rpc: string, args: object, request: typeof fetch) {
  if (!config.url || !config.key) return false
  try {
    const endpoint = new URL(`/rest/v1/rpc/${rpc}`, config.url)
    if (!['http:', 'https:'].includes(endpoint.protocol)) return false
    const response = await request(endpoint, {
      method: 'POST',
      cache: 'no-store',
      redirect: 'error',
      headers: { apikey: config.key, 'Content-Type': 'application/json' },
      body: JSON.stringify(args),
      signal: AbortSignal.timeout(2500),
    })
    return response.ok && (await response.json()) === true
  } catch {
    return false
  }
}

export function checkConfiguredDatabase(surface: Surface = 'web') {
  return checkReadiness({
    url: process.env.NEXT_PUBLIC_SUPABASE_URL,
    key: process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY,
  }, fetch, surface)
}

export async function readinessResponse(surface: Surface, appConfigured = true) {
  const ready = appConfigured && await checkConfiguredDatabase(surface)
  return Response.json({ status: ready ? 'ready' : 'not_ready' }, {
    status: ready ? 200 : 503,
    headers: { 'Cache-Control': 'no-store' },
  })
}
