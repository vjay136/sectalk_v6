type PublicDatabase = { url?: string; key?: string }
type Surface = 'web' | 'admin' | 'workers'

export async function checkReadiness(config: PublicDatabase, request: typeof fetch = fetch, surface: Surface = 'web') {
  if (!config.url || !config.key) return false
  try {
    const endpoint = new URL('/rest/v1/rpc/st_v8_release_ready', config.url)
    if (!['http:', 'https:'].includes(endpoint.protocol)) return false
    const response = await request(endpoint, {
      method: 'POST',
      cache: 'no-store',
      redirect: 'error',
      headers: { apikey: config.key, 'Content-Type': 'application/json' },
      body: JSON.stringify({ p_surface: surface }),
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

export async function readinessResponse(surface: Surface) {
  const ready = await checkConfiguredDatabase(surface)
  return Response.json({ status: ready ? 'ready' : 'not_ready' }, {
    status: ready ? 200 : 503,
    headers: { 'Cache-Control': 'no-store' },
  })
}
