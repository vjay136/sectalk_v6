type PublicDatabase = { url?: string; key?: string }

export async function checkReadiness(config: PublicDatabase, request: typeof fetch = fetch) {
  if (!config.url || !config.key) return false
  try {
    const endpoint = new URL('/rest/v1/rpc/st_v6_ready', config.url)
    if (!['http:', 'https:'].includes(endpoint.protocol)) return false
    const response = await request(endpoint, {
      method: 'POST',
      cache: 'no-store',
      headers: { apikey: config.key, 'Content-Type': 'application/json' },
      body: '{}',
      signal: AbortSignal.timeout(2500),
    })
    return response.ok && (await response.json()) === true
  } catch {
    return false
  }
}

export function checkConfiguredDatabase() {
  return checkReadiness({
    url: process.env.NEXT_PUBLIC_SUPABASE_URL,
    key: process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY,
  })
}
