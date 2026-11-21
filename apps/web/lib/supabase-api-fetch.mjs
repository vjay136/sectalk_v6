export function supabaseApiFetch(key, request = fetch) {
  const modernKey = key.startsWith('sb_secret_') || key.startsWith('sb_publishable_')
  return (input, options) => {
    const headers = new Headers(options?.headers)
    if (modernKey && headers.get('authorization') === `Bearer ${key}`) {
      headers.delete('authorization')
    }
    return request(input, { ...options, headers, redirect: 'error' })
  }
}
