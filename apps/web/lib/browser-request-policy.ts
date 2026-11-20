import { backgroundModel, backgroundWasm } from './meeting-background'

const challengeOrigin = 'https://challenges.cloudflare.com'
const development = process.env.NODE_ENV !== 'production'

function envOrigin(value: string | undefined) {
  if (!value) return ''
  return new URL(value).origin
}

const supabase = envOrigin(process.env.NEXT_PUBLIC_SUPABASE_URL)
const meeting = envOrigin(process.env.LIVEKIT_URL)
const meetingCloud = meeting.endsWith('.livekit.cloud') ? ['wss://*.livekit.cloud', 'https://*.livekit.cloud'] : []

export function documentPolicy(nonce: string, guest: boolean) {
  const connect = ["'self'", supabase, supabase.replace(/^http/, 'ws'), meeting, meeting.replace(/^ws/, 'http'),
    ...meetingCloud, backgroundWasm + '/', backgroundModel, development ? 'ws:' : '', guest ? challengeOrigin : '']
  return [
    "default-src 'self'", "base-uri 'none'", "object-src 'none'", "frame-ancestors 'none'", "form-action 'self'",
    `script-src 'nonce-${nonce}' 'strict-dynamic' 'wasm-unsafe-eval'${development ? " 'unsafe-eval'" : ''}`,
    "script-src-attr 'none'", "style-src 'self' 'unsafe-inline'", "img-src 'self' data: blob:",
    "media-src 'self' blob:", "worker-src 'self' blob:",
    `connect-src ${[...new Set(connect.filter(Boolean))].join(' ')}`,
    `frame-src ${guest ? challengeOrigin : "'none'"}`,
  ].join('; ')
}

export function allowedIntegrationOrigin(origin: string | null) {
  if (!origin) return false
  return (process.env.SECTALK_WORKSPACE_API_CORS_ORIGINS ?? '').split(',').some(value => {
    try {
      const parsed = new URL(value.trim())
      return parsed.protocol === 'https:' && parsed.origin === value.trim() && origin === parsed.origin
    } catch {
      return false
    }
  })
}

export const securedLocaleCookie = '__Host-sectalk_locale'
export const loopbackLocaleCookie = 'sectalk_locale_local'

export function browserRequestOrigin(protocol: string, host: string | null) {
  // Next's internal URL can use localhost while the browser uses the public request authority.
  if (!['http:', 'https:'].includes(protocol) || !host || !/^(?:[a-z0-9.-]+|\[[a-f0-9:]+\])(?::\d{1,5})?$/i.test(host)) return null
  try { return new URL(`${protocol}//${host}`) } catch { return null }
}
