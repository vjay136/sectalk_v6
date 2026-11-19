import type { NextConfig } from 'next'

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
const origin = supabaseUrl ? new URL(supabaseUrl).origin : ''
const websocket = origin.replace(/^http/, 'ws')
const dev = process.env.NODE_ENV !== 'production'

const config: NextConfig = {
  poweredByHeader: false,
  async headers() {
    return [{
      source: '/:path*',
      headers: [
        { key: 'X-Content-Type-Options', value: 'nosniff' },
        { key: 'X-Frame-Options', value: 'DENY' },
        { key: 'Referrer-Policy', value: 'no-referrer' },
        { key: 'Permissions-Policy', value: 'camera=(self), microphone=(self), geolocation=()' },
        { key: 'Content-Security-Policy', value: [
          "default-src 'self'", "base-uri 'none'", "frame-ancestors 'none'", "object-src 'none'",
          "form-action 'self'", "img-src 'self' data:", "style-src 'self' 'unsafe-inline'",
          "script-src 'self' 'unsafe-inline'" + (dev ? " 'unsafe-eval'" : ''),
          ["connect-src 'self'", origin, websocket, dev ? 'ws:' : ''].filter(Boolean).join(' '),
        ].join('; ') },
      ],
    }]
  },
}

export default config
