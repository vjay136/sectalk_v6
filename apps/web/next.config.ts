import type { NextConfig } from 'next'
import { backgroundModel, backgroundWasm } from './lib/meeting-background'

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
const origin = supabaseUrl ? new URL(supabaseUrl).origin : ''
const websocket = origin.replace(/^http/, 'ws')
const meetingSocket = process.env.LIVEKIT_URL ? new URL(process.env.LIVEKIT_URL).origin : ''
const meetingHttp = meetingSocket.replace(/^ws/,'http')
const meetingCloud = meetingSocket.endsWith('.livekit.cloud') ? ['wss://*.livekit.cloud','https://*.livekit.cloud'] : []
const dev = process.env.NODE_ENV !== 'production'
const challengeOrigin = 'https://challenges.cloudflare.com'

function contentSecurityPolicy(guest = false) {
  return [
    "default-src 'self'", "base-uri 'none'", "frame-ancestors 'none'", "object-src 'none'",
    "form-action 'self'", "img-src 'self' data: blob:", "style-src 'self' 'unsafe-inline'",
    ["script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'", backgroundWasm + '/', dev ? "'unsafe-eval'" : '',
      guest ? challengeOrigin : ''].filter(Boolean).join(' '),
    guest ? 'frame-src '+challengeOrigin : '',
    "worker-src 'self' blob:",
    ["connect-src 'self'", origin, websocket, meetingSocket, meetingHttp, ...meetingCloud, backgroundWasm + '/', backgroundModel,
      dev ? 'ws:' : '', guest ? challengeOrigin : ''].filter(Boolean).join(' '),
  ].filter(Boolean).join('; ')
}

const config: NextConfig = {
  poweredByHeader: false,
  async headers() {
    return [{
      source: '/:path*',
      headers: [
        { key: 'X-Content-Type-Options', value: 'nosniff' },
        { key: 'X-Frame-Options', value: 'DENY' },
        { key: 'Referrer-Policy', value: 'no-referrer' },
        { key: 'Permissions-Policy', value: 'camera=(self), microphone=(self), display-capture=(self), geolocation=()' },
        { key: 'Content-Security-Policy', value: contentSecurityPolicy() },
      ],
    }, {
      source: '/meeting-guest',
      headers: [
        { key: 'Content-Security-Policy', value: contentSecurityPolicy(true) },
        { key: 'Permissions-Policy', value: 'camera=(self), microphone=(self), display-capture=(), geolocation=()' },
        { key: 'Cache-Control', value: 'private, no-store' },
      ],
    }]
  },
}

export default config
