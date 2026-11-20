import type { NextConfig } from 'next'

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
      ],
    }, {
      source: '/meeting-guest',
      headers: [
        { key: 'Permissions-Policy', value: 'camera=(self), microphone=(self), display-capture=(), geolocation=()' },
        { key: 'Cache-Control', value: 'private, no-store' },
      ],
    }, {
      source: '/offline.html',
      headers: [{ key: 'Content-Security-Policy', value: "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'" }],
    }]
  },
}

export default config
