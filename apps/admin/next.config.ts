import { resolve } from 'node:path'
import type { NextConfig } from 'next'

const config: NextConfig = {
  agentRules: false,
  poweredByHeader: false,
  outputFileTracingRoot: resolve(__dirname, '../..'),
  async headers() {
    return [{
      source: '/:path*',
      headers: [
        { key: 'X-Content-Type-Options', value: 'nosniff' },
        { key: 'X-Frame-Options', value: 'DENY' },
        { key: 'Referrer-Policy', value: 'no-referrer' },
        { key: 'Permissions-Policy', value: 'camera=(), microphone=(), display-capture=(), geolocation=()' },
      ],
    }]
  },
}

export default config
