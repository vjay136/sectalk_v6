import { resolve } from 'node:path'
import type { NextConfig } from 'next'

const config: NextConfig = {
  poweredByHeader: false,
  outputFileTracingRoot: resolve(__dirname, '../..'),
}

export default config
