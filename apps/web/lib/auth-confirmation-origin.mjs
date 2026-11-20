import { isIP } from 'node:net'

const loopbackHosts = new Set(['localhost', '127.0.0.1', '[::1]'])

export function confirmationRedirect(configuredOrigin, requestUrl, hosted) {
  try {
    const request = new URL(requestUrl)
    if (!configuredOrigin && (hosted || !loopbackHosts.has(request.hostname))) return null
    const origin = new URL(configuredOrigin || request.origin)
    if (origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash) return null
    const hostname = origin.hostname.toLowerCase().replace(/\.$/, '')
    if (origin.protocol === 'https:' && hostname.includes('.') && !isIP(hostname) &&
      !['.localhost', '.local', '.internal', '.test', '.invalid'].some(suffix => hostname.endsWith(suffix))) {
      return new URL('/auth/confirm', origin).href
    }
    if (!hosted && loopbackHosts.has(hostname) && loopbackHosts.has(request.hostname) &&
      ['http:', 'https:'].includes(origin.protocol) && origin.protocol === request.protocol && origin.port === request.port) {
      return new URL('/auth/confirm', origin).href
    }
    return null
  } catch {
    return null
  }
}
