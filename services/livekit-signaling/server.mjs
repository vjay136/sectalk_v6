import http from 'node:http'
import https from 'node:https'
import { pipeline } from 'node:stream'

const paths = new Set(['/rtc/validate', '/rtc/v1/validate'])
const socketPaths = new Set(['/rtc', '/rtc/v1'])
const tokenPattern = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/

function endpoint(value, path) {
  const url = new URL(value)
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash ||
      url.pathname !== path) throw new Error('Invalid signaling service URL.')
  return url
}
const upstream = endpoint(process.env.LIVEKIT_SIGNAL_UPSTREAM, '/')
const admission = endpoint(process.env.LIVEKIT_SIGNAL_AUTH_URL, '/api/internal/livekit-admission')
const secret = process.env.LIVEKIT_SIGNAL_AUTH_SECRET
if (!secret || secret.length < 32) throw new Error('A signaling admission credential is required.')

async function allowed(token) {
  try {
    const result = await fetch(admission, { method: 'POST', body: token, redirect: 'error',
      headers: { Authorization: 'Bearer ' + secret, 'Content-Type': 'text/plain' },
      signal: AbortSignal.timeout(3500) })
    void result.body?.cancel().catch(() => undefined)
    return result.status === 204 ? 204 : result.status === 403 ? 403 : 503
  } catch {
    return 503
  }
}

async function reviewConnectedParticipants() {
  try {
    const result = await fetch(admission, { method: 'PUT', redirect: 'error',
      headers: { Authorization: 'Bearer ' + secret }, signal: AbortSignal.timeout(28000) })
    void result.body?.cancel().catch(() => undefined)
    if (result.status !== 204) process.stderr.write('LiveKit participant review unavailable\n')
  } catch {
    process.stderr.write('LiveKit participant review unavailable\n')
  } finally {
    setTimeout(reviewConnectedParticipants, 20000).unref()
  }
}

function resource(req, websocket) {
  if (req.method !== 'GET' || !req.url?.startsWith('/') || req.url.length > 24576) return null
  const path = req.url.split('?')[0]
  if (!(websocket ? socketPaths : paths).has(path)) return null
  const incoming = new URL(req.url, 'http://signaling.invalid')
  const tokens = incoming.searchParams.getAll('access_token')
  const header = req.headers.authorization
  const bearer = typeof header === 'string' ? /^Bearer (\S+)$/.exec(header)?.[1] : undefined
  const token = tokens[0] ?? bearer
  if (tokens.length > 1 || (header && (!bearer || tokens.length)) ||
      !token || token.length > 8192 || !tokenPattern.test(token))
    return { status: 403 }
  // Normalize credential transport so LiveKit verifies the same token as the gateway.
  incoming.searchParams.set('access_token', token)
  const headers = {
    host: upstream.host,
    'user-agent': req.headers['user-agent'] || 'SecTalk signaling',
  }
  for (const name of ['origin', 'connection', 'upgrade', 'sec-websocket-key',
    'sec-websocket-version', 'sec-websocket-protocol', 'sec-websocket-extensions']) {
    if (typeof req.headers[name] === 'string') headers[name] = req.headers[name]
  }
  return { token, path: incoming.pathname + incoming.search, headers }
}

function relay(info) {
  const client = upstream.protocol === 'https:' ? https : http
  return client.request(upstream, { method: 'GET', path: info.path, headers: info.headers, timeout: 10000 })
}
const statusText = { 403: 'Forbidden', 404: 'Not Found', 503: 'Service Unavailable' }

function shutdown(socket, status) {
  socket.end('HTTP/1.1 ' + status + ' ' + statusText[status] +
    '\r\nConnection: close\r\nCache-Control: no-store\r\nContent-Length: 0\r\n\r\n')
}

const server = http.createServer({ maxHeaderSize: 32768, headersTimeout: 10000, requestTimeout: 10000 }, async (req, res) => {
  const info = resource(req, false)
  const status = !info ? 404 : info.status ?? await allowed(info.token)
  if (status !== 204) return res.writeHead(status, { 'Cache-Control': 'no-store' }).end()
  const request = relay(info)
  res.once('close', () => request.destroy())
  request.on('timeout', () => request.destroy())
  request.on('error', () => {
    if (!res.headersSent) res.writeHead(503, { 'Cache-Control': 'no-store' }).end()
    else res.destroy()
  })
  request.on('response', response => {
    res.writeHead(response.statusCode, { ...response.headers, 'Cache-Control': 'no-store' })
    pipeline(response, res, () => undefined)
  })
  request.end()
})
server.maxConnections = 2000

server.on('upgrade', async (req, socket, head) => {
  socket.on('error', () => socket.destroy())
  socket.pause()
  const info = resource(req, true)
  const status = !info ? 404 : info.status ?? await allowed(info.token)
  if (socket.destroyed) return
  if (status !== 204) return shutdown(socket, status)
  const request = relay(info)
  socket.once('close', () => request.destroy())
  request.on('timeout', () => request.destroy())
  request.on('error', () => { if (!socket.destroyed) shutdown(socket, 503) })
  request.on('response', response => {
    response.resume()
    if (!socket.destroyed) shutdown(socket, response.statusCode === 401 || response.statusCode === 403 ? 403 : 503)
  })
  request.on('upgrade', async (response, provider, providerHead) => {
    provider.on('error', () => socket.destroy())
    provider.pause()
    socket.once('close', () => provider.destroy())
    provider.once('close', () => socket.destroy())
    // Recheck after the provider registers the participant, before giving the browser
    // a signaling stream. Moderation that commits later sees the registered participant.
    const current = await allowed(info.token)
    if (socket.destroyed) return provider.destroy()
    if (current !== 204 || provider.destroyed) {
      provider.removeAllListeners('close')
      provider.destroy()
      return shutdown(socket, current === 204 ? 503 : current)
    }
    const fields = ['connection', 'upgrade', 'sec-websocket-accept', 'sec-websocket-protocol', 'sec-websocket-extensions']
    socket.write('HTTP/1.1 101 Switching Protocols\r\n' + fields
      .filter(name => typeof response.headers[name] === 'string')
      .map(name => name + ': ' + response.headers[name] + '\r\n').join('') + '\r\n')
    if (head.length) provider.write(head)
    if (providerHead.length) socket.write(providerHead)
    provider.pipe(socket)
    socket.pipe(provider)
  })
  request.end()
})

server.listen(Number(process.env.PORT || 8080), process.env.BIND_HOST || '127.0.0.1')
setTimeout(reviewConnectedParticipants, 1000).unref()
