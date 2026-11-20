import { createServer } from 'node:http'
import { timingSafeEqual } from 'node:crypto'
import { open } from 'node:fs/promises'
import { pathToFileURL } from 'node:url'
import { inspectionHostname } from '../apps/web/lib/url-inspection-policy.mjs'
import { verifiedUrlReputation } from '../apps/web/lib/url-reputation-feed.mjs'
import { inspectUserUrl } from '../apps/web/lib/url-inspection-worker.mjs'

function sameToken(expected, supplied) {
  if (typeof supplied !== 'string' || supplied.length !== expected.length) return false
  const actual = Buffer.from(supplied)
  const configured = Buffer.from(expected)
  return actual.byteLength === configured.byteLength && timingSafeEqual(actual, configured)
}

async function readFeed(path, maxBytes) {
  if (!path) return null
  const file = await open(path, 'r')
  try {
    const info = await file.stat()
    if (!info.isFile() || info.size === 0 || info.size > maxBytes) return null
    const buffer = Buffer.alloc(info.size)
    const { bytesRead } = await file.read(buffer, 0, info.size, 0)
    return bytesRead === info.size ? buffer.toString('utf8') : null
  } finally { await file.close() }
}

export function startUrlInspectionWorker({ token, port, allowed, feed, transport }) {
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{24,128}$/.test(token) ||
      !Number.isInteger(port) || port < 1024 || port > 65535 || allowed.size > 200 ||
      [...allowed].some(host => !inspectionHostname(host))) throw new Error('Invalid URL inspector worker configuration')
  let active = 0
  const listener = createServer({ requestTimeout: 9000, headersTimeout: 3000, maxHeaderSize: 4096 }, async (request, response) => {
    const respond = (statusCode, result = null) => {
      response.writeHead(statusCode, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' })
      response.end(JSON.stringify(result))
    }
    if (request.url !== '/inspect' || request.method !== 'POST') { respond(404); return }
    if (!sameToken('Bearer ' + token, request.headers.authorization)) { respond(403); return }
    if (active >= 4) { respond(429); return }
    active++
    try {
      const chunks = []
      let size = 0
      for await (const chunk of request) {
        size += chunk.length
        if (size > 1800) { respond(413); return }
        chunks.push(chunk)
      }
      const raw = JSON.parse(Buffer.concat(chunks).toString('utf8'))
      const result = await inspectUserUrl(raw?.url, allowed, feed, transport)
      respond(result ? 200 : 400, result)
    } catch { if (!response.headersSent) respond(400) }
    finally { active-- }
  })
  listener.listen(port, '127.0.0.1')
  return listener
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (!process.execArgv.includes('--permission') || process.permission.has('child') || process.permission.has('fs.write')) {
    throw new Error('Run the worker with Node permissions and no child process or file write access')
  }
  const { SECTALK_URL_INSPECTION_PORT, SECTALK_URL_INSPECTION_WORKER_TOKEN,
    SECTALK_URL_INSPECTION_ALLOWED_HOSTS, SECTALK_URL_REPUTATION_FILE, SECTALK_URL_REPUTATION_PUBLIC_KEY_FILE } = process.env
  const [manifest, publicKey] = await Promise.all([
    readFeed(SECTALK_URL_REPUTATION_FILE, 524288).catch(() => null),
    readFeed(SECTALK_URL_REPUTATION_PUBLIC_KEY_FILE, 4096).catch(() => null),
  ])
  startUrlInspectionWorker({ port: Number(SECTALK_URL_INSPECTION_PORT), token: SECTALK_URL_INSPECTION_WORKER_TOKEN,
    allowed: new Set((SECTALK_URL_INSPECTION_ALLOWED_HOSTS ?? '').split(',').map(host => host.trim()).filter(Boolean)),
    feed: verifiedUrlReputation(manifest, publicKey) })
}
