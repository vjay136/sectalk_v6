import { createServer } from 'node:http'
import { spawn } from 'node:child_process'
import { createHash, timingSafeEqual } from 'node:crypto'

const limit = 4 * 1024 * 1024
const key = process.env.SECTALK_MALWARE_SCANNER_SECRET || ''
if (Buffer.byteLength(key) < 32) throw new Error('Scanner requires a private service secret')
const expected = Buffer.from('Bearer ' + key)
let admitted = 0
let tail = Promise.resolve()
const headers = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }

function scan(bytes) {
  return new Promise(resolve => {
    const task = spawn('/usr/bin/clamscan', [
      '--database=/definitions', '--stdout', '--no-summary', '--max-filesize=4M', '--max-scansize=16M',
      '--max-scantime=4000', '--max-recursion=8', '--max-files=256',
      '--alert-exceeds-max=yes', '--alert-encrypted=yes', '-',
    ], { cwd: '/tmp', env: { LANG: 'C', HOME: '/tmp', TMPDIR: '/tmp' }, stdio: ['pipe', 'pipe', 'pipe'] })
    const deadline = setTimeout(() => task.kill('SIGKILL'), 9000)
    let output = ''
    let failed = false
    task.stdout.on('data', chunk => {
      output += chunk.toString('utf8')
      if (output.length > 8192) { failed = true; task.kill('SIGKILL') }
    })
    task.stderr.on('data', () => { failed = true })
    task.stdin.on('error', () => { failed = true })
    task.on('error', () => { failed = true })
    task.on('close', code => {
      clearTimeout(deadline)
      if (failed || /Heuristics\.(?:Limits\.Exceeded|Encrypted)/i.test(output)) resolve('unavailable')
      else if (code === 0 && /stdin:\s+OK\s*$/m.test(output)) resolve('clean')
      else if (code === 1 && /stdin: .+ FOUND\s*$/m.test(output)) resolve('malware')
      else resolve('unavailable')
    })
    task.stdin.end(bytes)
  })
}

function enqueue(bytes) {
  const expires = Date.now() + 4500
  const result = tail.then(() => Date.now() < expires ? scan(bytes) : 'unavailable')
  tail = result.then(() => undefined, () => undefined)
  return result
}

async function handle(request, response) {
  const supplied = Buffer.from(request.headers.authorization || '')
  if (request.method !== 'POST' || request.url !== '/scan' ||
      supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
    response.writeHead(404, headers).end()
    request.resume()
    return
  }
  const size = Number(request.headers['content-length'])
  if (request.headers['content-type'] !== 'application/octet-stream' || !Number.isInteger(size) || size < 1 || size > limit) {
    response.writeHead(413, headers).end()
    request.resume()
    return
  }
  if (admitted >= 8) {
    response.writeHead(503, headers).end()
    request.resume()
    return
  }
  admitted++
  try {
    const chunks = []
    let received = 0
    for await (const chunk of request) {
      received += chunk.length
      if (received > size) {
        response.writeHead(413, headers).end()
        return
      }
      chunks.push(chunk)
    }
    if (received !== size) { response.writeHead(400, headers).end(); return }
    const bytes = Buffer.concat(chunks, received)
    const verdict = await enqueue(bytes)
    if (verdict === 'unavailable') { response.writeHead(503, headers).end(); return }
    response.writeHead(200, { ...headers, 'Content-Type': 'application/json' })
      .end(JSON.stringify({ verdict, sha256: createHash('sha256').update(bytes).digest('hex') }))
  } finally {
    admitted--
  }
}

const server = createServer({ requestTimeout: 6000, headersTimeout: 4000, connectionsCheckingInterval: 1000,
  maxHeaderSize: 2048 }, (request, response) => {
  request.setTimeout(5000, () => request.destroy())
  void handle(request, response).catch(() => { if (!response.headersSent) response.writeHead(503, headers).end() })
})
server.maxConnections = 8
server.keepAliveTimeout = 2000
server.listen(8080, '0.0.0.0')
