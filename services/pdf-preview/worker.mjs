import { createServer } from 'node:http'
import { spawn, spawnSync } from 'node:child_process'
import { timingSafeEqual } from 'node:crypto'

const launcher = '/worker/raster-sandbox'
const maximumInput = 1024 * 1024
const maximumOutput = 1024 * 1024
const pngHeader = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])
const expected = Buffer.from('Bearer ' + process.env.SECTALK_PDF_WORKER_SECRET)
if (Buffer.byteLength(process.env.SECTALK_PDF_WORKER_SECRET || '') < 32 ||
    spawnSync(launcher, ['verify'], { stdio: 'ignore', env: {} }).status !== 0) {
  throw new Error('PDF worker needs a configured secret and a supported seccomp runtime')
}

let occupied = false
const headers = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }

function convert(mode, pdf, limit) {
  return new Promise(resolve => {
    const child = spawn(launcher, [mode], { stdio: ['pipe', 'pipe', 'pipe'], env: {} })
    let size = 0
    let warned = false
    const chunks = []
    const timeout = setTimeout(() => child.kill('SIGKILL'), 3000)
    child.stdin.on('error', () => {})
    child.stderr.on('data', () => { warned = true })
    child.stdout.on('data', chunk => {
      size += chunk.length
      if (size > limit) child.kill('SIGKILL')
      else chunks.push(chunk)
    })
    child.on('error', () => { warned = true })
    child.on('close', code => {
      clearTimeout(timeout)
      resolve(code === 0 && !warned && size <= limit ? Buffer.concat(chunks, size) : null)
    })
    child.stdin.end(pdf)
  })
}

function safeDocument(text) {
  const pages = [...text.matchAll(/^Pages:\s+(\d+)\s*$/gm)]
  const dimensions = [...text.matchAll(/^Page size:\s+([\d.]+) x ([\d.]+) pts\b/gm)]
  return pages.length === 1 && Number(pages[0][1]) >= 1 && Number(pages[0][1]) <= 100 &&
    dimensions.length === 1 && dimensions[0].slice(1).every(value => Number(value) >= 1 && Number(value) <= 2880) &&
    [...text.matchAll(/^Encrypted:\s+([a-z]+)/gm)].map(match => match[1]).join(',') === 'no' &&
    [...text.matchAll(/^JavaScript:\s+([a-z]+)/gm)].map(match => match[1]).join(',') === 'no' &&
    [...text.matchAll(/^Form:\s+(\w+)/gm)].map(match => match[1]).join(',') === 'none'
}

async function raster(request, response) {
  const auth = Buffer.from(request.headers.authorization || '')
  if (auth.length !== expected.length || !timingSafeEqual(auth, expected)) {
    response.writeHead(404, headers).end()
    request.resume()
    return
  }
  if (request.headers['content-type'] !== 'application/pdf' ||
      !(Number(request.headers['content-length']) > 0 && Number(request.headers['content-length']) <= maximumInput)) {
    response.writeHead(413, headers).end()
    request.resume()
    return
  }
  if (occupied) {
    response.writeHead(503, headers).end()
    request.resume()
    return
  }
  occupied = true
  try {
    const pdf = await collect(request, maximumInput)
    const info = pdf?.subarray(0, 5).toString('ascii') === '%PDF-' && await convert('info', pdf, 16384)
    const image = info && safeDocument(info.toString('utf8')) && await convert('raster', pdf, maximumOutput)
    if (!image || !image.subarray(0, 8).equals(pngHeader)) response.writeHead(422, headers).end()
    else response.writeHead(200, { ...headers, 'Content-Type': 'image/png', 'Content-Length': image.length }).end(image)
  } finally {
    occupied = false
  }
}

async function collect(request, limit) {
  let size = 0
  const chunks = []
  for await (const chunk of request) {
    size += chunk.length
    if (size > limit) return null
    chunks.push(chunk)
  }
  return Buffer.concat(chunks, size)
}

const server = createServer({ requestTimeout: 8000, headersTimeout: 5000, maxHeaderSize: 2048 }, (request, response) => {
  if (request.method !== 'POST' || request.url !== '/render') {
    response.writeHead(404, headers).end()
    return
  }
  request.setTimeout(5000, () => request.destroy())
  void raster(request, response).catch(() => { if (!response.headersSent) response.writeHead(422, headers).end() })
})
server.maxConnections = 8
server.keepAliveTimeout = 2000
server.listen(8080, '0.0.0.0')
