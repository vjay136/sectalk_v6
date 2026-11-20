import assert from 'node:assert/strict'
import sharp from 'sharp'
import { previewPdf } from './fixtures/preview-pdf.mjs'

const origin = new URL(process.env.SECTALK_PDF_PREVIEW_WORKER_URL)
assert.equal(origin.hostname, '127.0.0.1')
const worker = new URL('/render', origin)
const key = process.env.SECTALK_PDF_WORKER_SECRET
assert.ok(key.length >= 32)
const request = (bytes, secret = key) => fetch(worker, {
  method: 'POST', headers: { Authorization: 'Bearer ' + secret, 'Content-Type': 'application/pdf' }, body: bytes,
})

assert.equal((await request(previewPdf(), 'invalid-test-key')).status, 404)
assert.equal((await request(Buffer.alloc(1024 * 1024 + 1))).status, 413)
assert.equal((await request(Buffer.from('%PDF-1.4\n%%EOF\n'))).status, 422)
assert.equal((await request(previewPdf(2881))).status, 422)
const response = await request(previewPdf())
assert.equal(response.status, 200)
assert.equal(response.headers.get('content-type'), 'image/png')
assert.equal(response.headers.get('x-content-type-options'), 'nosniff')
const raster = Buffer.from(await response.arrayBuffer())
const image = sharp(raster)
const metadata = await image.metadata()
assert.equal(metadata.width, 768)
assert.equal(metadata.height, 384)
const pixels = await image.raw().toBuffer()
assert.ok(pixels.some(byte => byte < 180), 'Expected content visibly rendered in the first-page raster')
console.log('PDF worker passed authentication, input bound, malformed and oversize-page denial, and actual PNG rasterization.')
