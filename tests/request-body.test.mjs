import assert from 'node:assert/strict'
import { test } from 'node:test'
import { readBoundedBody, readBoundedText } from '../apps/web/lib/request-body.ts'

const bytes = new TextEncoder()
const request = (body, headers) => new Request('http://127.0.0.1/input', {
  method: 'POST', body, headers, ...(body instanceof ReadableStream ? { duplex: 'half' } : {}),
})

test('the body limit measures streamed bytes and stops reading on overflow', async () => {
  let canceled = false
  const input = new ReadableStream({
    start(controller) { controller.enqueue(bytes.encode('界')); controller.enqueue(bytes.encode('é')) },
    cancel() { canceled = true },
  })
  assert.equal(await readBoundedBody(request(input), 4), undefined)
  assert.equal(canceled, true)
  assert.equal(await readBoundedBody(request('a', { 'Content-Length': '12' }), 5), undefined)
  const understated = request('界界', { 'Content-Length': '1' })
  assert.equal(await readBoundedBody(understated, 5), undefined)
  assert.equal(await readBoundedText(new Response('é'), 2), 'é')
})

test('bounded text preserves valid UTF-8 and rejects malformed input', async () => {
  assert.equal(await readBoundedText(request('é'), 2), 'é')
  assert.equal(await readBoundedText(request(null), 4), null)
  assert.equal(await readBoundedText(request(new Uint8Array()), 4), '')
  assert.equal(await readBoundedText(request('\uFEFF{}'), 8), '\uFEFF{}')
  await assert.rejects(readBoundedText(request(new Uint8Array([0xf0, 0x80, 0x80, 0x80])), 8), TypeError)
})
