import assert from 'node:assert/strict'
import test from 'node:test'
import { speechWorkerConfig } from '../apps/web/lib/speech-worker-config.mjs'

const origin = 'https://speech.sectalk.example.com'
const secret = 't'.repeat(32)
const config = (url, trusted, token = secret) => speechWorkerConfig({
  MEETING_CAPTIONS_WORKER_URL: url,
  MEETING_CAPTIONS_WORKER_TOKEN: token,
  SECTALK_SPEECH_WORKER_HTTPS_ORIGIN: trusted,
})

test('speech worker accepts the existing loopback endpoint and an explicitly allowed HTTPS endpoint', () => {
  assert.equal(config('http://127.0.0.1:3495/transcribe').endpoint.port, '3495')
  assert.equal(config(origin + '/transcribe', origin).endpoint.origin, origin)
})

test('speech worker rejects alternate origins, credentials, ports and endpoint paths', () => {
  for (const url of [
    'http://speech.sectalk.example.com/transcribe',
    'https://untrusted.example.com/transcribe',
    'https://username:password@speech.sectalk.example.com/transcribe',
    origin + ':8443/transcribe',
    origin + '/other',
    origin + '/transcribe?x=1',
    origin + '/transcribe#unused',
    'http://127.0.0.1:3495/transcribe',
  ]) assert.equal(config(url, origin), null, url)
  assert.equal(config(origin + '/transcribe'), null)
  assert.equal(config(origin + '/transcribe', origin, 'short'), null)
  assert.equal(config(origin + '/transcribe', origin, secret + '\n'), null)
})

test('speech worker rejects direct IP and local DNS HTTPS endpoints even if configured', () => {
  for (const host of ['127.0.0.1', '[::1]', '192.168.1.5', 'speech.local', 'speech.localhost']) {
    const localOrigin = 'https://' + host
    assert.equal(config(localOrigin + '/transcribe', localOrigin), null)
  }
})
