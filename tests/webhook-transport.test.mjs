import { createHmac, randomBytes, randomUUID } from 'node:crypto'
import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  openWebhookSecret, publicWebhookAddress, sealWebhookSecret, webhookHeaders, webhookUrl,
} from '../apps/web/lib/webhook-transport.ts'

test('webhook transport accepts public HTTPS and rejects private or ambiguous destinations', () => {
  assert.equal(webhookUrl('https://receiver.example.com/events').pathname, '/events')
  for (const url of ['http://receiver.example.com/events', 'https://10.0.0.1/events', 'https://[::1]/events',
    'https://host.local/events', 'https://trusted.example.com:3443/events', 'https://user@receiver.example.com/events',
    'https://receiver.example.com/events?secret=example', 'https://receiver.example.com/events#other']) assert.equal(webhookUrl(url), null)
  for (const address of ['127.0.0.1', '10.4.8.8', '169.254.169.254', '100.64.0.1', '192.0.2.1', '::1', '::ffff:127.0.0.1',
    'fc00::1', 'fe80::1', '2001:db8::1', '2002:0808:0808::1', '64:ff9b::0808:0808']) assert.equal(publicWebhookAddress(address), false, address)
  assert.equal(publicWebhookAddress('8.8.8.8'), true)
  assert.equal(publicWebhookAddress('2606:4700::1111'), true)
})

test('webhook secrets are endpoint-bound and HMAC covers the raw bytes, ID and timestamp', () => {
  const prior = process.env.SECTALK_WEBHOOK_ENCRYPTION_KEY
  process.env.SECTALK_WEBHOOK_ENCRYPTION_KEY = randomBytes(32).toString('hex')
  try {
    const workspace = randomUUID()
    const endpoint = randomUUID()
    const secret = randomBytes(32)
    const wrapped = sealWebhookSecret(secret, workspace, endpoint)
    assert.equal(wrapped.length, 80)
    assert.deepEqual(openWebhookSecret(wrapped, workspace, endpoint), secret)
    assert.throws(() => openWebhookSecret(wrapped, workspace, randomUUID()))
    const time = 1730000000
    const body = '{"text":"hello"}'
    const id = randomUUID()
    const expected = createHmac('sha256', secret).update(id + '.' + time + '.' + body).digest('base64')
    assert.deepEqual(webhookHeaders(secret, id, body, time), {
      'webhook-id': id, 'webhook-timestamp': String(time), 'webhook-signature': 'v1,' + expected,
    })
  } finally {
    if (prior) process.env.SECTALK_WEBHOOK_ENCRYPTION_KEY = prior
    else delete process.env.SECTALK_WEBHOOK_ENCRYPTION_KEY
  }
})
