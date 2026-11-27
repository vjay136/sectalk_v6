import assert from 'node:assert/strict'
import { createECDH, randomBytes } from 'node:crypto'
import { EventEmitter } from 'node:events'
import https from 'node:https'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import vm from 'node:vm'
import ece from 'http_ece'
import { generateVAPIDKeys } from 'web-push'
import { dispatchAuthorized, pushEndpoint, sendWebPush } from '../apps/web/lib/web-push-server.ts'

test('Web Push uses VAPID and recipient encryption with a generic payload', async t => {
  const recipient = createECDH('prime256v1')
  recipient.generateKeys()
  const auth = randomBytes(16)
  const endpoint = 'https://fcm.googleapis.com/fcm/send/test-only-subscription'
  const subscription = { endpoint, keys: { p256dh: recipient.getPublicKey().toString('base64url'), auth: auth.toString('base64url') } }
  const vapid = { ...generateVAPIDKeys(), subject: 'mailto:push@example.invalid' }
  let providerStatus = 201
  const requests = []
  t.mock.method(https, 'request', (options, callback) => {
    const response = new EventEmitter()
    const request = new EventEmitter()
    response.statusCode = providerStatus
    response.headers = {}
    request.write = body => requests.push({ options, body })
    request.end = () => queueMicrotask(() => { callback(response); response.emit('end') })
    return request
  })

  assert.equal(await sendWebPush(subscription, 60, vapid), 'sent')
  const [{ options, body }] = requests
  assert.equal(options.hostname, 'fcm.googleapis.com')
  assert.equal(options.method, 'POST')
  assert.equal(options.headers['Content-Encoding'], 'aes128gcm')
  assert.match(options.headers.Authorization, /^vapid t=[^.]+\.[^.]+\.[^,]+, k=/i)
  const token = options.headers.Authorization.match(/t=([^,]+)/i)[1]
  const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url'))
  assert.equal(claims.aud, new URL(endpoint).origin)
  assert.equal(claims.sub, vapid.subject)
  assert.deepEqual(JSON.parse(ece.decrypt(body, { version: 'aes128gcm', privateKey: recipient, authSecret: auth })), { v: 1 })

  const before = Date.now()
  assert.equal(await sendWebPush(subscription, 600, vapid, true), 'sent')
  const call = requests[1]
  assert.equal(Number(call.options.headers.TTL), 30)
  assert.equal(call.options.headers.Urgency, 'high')
  assert.equal(call.options.headers.Topic, 'sectalk-call')
  const alert = JSON.parse(ece.decrypt(call.body, { version: 'aes128gcm', privateKey: recipient, authSecret: auth }))
  assert.deepEqual(Object.keys(alert).sort(), ['expiresAt', 'kind', 'v'])
  assert.equal(alert.kind, 'incoming-call')
  assert.equal(alert.v, 2)
  assert.ok(alert.expiresAt >= before + 30000 && alert.expiresAt <= Date.now() + 30000)

  providerStatus = 410
  assert.equal(await sendWebPush(subscription, 60, vapid), 'gone')
  providerStatus = 429
  assert.equal(await sendWebPush(subscription, 60, vapid), 'retry')
  providerStatus = 403
  assert.equal(await sendWebPush(subscription, 60, vapid), 'rejected')
  assert.equal(await sendWebPush({ ...subscription, endpoint: 'https://localhost:55322/private' }, 60, vapid), 'discard')
  assert.equal(requests.length, 5)
  assert.equal(pushEndpoint('https://fcm.googleapis.com.attacker.invalid/fcm/send/s'), null)
  assert.equal(pushEndpoint('https://fcm.googleapis.com@localhost/fcm/send/s'), null)
})

test('the service worker shows generic copy and opens only the SecTalk inbox', async () => {
  const handlers = new Map()
  const shown = []
  const opened = []
  const self = {
    addEventListener: (event, handler) => handlers.set(event, handler),
    location: { origin: 'https://sectalk.example' },
    registration: { showNotification: (title, options) => shown.push({ title, options }) },
    clients: { matchAll: async () => [], openWindow: url => opened.push(url) },
  }
  vm.runInNewContext(await readFile(new URL('../apps/web/public/sectalk-sw.js', import.meta.url), 'utf8'), { self, URL })
  const valid = handlers.get('push')
  valid({ data: { json: () => ({ v: 1, body: 'private text', url: 'https://outside.example' }) }, waitUntil() {} })
  assert.equal(shown[0].title, 'SecTalk')
  assert.equal(shown[0].options.body, 'You have a new alert. Open SecTalk to view it.')
  valid({ data: { json: () => ({ v: 2 }) }, waitUntil() { assert.fail('Unknown push version was displayed') } })
  valid({ data: { json: () => ({ v: 2, kind: 'incoming-call', expiresAt: Date.now() - 1000 }) },
    waitUntil() { assert.fail('Expired call was displayed') } })
  valid({ data: { json: () => ({ v: 2, kind: 'incoming-call', expiresAt: Date.now() + 30000,
    body: 'private caller name', url: 'https://outside.example' }) }, waitUntil() {} })
  assert.equal(shown[1].options.body, 'Incoming call. Open SecTalk to answer.')
  assert.equal(shown[1].options.tag, 'sectalk-call')
  assert.equal(shown[1].options.silent, false)

  let pending
  handlers.get('notificationclick')({
    notification: { close() {}, data: { url: 'https://outside.example' } },
    waitUntil(promise) { pending = promise },
  })
  await pending
  assert.deepEqual(opened, ['https://sectalk.example/'])
  assert.equal(dispatchAuthorized(new Request('https://sectalk.example'), 'secret'), false)
  assert.equal(dispatchAuthorized(new Request('https://sectalk.example', { headers: { Authorization: 'Bearer secret' } }), 'secret'), true)
})
