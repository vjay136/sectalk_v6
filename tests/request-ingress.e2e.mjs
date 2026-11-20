import assert from 'node:assert/strict'
import { createHash, createHmac } from 'node:crypto'
import { AccessToken } from 'livekit-server-sdk'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
assert.equal(app.hostname, '127.0.0.1')
const stripeSecret = process.env.SECTALK_QA_STRIPE_WEBHOOK_SECRET
const livekitSecret = process.env.SECTALK_QA_LIVEKIT_SECRET
const livekitKey = process.env.SECTALK_QA_LIVEKIT_KEY
assert.ok(stripeSecret && livekitSecret && livekitKey)

const emailRoute = '/api/auth/sign-in'
const stripeRoute = '/api/billing/webhook'
const livekitRoute = '/api/meetings/recordings/webhook'
const commandRoute = '/api/account/devices/commands'
const request = (path, body, headers = {}) => fetch(new URL(path, app), {
  method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body,
  ...(body instanceof ReadableStream ? { duplex: 'half' } : {}), signal: AbortSignal.timeout(15000),
})

const missingUser = await request(emailRoute, JSON.stringify({ email: 'unknown-ingress-fixture@example.invalid', password: 'fixture-only' }))
assert.equal(missingUser.status, 401)
const longSignIn = await request(emailRoute, JSON.stringify({ email: '界'.repeat(1000), password: 'fixture-only' }))
assert.equal(longSignIn.status, 401)
assert.deepEqual(await longSignIn.json(), await missingUser.json())
assert.equal((await request(commandRoute, '🧪'.repeat(260))).status, 413)
assert.equal((await request(commandRoute, Uint8Array.of(0xf0, 0x80, 0x80, 0x80))).status, 400)

const stripeBody = '{"id":"evt_ingress_fixture","object":"event","type":"ping","data":{"object":{"name":"test é"}}}\n'
const timestamp = Math.floor(Date.now() / 1000)
const stripeSignature = createHmac('sha256', stripeSecret).update(`${timestamp}.${stripeBody}`).digest('hex')
const stripeHeaders = { 'Stripe-Signature': `t=${timestamp},v1=${stripeSignature}` }
assert.equal((await request(stripeRoute, stripeBody, stripeHeaders)).status, 204)
assert.equal((await request(stripeRoute, stripeBody.trimEnd(), stripeHeaders)).status, 400)
assert.equal((await request(stripeRoute, 'x'.repeat((1024 * 1024) + 1), stripeHeaders)).status, 413)

const liveBody = '{"event":"room_started","room":{"name":"ingress fixture é"}}\n'
const token = new AccessToken(livekitKey, livekitSecret)
token.sha256 = createHash('sha256').update(liveBody).digest('base64')
const liveHeaders = { Authorization: await token.toJwt(), 'Content-Type': 'application/webhook+json' }
assert.equal((await request(livekitRoute, liveBody, liveHeaders)).status, 204)
assert.equal((await request(livekitRoute, liveBody.trimEnd(), liveHeaders)).status, 401)
const overlong = new ReadableStream({ start(controller) {
  controller.enqueue(new Uint8Array(800 * 1024))
  controller.enqueue(new Uint8Array(300 * 1024))
  controller.close()
} })
assert.equal((await request(livekitRoute, overlong, liveHeaders)).status, 413)
console.log('Verified byte-bounded ingress, preserved sign-in errors, and raw Stripe and LiveKit signature checks.')
