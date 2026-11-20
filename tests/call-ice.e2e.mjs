// Run against loopback Supabase and an app configured with synthetic Coturn settings.
import assert from 'node:assert/strict'
import { createHmac, randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.hostname, '127.0.0.1')

const { SECTALK_STORAGE_TEST_PUBLIC_KEY: key, SECTALK_STORAGE_TEST_SERVICE_KEY: serviceKey } = process.env
assert.ok(key && serviceKey)
const testSecret = 'synthetic-call-ice-fixture'
const turn = ['turn:turn.example.invalid:3478?transport=udp', 'turns:turn.example.invalid:5349?transport=tcp']
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(supabase.href, serviceKey, options)
const suffix = randomUUID().slice(0, 8)
const password = randomUUID() + '1!Q'

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

async function account(name) {
  const handle = name.toLowerCase() + '_' + suffix
  const email = handle + '@example.org'
  data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(supabase.href, key, options)
  const { user, session } = data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: name }))
  return { client, email, token: session.access_token, id: user.id, handle }
}

function request(call, token) {
  const url = new URL('/api/ice', app)
  if (call) url.searchParams.set('call', call)
  return fetch(url, { headers: token ? { Authorization: 'Bearer ' + token } : {} })
}

async function readLease(person, call, maxSeconds = 300) {
  const before = Math.floor(Date.now() / 1000)
  const response = await request(call, person.token)
  assert.equal(response.status, 200)
  assert.match(response.headers.get('Cache-Control'), /no-store/)
  assert.match(response.headers.get('Vary'), /Authorization/i)
  const answer = await response.json()
  const relay = answer.iceServers.find(server => server.credential)
  assert.equal(answer.iceTransportPolicy, 'relay')
  assert.deepEqual(relay.urls, turn)
  assert.ok(answer.iceServers.some(server => typeof server.urls === 'string' && /^stuns?:/.test(server.urls)))
  assert.ok(Number.isInteger(answer.ttlSeconds) && answer.ttlSeconds > 0 && answer.ttlSeconds <= maxSeconds)
  const [expiry, principal] = relay.username.split(':')
  assert.ok(Number(expiry) >= before + answer.ttlSeconds)
  assert.ok(Number(expiry) <= Math.floor(Date.now() / 1000) + answer.ttlSeconds)
  assert.match(principal, /^[a-f0-9]{32}$/)
  assert.ok(!relay.username.includes(person.id) && !relay.username.includes(call))
  assert.equal(relay.credential, createHmac('sha1', testSecret).update(relay.username).digest('base64'))
  assert.ok(!JSON.stringify(answer).includes(testSecret))
  return principal
}

const caller = await account('IceCaller')
const callee = await account('IceCallee')
const outsider = await account('IceOutsider')
const chat = data(await caller.client.rpc('st_request', { p_handle: callee.handle }))
data(await callee.client.rpc('st_respond', { p_chat: chat, p_accept: true }))

async function place() {
  return data(await caller.client.rpc('st_place_call', { p_chat: chat, p_video: false }))
}

const first = await place()
assert.equal((await request(first)).status, 401)
assert.equal((await request(first, 'invalid')).status, 401)
assert.equal((await request(null, caller.token)).status, 400)
assert.equal((await request(first, caller.token)).status, 403)
data(await callee.client.rpc('st_call_status', { p_call: first, p_accept: true }))
assert.equal((await request(first, outsider.token)).status, 403)
const firstPrincipal = await readLease(caller, first)
assert.notEqual(await readLease(callee, first), firstPrincipal)
data(await caller.client.rpc('st_call_status', { p_call: first, p_accept: false }))
assert.equal((await request(first, caller.token)).status, 403)

const next = await place()
data(await callee.client.rpc('st_call_status', { p_call: next, p_accept: true }))
data(await admin.from('st_calls').update({ expires_at: new Date(Date.now() + 25000).toISOString() }).eq('id', next))
assert.notEqual(await readLease(caller, next, 25), firstPrincipal)
data(await caller.client.rpc('st_call_status', { p_call: next, p_accept: false }))

const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const browser = await chromium.launch({
  executablePath: process.env.SECTALK_TEST_BROWSER,
  args: ['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream'],
})

async function openChat(person, peerName, captureLease) {
  const page = await browser.newPage({ locale: 'en-US' })
  if (captureLease) {
    await page.addInitScript(() => {
      window.iceCredentials = []
      const Peer = window.RTCPeerConnection
      window.RTCPeerConnection = class extends Peer {
        constructor(config) {
          window.iceCredentials.push(config.iceServers.at(-1).username)
          super({ ...config, iceServers: [], iceTransportPolicy: 'all' })
        }
        setConfiguration(config) {
          window.iceCredentials.push(config.iceServers.at(-1).username)
          super.setConfiguration({ ...config, iceServers: [], iceTransportPolicy: 'all' })
        }
      }
    })
    await page.route('**/api/ice?*', async route => {
      const response = await route.fetch()
      assert.equal(response.status(), 200)
      const lease = await response.json()
      // Shorten the browser timer while using the real signed endpoint responses.
      await route.fulfill({ response, json: { ...lease, ttlSeconds: 62 } })
    })
  } else {
    // No media request from either browser reaches the synthetic or default servers.
    await page.addInitScript(() => {
      const Peer = window.RTCPeerConnection
      window.RTCPeerConnection = class extends Peer {
        constructor(config) {
          super({ ...config, iceServers: [], iceTransportPolicy: 'all' })
        }
      }
    })
  }
  await page.goto(app.href)
  await page.getByLabel('Email address', { exact: true }).fill(person.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await page.locator('.chat-item').filter({ hasText: peerName }).click()
  return page
}

try {
  const [origin, answer] = await Promise.all([
    openChat(caller, 'IceCallee', true),
    openChat(callee, 'IceCaller', false),
  ])
  await origin.getByRole('button', { name: 'Start audio call' }).click()
  await answer.getByRole('button', { name: 'Answer', exact: true }).click()
  await origin.waitForFunction(() => window.iceCredentials?.length >= 2)
  const [original, renewed] = await origin.evaluate(() => window.iceCredentials)
  assert.notEqual(original, renewed)
  assert.equal(original.split(':')[1], renewed.split(':')[1])
  await origin.getByRole('button', { name: 'Hang up', exact: true }).click()
} finally {
  await browser.close()
}
console.log('Passed per-call ICE scope, TTL, signed credentials, endpoint denials and browser renewal.')
