// Uses only the disposable loopback app, database, and Coturn relay.
import assert from 'node:assert/strict'
import { createHmac, randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.hostname, '127.0.0.1')
const { SECTALK_STORAGE_TEST_PUBLIC_KEY: publicKey, SECTALK_STORAGE_TEST_SERVICE_KEY: serviceKey } = process.env
assert.ok(publicKey && serviceKey)
const syntheticSecret = 'sectalk-local-diagnostics-fixture'
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(supabase.href, serviceKey, options)
const password = randomUUID() + '!1Q'
const endpoint = new URL('/api/ice/diagnostics', app)

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

async function account(name) {
  const handle = name.toLowerCase() + '_' + randomUUID().slice(0, 8)
  const email = handle + '@example.org'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(supabase.href, publicKey, options)
  const { session } = data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: name }))
  return { id: user.id, email, token: session.access_token }
}

function lease(token) {
  return fetch(endpoint, { method: 'POST', headers: token ? { Authorization: 'Bearer ' + token } : {} })
}

assert.equal((await lease()).status, 401)
assert.equal((await lease('invalid')).status, 401)
assert.equal((await fetch(endpoint)).status, 405)
const api = await account('DiagLease')
const before = Math.floor(Date.now() / 1000)
const response = await lease(api.token)
assert.equal(response.status, 200)
assert.match(response.headers.get('Cache-Control'), /private, no-store/)
assert.match(response.headers.get('Vary'), /Authorization/i)
const config = await response.json()
assert.equal(config.stun.urls, 'stun:127.0.0.1:34790')
assert.equal(config.bandwidth, true)
assert.deepEqual(Object.keys(config.relays).sort(), ['tcp', 'tls', 'udp'])
assert.equal(config.relays.udp.urls, 'turn:127.0.0.1:34790?transport=udp')
assert.equal(config.relays.tcp.urls, 'turn:127.0.0.1:34790?transport=tcp')
assert.equal(config.relays.tls.urls, 'turns:127.0.0.1:443?transport=tcp')
const usernames = new Set()
for (const { username, credential } of Object.values(config.relays)) {
  const [expires, principal] = username.split(':')
  assert.ok(Number(expires) >= before + 90 && Number(expires) <= Math.floor(Date.now() / 1000) + 90)
  assert.match(principal, /^[a-f0-9]{32}$/)
  assert.ok(!principal.includes(api.id.replaceAll('-', '')))
  assert.equal(credential, createHmac('sha1', syntheticSecret).update(username).digest('base64'))
  usernames.add(username)
}
assert.equal(usernames.size, 3)
assert.ok(!JSON.stringify(config).includes(syntheticSecret))
const second = await lease(api.token)
assert.equal(second.status, 200)
assert.notEqual((await second.json()).relays.udp.username, config.relays.udp.username)
let limited = false
for (let attempt = 0; attempt < 5 && !limited; attempt++) {
  const issued = await lease(api.token)
  if (issued.status === 429) {
    assert.equal(issued.headers.get('Retry-After'), '60')
    limited = true
  } else assert.equal(issued.status, 200)
}
assert.ok(limited, 'A repeat caller must be rate limited')

const viewer = await account('DiagViewer')
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const spki = process.env.SECTALK_DIAGNOSTICS_CERT_SPKI
const browser = await chromium.launch({
  executablePath: process.env.SECTALK_TEST_BROWSER,
  args: spki ? ['--ignore-certificate-errors-spki-list=' + spki] : [],
})

try {
  const page = await browser.newPage({ locale: 'en-US' })
  await page.addInitScript(() => {
    window.diagnosticPeers = []
    const Peer = window.RTCPeerConnection
    window.RTCPeerConnection = class extends Peer {
      constructor(config) {
        super(config)
        window.diagnosticPeers.push({ peer: this, server: config.iceServers[0].urls, policy: config.iceTransportPolicy })
      }
    }
    navigator.mediaDevices.getUserMedia = () => { throw new Error('Diagnostics must not capture local media') }
  })
  let requests = 0
  page.on('request', request => { if (request.url() === endpoint.href) requests++ })
  await page.goto(app.href)
  await page.getByLabel('Email address', { exact: true }).fill(viewer.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('button', { name: 'Calls', exact: true }).click()
  await page.getByRole('button', { name: 'Network diagnostics', exact: true }).click()
  const diagnostics = page.getByRole('region', { name: 'Network diagnostics' })
  await diagnostics.getByRole('heading', { name: 'Network diagnostics' }).waitFor()
  assert.equal(requests, 0)
  assert.equal(await page.evaluate(() => window.diagnosticPeers.length), 0)
  await diagnostics.getByRole('button', { name: 'Run diagnostics' }).click()
  const results = diagnostics.locator('dl[aria-label="Network diagnostic results"]')
  await results.waitFor({ timeout: 30_000 })
  assert.equal(requests, 1)
  const read = label => results.locator('div').filter({ has: page.getByText(label, { exact: true }) }).locator('dd').innerText()
  const paths = {
    stun: await read('STUN'), udp: await read('TURN UDP'), tcp: await read('TURN TCP'),
    tls: await read('TURN TLS on port 443'), bandwidth: await read('Relay bandwidth estimate'),
  }
  console.log('Browser paths:', paths)
  assert.equal(paths.udp, 'Data transfer confirmed')
  assert.equal(paths.tcp, 'Data transfer confirmed')
  if (process.env.SECTALK_DIAGNOSTICS_EXPECT_TLS === '1') assert.equal(paths.tls, 'Data transfer confirmed')
  if (process.env.SECTALK_DIAGNOSTICS_EXPECT_STUN === '1') assert.equal(paths.stun, 'Server-reflexive address discovered')
  assert.match(paths.bandwidth, /Mbps via TURN/)
  assert.ok(!JSON.stringify(paths).includes(config.relays.udp.username))
  const peers = await page.evaluate(() => window.diagnosticPeers.map(({ peer, server, policy }) =>
    ({ server, policy, state: peer.connectionState })))
  assert.equal(peers.filter(peer => peer.policy === 'relay').length, 6)
  assert.equal(peers.filter(peer => peer.policy === 'all').length, 1)
  assert.ok(peers.every(peer => peer.state === 'closed'))

  await page.route(endpoint.href, async route => {
    await new Promise(resolve => setTimeout(resolve, 3500))
    await route.abort().catch(() => {})
  })
  await diagnostics.getByRole('button', { name: 'Run diagnostics' }).click()
  await diagnostics.getByRole('button', { name: 'Stop diagnostics' }).click()
  await diagnostics.getByText('Diagnostics stopped.', { exact: true }).waitFor()
} finally {
  await browser.close()
}
console.log('Passed authenticated diagnostics leases, isolation, throttling, explicit browser probes, bandwidth, and cancellation.')
