// Isolated QA only. Simulates provider outcomes without issuing provider requests.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createECDH, createHmac, randomBytes, randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const password = randomUUID() + '1!Q'
const suffix = randomUUID().slice(0, 8)

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

async function account(prefix) {
  const handle = prefix + '_' + suffix
  const email = handle + '@example.invalid'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(supabase.origin, publicKey, options)
  const { session } = data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: handle }))
  assert.match(user.id, /^[a-f0-9-]{36}$/)
  return { id: user.id, session, client, email, handle }
}

function sql(statement) {
  return execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-v', 'ON_ERROR_STOP=1',
    '-At', '-U', 'postgres', '-d', 'postgres'], { input: statement, encoding: 'utf8', windowsHide: true }).trim()
}

function totp(secret) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bits = [...secret.toUpperCase().replace(/=+$/, '')].map(character =>
    alphabet.indexOf(character).toString(2).padStart(5, '0')).join('')
  const key = Buffer.from(bits.match(/.{8}/g).map(part => Number.parseInt(part, 2)))
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)))
  const mac = createHmac('sha1', key).update(counter).digest()
  return String((mac.readUInt32BE(mac.at(-1) & 15) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}

const [sender, recipient, operator] = await Promise.all([
  account('queue_sender'), account('queue_peer'), account('queue_ops'),
])
sql("insert into sectalk_private.staff(user_id) values ('" + operator.id + "');"
  + "insert into sectalk_private.st_v6_queue_operators(account_id) values ('" + operator.id + "');")
assert.equal(data(await operator.client.rpc('st_v6_queue_operations_status')), 'mfa')
assert.equal((await recipient.client.rpc('st_v6_queue_dead_letters')).error?.code, '42501')
assert.equal((await recipient.client.rpc('st_v6_platform_queue_health')).error?.code, '42501')
assert.equal((await operator.client.rpc('st_v6_platform_queue_health')).error?.code, '42501')
const chat = data(await sender.client.rpc('st_request', { p_handle: recipient.handle }))
data(await recipient.client.rpc('st_respond', { p_chat: chat, p_accept: true }))
const endpoint = 'https://fcm.googleapis.com/fcm/send/queue-replay-fixture-' + suffix
const device = createECDH('prime256v1')
device.generateKeys()
const enrolled = await fetch(new URL('/api/push/subscription', app), {
  method: 'POST',
  headers: { Authorization: 'Bearer ' + recipient.session.access_token, 'Content-Type': 'application/json' },
  body: JSON.stringify({ endpoint, keys: {
    p256dh: device.getPublicKey().toString('base64url'), auth: randomBytes(16).toString('base64url'),
  } }),
})
assert.equal(enrolled.status, 200)
data(await sender.client.rpc('st_send', { p_chat: chat, p_id: randomUUID(), p_body: 'Original private message' }))
const acquisition = randomUUID()
const failed = data(await admin.rpc('st_v6_claim_web_push', { p_request: acquisition })).find(job => job.endpoint === endpoint)
assert.ok(failed?.job)
assert.deepEqual(data(await admin.rpc('st_v6_claim_web_push', { p_request: acquisition })), [])
data(await admin.rpc('st_v6_finish_web_push', { p_job: failed.job, p_lease: failed.lease, p_result: 'expired' }))
assert.match(failed.job, /^[a-f0-9-]{36}$/)
const deadLetter = sql("select id from sectalk_private.st_v6_notification_dead_letters where job_id='" + failed.job + "';")
assert.match(deadLetter, /^[a-f0-9-]{36}$/)

const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
try {
  const page = await browser.newPage()
  await page.goto(new URL('/#account', app).href)
  await page.getByLabel('Email address', { exact: true }).fill(operator.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation', { name: 'SecTalk features' }).getByRole('button', { name: 'Safety', exact: true }).click()
  await page.getByRole('button', { name: 'Queue operations', exact: true }).click()
  await page.getByRole('heading', { name: 'Verify staff access' }).waitFor()
  await page.getByRole('button', { name: 'Set up authenticator' }).click()
  const secret = (await page.locator('.mfa-setup code').textContent()).trim()
  const listings = page.waitForResponse(response => response.ok() && response.url().endsWith('/rpc/st_v6_queue_dead_letters'))
  await page.getByLabel('Authenticator code', { exact: true }).fill(totp(secret))
  await page.getByRole('button', { name: 'Verify access', exact: true }).click()
  const rows = await (await listings).json()
  const index = rows.findIndex(row => row.id === deadLetter)
  assert.ok(index >= 0)
  assert.deepEqual(Object.keys(rows[index]).sort(), ['channel', 'failed_at', 'id', 'reason', 'replayable'])
  assert.equal(rows[index].replayable, true)
  const queue = page.getByRole('region', { name: 'Queue operations' })
  const entry = queue.getByRole('article').nth(index)
  await entry.getByRole('button', { name: 'Replay delivery', exact: true }).click()
  await queue.getByText('Replay queued.', { exact: true }).waitFor()
  await entry.getByText('Replay unavailable', { exact: true }).waitFor()
  const healthResponse = page.waitForResponse(response => response.ok() && response.url().endsWith('/rpc/st_v6_platform_queue_health'))
  await queue.getByRole('button', { name: 'Service health and SLOs', exact: true }).click()
  const healthData = await (await healthResponse).json()
  assert.ok(healthData.queues.web_push.depth >= 1)
  assert.ok(healthData.queues.web_push.dead_letters >= 1)
  const serviceHealth = queue.getByRole('region', { name: 'Service health and SLOs' })
  await serviceHealth.getByText('API and database readiness ready.', { exact: true }).waitFor()
  await serviceHealth.getByRole('table', { name: 'Service objectives', exact: true }).waitFor()
  await serviceHealth.getByRole('article', { name: 'Browser push', exact: true })
    .getByText(new RegExp(healthData.queues.web_push.depth.toLocaleString() + ' pending')).waitFor()
  await page.route('**/api/ready', route => route.fulfill({ status: 503, json: { status: 'not_ready' } }))
  await serviceHealth.getByRole('button', { name: 'Refresh service health' }).click()
  await serviceHealth.getByText('API and database readiness degraded.', { exact: true }).waitFor()
  const replay = data(await admin.rpc('st_v6_claim_web_push')).find(job => job.endpoint === endpoint)
  assert.ok(replay?.job)
  assert.notEqual(replay.job, failed.job)
  data(await admin.rpc('st_v6_finish_web_push', { p_job: replay.job, p_lease: replay.lease, p_result: 'sent' }))
  console.log('Passed real TOTP queue operator access, live queue depth, readiness, SLO display and eligible replay without a provider send.')
} finally {
  await browser.close()
  await recipient.client.auth.signOut({ scope: 'local' })
}
