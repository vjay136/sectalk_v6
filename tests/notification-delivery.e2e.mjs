// Local only. Simulates a push provider response through the service-role worker contract.
import assert from 'node:assert/strict'
import { createECDH, randomBytes, randomUUID } from 'node:crypto'
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
  const email = handle + '@example.org'
  data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(supabase.origin, publicKey, options)
  const { session } = data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: handle }))
  return { client, handle, email, session }
}

const [sender, recipient] = await Promise.all([account('deliver_sender'), account('deliver_peer')])
const chat = data(await sender.client.rpc('st_request', { p_handle: recipient.handle }))
data(await recipient.client.rpc('st_respond', { p_chat: chat, p_accept: true }))
const device = createECDH('prime256v1')
device.generateKeys()
const endpoint = 'https://fcm.googleapis.com/fcm/send/delivery-simulation-' + suffix
const browserSetup = await fetch(new URL('/api/push/subscription', app), {
  method: 'POST',
  headers: { Authorization: 'Bearer ' + recipient.session.access_token, 'Content-Type': 'application/json' },
  body: JSON.stringify({ endpoint, keys: {
    p256dh: device.getPublicKey().toString('base64url'), auth: randomBytes(16).toString('base64url'),
  } }),
})
assert.equal(browserSetup.status, 200)
const message = 'Private fixture that must not appear in delivery metadata.'
data(await sender.client.rpc('st_send', { p_chat: chat, p_id: randomUUID(), p_body: message }))
const jobs = data(await admin.rpc('st_v6_claim_web_push'))
const job = jobs.find(candidate => candidate.endpoint === endpoint)
assert.ok(job)
assert.equal(job.terminal, null)
data(await admin.rpc('st_v6_finish_web_push', { p_job: job.job, p_lease: job.lease, p_result: 'rejected' }))
assert.deepEqual(data(await sender.client.rpc('st_v6_notification_fallbacks')), [])

const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
try {
  const page = await browser.newPage()
  await page.goto(new URL('/#account', app).href)
  await page.getByLabel('Email address', { exact: true }).fill(recipient.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation', { name: 'SecTalk features' })
    .getByRole('button', { name: 'Notifications', exact: true }).click()
  await page.getByRole('button', { name: 'Delivery', exact: true }).click()
  const delivery = page.getByRole('region', { name: 'Delivery fallback' })
  await delivery.getByText('Direct message', { exact: true }).waitFor()
  assert.equal(await delivery.getByText(message, { exact: true }).count(), 0)
  const mark = delivery.getByRole('button', { name: 'Mark read', exact: true })
  await mark.click()
  await mark.waitFor({ state: 'detached' })
  assert.ok(data(await recipient.client.rpc('st_v6_notification_fallbacks'))[0].read_at)
  console.log('Passed browser fallback from a simulated Web Push provider rejection, recipient access, and read state.')
} finally {
  await browser.close()
  data(await recipient.client.auth.signOut({ scope: 'local' }))
}
