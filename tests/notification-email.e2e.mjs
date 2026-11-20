// Run only against the loopback app, isolated Supabase QA database and Mailpit.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
const mailpit = new URL('http://127.0.0.1:55425')
assert.equal(app.origin, 'http://127.0.0.1:3484')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
assert.equal(process.env.SECTALK_NOTIFICATION_SMTP_HOST, '127.0.0.1')
assert.equal(process.env.SECTALK_NOTIFICATION_SMTP_PORT, '55426')
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
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: handle }))
  return { id: user.id, handle, email, client }
}

const [sender, recipient] = await Promise.all([account('email_sender'), account('email_peer')])
const workspace = data(await sender.client.rpc('st_v2_create_workspace', { p_name: 'Private email test workspace' }))
data(await sender.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: recipient.handle }))
const invite = data(await recipient.client.from('st_v2_invites').select('id').eq('workspace_id', workspace).single())
data(await recipient.client.rpc('st_v2_reply_invite', { p_invite: invite.id, p_accept: true }))
const room = randomUUID()
const roomName = 'Confidential email test room'
data(await sender.client.rpc('st_v6_room_create', { p_workspace: workspace, p_id: room,
  p_name: roomName, p_kind: 'public', p_template: 'blank' }))
data(await recipient.client.rpc('st_v6_room_membership', { p_room: room, p_action: 'join' }))
const drainUrl = new URL('/api/notification-email/drain', app)
assert.equal((await fetch(drainUrl, { method: 'POST' })).status, 401)
assert.equal((await fetch(drainUrl).then(response => response.json())).available, true)

async function drain() {
  const response = await fetch(drainUrl, {
    method: 'POST', headers: { Authorization: 'Bearer ' + process.env.SECTALK_NOTIFICATION_DRAIN_SECRET },
  })
  assert.equal(response.status, 200)
  return response.json()
}
async function messages() {
  const search = new URL('/api/v1/search', mailpit)
  search.searchParams.set('query', 'to:' + recipient.email)
  const response = await fetch(search)
  assert.equal(response.status, 200)
  return (await response.json()).messages ?? []
}

const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
try {
  const page = await browser.newPage()
  await page.goto(new URL('/#account', app).href)
  await page.getByLabel('Email address', { exact: true }).fill(recipient.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation', { name: 'SecTalk features' })
    .getByRole('button', { name: 'Notifications', exact: true }).click()
  await page.getByRole('button', { name: 'Preferences', exact: true }).click()
  const settings = page.getByRole('region', { name: 'Email notifications' })
  const emailToggle = settings.getByRole('checkbox', { name: 'Send email notifications' })
  await emailToggle.check()
  await settings.getByRole('checkbox', { name: 'Room mentions' }).check()
  await settings.getByLabel('Frequency').selectOption('daily')
  await settings.getByRole('button', { name: 'Save email preferences' }).click()
  await settings.getByText('Email notification settings saved.', { exact: true }).waitFor()
  const post = body => sender.client.rpc('st_v6_room_post', {
    p_room: room, p_id: randomUUID(), p_body: body + ' @' + recipient.handle,
  }).then(data)
  await post('Plaintext that must stay in the room')
  await drain()
  assert.equal((await messages()).length, 0)

  assert.match(recipient.id, /^[a-f0-9-]{36}$/)
  // Advance the fixture's schedule so the daily digest can be captured without waiting a day.
  execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres'], {
    input: "update sectalk_private.st_v6_notification_email set next_at=now() where recipient='" + recipient.id + "';",
    encoding: 'utf8',
  })
  const accepted = await drain()
  assert.ok(accepted.accepted >= 1)
  const [captured] = await messages()
  assert.ok(captured?.ID)
  const full = await fetch(new URL('/api/v1/message/' + captured.ID, mailpit)).then(response => response.json())
  assert.equal(full.Subject, 'Your SecTalk daily digest')
  assert.match(full.Text, /Room mentions: 1/)
  assert.doesNotMatch(full.Text, /Plaintext that must stay|Confidential email test room|Task updates:|Missed calls:/)
  const raw = await fetch(new URL('/api/v1/message/' + captured.ID + '/raw', mailpit)).then(response => response.text())
  assert.match(raw, /List-Unsubscribe-Post:\s*List-Unsubscribe=One-Click/i)
  assert.match(raw, /Message-ID:\s*<[a-f0-9-]{36}@127\.0\.0\.1>/i)
  const unsubscribe = new URL(full.Text.match(/Unsubscribe from SecTalk notification emails: (\S+)/)[1])
  assert.equal(unsubscribe.origin, app.origin)
  await page.goto(unsubscribe.href)
  assert.equal(data(await recipient.client.rpc('st_v6_notification_email_settings')).enabled, true)
  await page.getByRole('button', { name: 'Unsubscribe', exact: true }).click()
  await page.getByText('You are unsubscribed from SecTalk notification emails.', { exact: true }).waitFor()
  assert.equal(data(await recipient.client.rpc('st_v6_notification_email_settings')).enabled, false)
  await post('Another private mention')
  await drain()
  assert.equal((await messages()).length, 1)

  data(await recipient.client.rpc('st_v6_set_notification_email', {
    p_enabled: true, p_cadence: 'prompt', p_categories: ['mention'],
  }))
  await post('Fallback fixture private text')
  const jobs = data(await admin.rpc('st_v6_claim_notification_email'))
  const failure = jobs.find(job => job.recipient === recipient.id)
  assert.ok(failure?.delivery_id)
  data(await admin.rpc('st_v6_finish_notification_email', {
    p_recipient: failure.recipient, p_lease: failure.lease, p_result: 'rejected',
  }))
  assert.equal(data(await sender.client.rpc('st_v6_notification_fallbacks')).some(item => item.id === failure.delivery_id), false)
  await page.goto(new URL('/', app).href)
  await page.getByRole('navigation', { name: 'SecTalk features' })
    .getByRole('button', { name: 'Notifications', exact: true }).click()
  await page.getByRole('button', { name: 'Delivery', exact: true }).click()
  const fallback = page.getByRole('region', { name: 'Delivery fallback' })
  await fallback.getByText('Email notification', { exact: true }).waitFor()
  assert.equal(await fallback.getByText('Fallback fixture private text', { exact: false }).count(), 0)
  const mark = fallback.getByRole('button', { name: 'Mark read', exact: true })
  await mark.click()
  await mark.waitFor({ state: 'detached' })
  assert.ok(data(await recipient.client.rpc('st_v6_notification_fallbacks')).find(item => item.id === failure.delivery_id)?.read_at)
  console.log('Passed local SMTP digest, unsubscribe, and private in-app fallback from a simulated provider rejection.')
} finally {
  await browser.close()
  await recipient.client.rpc('st_v6_set_notification_email', { p_enabled: false, p_cadence: 'daily', p_categories: [] })
}
