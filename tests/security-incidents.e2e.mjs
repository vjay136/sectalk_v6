import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHmac, randomUUID } from 'node:crypto'
import { setTimeout } from 'node:timers/promises'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const dbUrl = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(dbUrl.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const admin = createClient(dbUrl.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const suffix = randomUUID().slice(0, 8)
const password = randomUUID() + '1!Q'

function data(result) {
  assert.equal(result.error, null, result.error?.message)
  return result.data
}

async function account(role) {
  const handle = 'in_' + role + '_' + suffix
  const email = handle + '@example.org'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(dbUrl.origin, publicKey, options)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: 'Incident ' + role }))
  return { id: user.id, email, handle, client }
}

async function totp(encoded) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const digits = [...encoded.replace(/=+$/, '')].map(char => alphabet.indexOf(char).toString(2).padStart(5, '0')).join('')
  const key = Buffer.from(digits.match(/.{8}/g).map(group => parseInt(group, 2)))
  const remaining = 30000 - Date.now() % 30000
  if (remaining < 3000) await setTimeout(remaining + 60)
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)))
  const digest = createHmac('sha1', key).update(counter).digest()
  return String((digest.readUInt32BE(digest.at(-1) & 15) & 0x7fffffff) % 1000000).padStart(6, '0')
}

const [lead, responder, reporter, subject] = await Promise.all([
  account('lead'), account('resp'), account('reporter'), account('subject'),
])
for (const id of [lead.id, responder.id]) assert.match(id, /^[0-9a-f-]{36}$/i)
execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres'], {
  input: "insert into sectalk_private.staff(user_id) values ('" + lead.id + "'),('" + responder.id +
    "'); insert into sectalk_private.st_v6_incident_responders(user_id,role) values ('" + lead.id +
    "','lead'),('" + responder.id + "','responder');",
  windowsHide: true,
})
const chat = data(await reporter.client.rpc('st_request', { p_handle: subject.handle }))
data(await subject.client.rpc('st_respond', { p_chat: chat, p_accept: true }))
const message = randomUUID()
data(await subject.client.rpc('st_send', { p_chat: chat, p_id: message, p_body: 'Fictional incident evidence ' + suffix }))
const report = data(await reporter.client.rpc('st_v5_report', {
  p_chat: chat, p_message: message, p_category: 'scam', p_details: 'Fictional incident details ' + suffix,
}))
assert.equal((await reporter.client.rpc('st_v6_incident_dashboard')).error?.code, '42501')

const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
try {
  const button = (scope, name) => scope.getByRole('button', { name, exact: true })
  async function asStaff(person) {
    const page = await browser.newPage()
    await page.goto(new URL('/#account', app).href)
    await page.getByLabel('Email address', { exact: true }).fill(person.email)
    await page.getByLabel('Password', { exact: true }).fill(password)
    await page.locator('button.submit-auth').click()
    await button(page.getByRole('navigation', { name: 'SecTalk features' }), 'Safety').click()
    await button(page, 'Staff console').click()
    await button(page, 'Set up authenticator').click()
    const secret = (await page.locator('.mfa-setup code').textContent()).trim()
    await page.getByLabel('Authenticator code').fill(await totp(secret))
    await button(page, 'Verify access').click()
    await button(page, 'Incidents').waitFor()
    return page
  }
  const [leadPage, responderPage] = await Promise.all([asStaff(lead), asStaff(responder)])
  const leadIncidents = leadPage.getByRole('region', { name: 'Security incidents' })
  const responderIncidents = responderPage.getByRole('region', { name: 'Security incidents' })
  await leadPage.getByRole('button', { name: new RegExp(subject.handle) }).click()
  await button(leadPage, 'Link report to incident').click()
  await leadIncidents.getByText('Create an incident', { exact: true }).click()
  const title = 'Scoped incident ' + suffix
  await leadIncidents.getByLabel('Incident title').fill(title)
  await leadIncidents.getByLabel('Incident severity').selectOption('high')
  await button(leadIncidents, 'Create incident').click()
  await leadIncidents.getByRole('heading', { name: title }).waitFor()
  assert.equal(await leadIncidents.getByLabel('Report ID').inputValue(), report)
  await leadIncidents.getByLabel('Link reason').fill('Link the selected case record')
  await button(leadIncidents, 'Link report').click()
  await leadIncidents.getByText('Report linked.', { exact: true }).waitFor()

  await button(responderPage, 'Incidents').click()
  await responderIncidents.getByText('No incidents in your queue.', { exact: true }).waitFor()
  await leadIncidents.getByText('Assignment', { exact: true }).click()
  await leadIncidents.getByLabel('Assigned responder').selectOption(responder.id)
  await leadIncidents.getByLabel('Assignment reason').fill('Verified assignment for investigation')
  await button(leadIncidents, 'Assign responder').click()
  await responderIncidents.getByRole('button', { name: new RegExp(title) }).click({ timeout: 16000 })
  const status = responderIncidents.getByRole('form', { name: 'Incident status' })
  await status.waitFor()
  assert.equal(await responderIncidents.getByLabel('Assigned responder').count(), 0)
  await status.getByRole('combobox', { name: 'Status' }).selectOption('investigating')
  await status.getByLabel('Update reason').fill('Started incident investigation')
  await button(status, 'Save incident status').click()
  await responderIncidents.getByText('High severity · Investigating', { exact: true }).waitFor()
  await status.getByRole('combobox', { name: 'Status' }).selectOption('resolved')
  await status.getByLabel('Update reason').fill('Resolved the fixture incident')
  await button(status, 'Save incident status').click()
  await responderIncidents.locator('summary').filter({ hasText: /^Postmortem$/ }).click()
  await responderIncidents.getByLabel('Postmortem', { exact: true }).fill('Documented timeline and follow-up.')
  await button(responderIncidents, 'Save postmortem').click()
  await responderIncidents.getByText('Postmortem saved', { exact: true }).waitFor()
  assert.equal(await responderIncidents.getByText('Fictional incident evidence ' + suffix).count(), 0)
  console.log('Passed scoped incident creation from a report, actual MFA, assignment sync, status and postmortem.')
} finally {
  await browser.close()
}
