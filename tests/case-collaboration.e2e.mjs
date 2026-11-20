// Local QA only. Uses genuine browser TOTP and private cross-account case alerts.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHmac, randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = {auth: {persistSession: false, autoRefreshToken: false}}
const admin = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const password = randomUUID() + '1!Q'
const suffix = randomUUID().slice(0, 8)
assert.match(suffix, /^[a-f0-9]{8}$/)

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}
async function account(role) {
  const handle = 'case_' + role + '_' + suffix
  const email = handle + '@example.invalid'
  const {user} = data(await admin.auth.admin.createUser({email, password, email_confirm: true}))
  const client = createClient(supabase.origin, publicKey, options)
  data(await client.auth.signInWithPassword({email, password}))
  data(await client.rpc('st_save_profile', {p_handle: handle, p_name: 'Private fixture profile'}))
  assert.match(user.id, /^[a-f0-9-]{36}$/)
  return {id: user.id, email, handle, client}
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

const [author, recipient, reporter, subject] = await Promise.all([
  account('author'), account('recipient'), account('reporter'), account('subject'),
])
execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-v', 'ON_ERROR_STOP=1',
  '-U', 'postgres', '-d', 'postgres'], {input:
    "insert into sectalk_private.staff(user_id) values ('" + author.id + "'), ('" + recipient.id + "');"})

const chat = data(await reporter.client.rpc('st_request', {p_handle: subject.handle}))
data(await subject.client.rpc('st_respond', {p_chat: chat, p_accept: true}))
const message = randomUUID()
const excerpt = 'Explicitly shared evidence ' + suffix
data(await subject.client.rpc('st_send', {p_chat: chat, p_id: message, p_body: excerpt}))
const report = data(await reporter.client.rpc('st_v5_report', {
  p_chat: chat, p_message: message, p_category: 'harassment', p_details: 'Private reporter details ' + suffix,
}))
for (const person of [author, recipient, reporter, subject]) {
  assert.equal((await person.client.rpc('st_v6_case_collaboration', {p_report: report})).error?.code, '42501')
  assert.equal((await person.client.rpc('st_v6_case_collaboration_alerts')).error?.code, '42501')
}

const browser = await chromium.launch({executablePath: process.env.SECTALK_TEST_BROWSER})
try {
  async function verifyStaff(person) {
    const page = await browser.newPage()
    await page.goto(new URL('/#account', app).href)
    await page.getByLabel('Email address', {exact: true}).fill(person.email)
    await page.getByLabel('Password', {exact: true}).fill(password)
    await page.locator('button.submit-auth').click()
    await page.getByRole('navigation', {name: 'SecTalk features'}).getByRole('button', {name: 'Safety', exact: true}).click()
    await page.getByRole('button', {name: 'Staff console', exact: true}).click()
    await page.getByRole('button', {name: 'Set up authenticator', exact: true}).click()
    const secret = (await page.locator('.mfa-setup code').textContent()).trim()
    await page.getByLabel('Authenticator code', {exact: true}).fill(totp(secret))
    const verified = page.waitForResponse(response => response.url().includes('/auth/v1/factors/') && response.url().endsWith('/verify'))
    await page.getByRole('button', {name: 'Verify access', exact: true}).click()
    assert.equal((await verified).status(), 200)
    await page.getByRole('region', {name: 'Case mentions'}).getByText('No case mentions.', {exact: true}).waitFor()
    return page
  }

  const [writer, reader] = await Promise.all([verifyStaff(author), verifyStaff(recipient)])
  const filters = writer.getByRole('group', {name: 'Moderation queue filters'})
  await filters.getByRole('combobox', {name: 'Report category'}).selectOption('harassment')
  await filters.getByRole('combobox', {name: 'Deadline'}).selectOption('next_day')
  await writer.getByRole('button', {name: new RegExp(subject.handle)}).click()
  const notes = writer.getByRole('region', {name: 'Case collaboration'})
  const note = 'Please review @' + recipient.handle + ' and @' + reporter.handle + '.'
  await notes.getByLabel('Staff note', {exact: true}).fill(note)
  await notes.getByLabel('Link shared message evidence', {exact: true}).check()
  await notes.getByRole('button', {name: 'Add staff note', exact: true}).click()
  await notes.getByText('Staff note added.', {exact: true}).waitFor()
  await notes.getByText(note, {exact: true}).waitFor()
  await reader.getByText('You have a new staff case mention.', {exact: true}).waitFor()

  const mentions = reader.getByRole('region', {name: 'Case mentions'})
  await mentions.getByLabel('Unread', {exact: true}).waitFor({timeout: 22000})
  assert.equal(await mentions.getByText(note, {exact: true}).count(), 0)
  assert.equal(await mentions.getByText(excerpt, {exact: true}).count(), 0)
  const marked = reader.waitForResponse(response => response.url().endsWith('/rpc/st_v6_read_case_collaboration_alert'))
  await mentions.getByRole('button', {name: 'Open case', exact: true}).click()
  assert.ok((await marked).ok())
  const readerNotes = reader.getByRole('region', {name: 'Case collaboration'})
  await readerNotes.getByText(note, {exact: true}).waitFor()
  assert.equal(await readerNotes.getByText(excerpt, {exact: true}).count(), 0)
  await readerNotes.getByRole('button', {name: 'Open linked message evidence', exact: true}).click()
  await readerNotes.getByText(excerpt, {exact: true}).waitFor()
  await reader.getByRole('button', {name: 'Back to queue', exact: true}).click()
  await mentions.getByRole('button', {name: 'Open case', exact: true}).waitFor()
  assert.equal(await mentions.getByLabel('Unread', {exact: true}).count(), 0)

  const timeline = data(await reporter.client.rpc('st_v5_report_timeline', {p_report: report}))
  assert.ok(timeline.every(entry => !entry.action.startsWith('case_note_')))
  assert.doesNotMatch(JSON.stringify(timeline), /Please review|Collaboration note|Shared evidence opened/)
  await writer.getByRole('button', {name: 'Back to queue', exact: true}).click()
  await writer.getByRole('region', {name: 'Case mentions'}).getByText('No case mentions.', {exact: true}).waitFor()
  console.log('Passed real TOTP case collaboration, recipient-only realtime alert, read status and audited evidence links.')
} finally {
  await browser.close()
}
