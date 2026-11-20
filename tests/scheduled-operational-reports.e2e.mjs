// Isolated loopback app and Mailpit only.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHmac, randomUUID } from 'node:crypto'
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
const client = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY, options)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const password = randomUUID() + '1!Q'
const handle = 'report_ops_' + randomUUID().slice(0, 8)
const email = handle + '@example.invalid'

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}
function sql(statement) {
  return execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-v', 'ON_ERROR_STOP=1',
    '-At', '-U', 'postgres', '-d', 'postgres'], {input: statement, encoding: 'utf8', windowsHide: true}).trim()
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

const { user } = data(await admin.auth.admin.createUser({email, password, email_confirm: true}))
data(await client.auth.signInWithPassword({email, password}))
data(await client.rpc('st_save_profile', {p_handle: handle, p_name: 'Private fixture staff name'}))
assert.match(user.id, /^[a-f0-9-]{36}$/)
sql("insert into sectalk_private.staff(user_id) values ('" + user.id + "');")
const drainUrl = new URL('/api/operational-reports/drain', app)
assert.equal((await fetch(drainUrl, {method: 'POST'})).status, 401)
assert.equal((await client.rpc('st_v6_set_operational_report', {p_cadence: 'daily', p_active: true})).error?.code, '42501')

async function drain(acquisition = randomUUID()) {
  const response = await fetch(drainUrl, {method: 'POST', headers: {
    Authorization: 'Bearer ' + process.env.SECTALK_REPORT_DRAIN_SECRET, 'Idempotency-Key': acquisition,
  }})
  assert.equal(response.status, 200)
  return response.json()
}
async function messages() {
  const search = new URL('/api/v1/search', mailpit)
  search.searchParams.set('query', 'to:' + email)
  const response = await fetch(search)
  assert.equal(response.status, 200)
  return (await response.json()).messages ?? []
}

const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
try {
  const page = await browser.newPage({acceptDownloads: true})
  await page.goto(new URL('/#account', app).href)
  await page.getByLabel('Email address', {exact: true}).fill(email)
  await page.getByLabel('Password', {exact: true}).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation', {name: 'SecTalk features'}).getByRole('button', {name: 'Safety', exact: true}).click()
  await page.getByRole('button', {name: 'Staff console', exact: true}).click()
  await page.getByRole('button', {name: 'Set up authenticator'}).click()
  const secret = (await page.locator('.mfa-setup code').textContent()).trim()
  await page.getByLabel('Authenticator code', {exact: true}).fill(totp(secret))
  await page.getByRole('button', {name: 'Verify access', exact: true}).click()
  await page.getByRole('button', {name: 'Operational metrics', exact: true}).click()
  const reports = page.getByRole('region', {name: 'Scheduled operational reports'})
  await reports.getByRole('button', {name: 'Save report schedule'}).click()
  await reports.getByText('Report schedule saved.', {exact: true}).waitFor()
  await drain()
  assert.equal((await messages()).length, 0)

  sql(`insert into sectalk_private.st_v6_operation_rollups values
    (date_bin(interval '5 minutes',now(),'2000-01-01 00:00+00'::timestamptz)-interval '19 hours 15 minutes',
      'file_upload',17,2,1,0,0,4,array[17,0,0,0,0,0,0,0,0]) on conflict do nothing;
    update sectalk_private.st_v6_operational_report_schedules set next_at=now() where owner='${user.id}';`)
  const acquisition = randomUUID()
  assert.ok((await drain(acquisition)).accepted >= 1)
  assert.deepEqual(await drain(acquisition), {processed: 0, accepted: 0})
  const [captured] = await messages()
  assert.ok(captured?.ID)
  const full = await fetch(new URL('/api/v1/message/' + captured.ID, mailpit)).then(response => response.json())
  assert.equal(full.Subject, 'Your SecTalk daily operational report')
  assert.doesNotMatch(full.Text, /Private fixture staff name|report_ops_/)
  const [attachment] = full.Attachments
  assert.equal(attachment.FileName, 'sectalk-daily-operational-report.csv')
  const attached = await fetch(new URL('/api/v1/message/' + captured.ID + '/part/' + attachment.PartID, mailpit)).then(response => response.text())
  assert.match(attached, /^Operation,Requests,Client errors/)
  assert.match(attached, /^file_upload,\d+,/m)
  assert.doesNotMatch(attached, /@|Private fixture staff name|[0-9a-f]{8}-[0-9a-f-]{27}/i)

  await reports.getByRole('button', {name: 'Refresh reports'}).click()
  await reports.getByText('Email accepted', {exact: true}).waitFor()
  const download = page.waitForEvent('download')
  await reports.getByRole('button', {name: 'Download CSV'}).click()
  const stream = await (await download).createReadStream()
  const chunks = []
  for await (const chunk of stream) chunks.push(chunk)
  assert.equal(Buffer.concat(chunks).toString('utf8'), attached)
  const runId = sql("select id from sectalk_private.st_v6_operational_report_runs where owner='" + user.id + "';")
  assert.match(runId, /^[a-f0-9-]{36}$/)
  const exportUrl = new URL('/api/operational-reports/export?run=' + runId, app)
  assert.equal((await fetch(exportUrl)).status, 401)
  const {session} = data(await client.auth.signInWithPassword({email, password}))
  assert.equal((await fetch(exportUrl, {headers: {Authorization: 'Bearer ' + session.access_token}})).status, 403)

  await reports.getByRole('button', {name: 'Pause reports'}).click()
  await reports.getByText('Report schedule paused.', {exact: true}).waitFor()
  sql("update sectalk_private.st_v6_operational_report_schedules set next_at=now() where owner='" + user.id + "';")
  await drain()
  assert.equal((await messages()).length, 1)
  console.log('Passed real MFA schedule, loopback SMTP CSV, identical browser export, and pause.')
} finally {
  await browser.close()
  sql("update sectalk_private.st_v6_operational_report_schedules set active=false where owner='" + user.id + "';")
}
