// Run against the isolated loopback app and QA database.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHmac, randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { PDFDocument } from 'pdf-lib'

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
async function account(role) {
  const handle = 'soc_' + role + '_' + suffix
  const email = handle + '@example.invalid'
  const {user} = data(await admin.auth.admin.createUser({email, password, email_confirm: true}))
  const client = createClient(supabase.origin, publicKey, options)
  const {session} = data(await client.auth.signInWithPassword({email, password}))
  data(await client.rpc('st_save_profile', {p_handle: handle, p_name: 'Private fixture staff'}))
  return {id: user.id, email, session, client}
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
async function capture(download) {
  const stream = await (await download).createReadStream()
  const chunks = []
  for await (const chunk of stream) chunks.push(chunk)
  return Buffer.concat(chunks)
}

const [staff, member] = await Promise.all([account('staff'), account('member')])
assert.match(staff.id, /^[a-f0-9-]{36}$/)
execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-v', 'ON_ERROR_STOP=1',
  '-U', 'postgres', '-d', 'postgres'], {input: "insert into sectalk_private.staff(user_id) values ('" + staff.id + "');"})
assert.equal((await staff.client.rpc('st_v6_security_report', {p_period: 'daily'})).error?.code, '42501')
assert.equal((await member.client.rpc('st_v6_security_report', {p_period: 'weekly'})).error?.code, '42501')
const csvUrl = new URL('/api/security-reports/export?period=daily&format=csv', app)
const pdfUrl = new URL('/api/security-reports/export?period=weekly&format=pdf', app)
assert.equal((await fetch(csvUrl)).status, 401)
assert.equal((await fetch(pdfUrl, {headers: {Authorization: 'Bearer ' + member.session.access_token}})).status, 403)

const browser = await chromium.launch({executablePath: process.env.SECTALK_TEST_BROWSER})
try {
  const page = await browser.newPage({acceptDownloads: true})
  await page.goto(new URL('/#account', app).href)
  await page.getByLabel('Email address', {exact: true}).fill(staff.email)
  await page.getByLabel('Password', {exact: true}).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation', {name: 'SecTalk features'}).getByRole('button', {name: 'Safety', exact: true}).click()
  await page.getByRole('button', {name: 'Staff console', exact: true}).click()
  await page.getByRole('button', {name: 'Set up authenticator', exact: true}).click()
  const secret = (await page.locator('.mfa-setup code').textContent()).trim()
  await page.getByLabel('Authenticator code', {exact: true}).fill(totp(secret))
  await page.getByRole('button', {name: 'Verify access', exact: true}).click()

  const dailyCall = page.waitForResponse(response => response.ok() && response.url().endsWith('/rpc/st_v6_security_report'))
  await page.getByRole('button', {name: 'Threat trends', exact: true}).click()
  const daily = await (await dailyCall).json()
  assert.equal(daily.period, 'daily')
  assert.equal(daily.rows.length, 7)
  const reports = page.getByRole('region', {name: 'Security reports'})
  await reports.getByRole('table').waitFor()
  const csvDownload = page.waitForEvent('download')
  await reports.getByRole('button', {name: 'Download CSV', exact: true}).click()
  const csv = (await capture(csvDownload)).toString('utf8')
  assert.match(csv, /^Period,UTC start,UTC end \(exclusive\),Category,Reports filed,Reports with staff action/)
  assert.equal(csv.split('\r\n').filter(Boolean).length, 8)
  assert.doesNotMatch(csv, /@|Private fixture staff|[0-9a-f]{8}-[a-f0-9-]{27}/i)

  const weeklyCall = page.waitForResponse(response => response.ok() && response.url().endsWith('/rpc/st_v6_security_report')
    && response.request().postDataJSON().p_period === 'weekly')
  await reports.getByRole('button', {name: 'Weekly', exact: true}).click()
  const weekly = await (await weeklyCall).json()
  assert.equal(weekly.period, 'weekly')
  assert.equal((Date.parse(weekly.period_end) - Date.parse(weekly.period_start)) / 86400000, 7)
  const bearer = await page.evaluate(() => {
    const sessionKey = Object.keys(localStorage).find(key => /^sb-.+-auth-token$/.test(key))
    return sessionKey ? JSON.parse(localStorage.getItem(sessionKey)).access_token : null
  })
  assert.ok(bearer)
  const apiPdf = await fetch(pdfUrl, {headers: {Authorization: 'Bearer ' + bearer}})
  assert.equal(apiPdf.status, 200, 'Authenticated loopback PDF API status')
  assert.equal(apiPdf.headers.get('content-type'), 'application/pdf')
  const apiBytes = Buffer.from(await apiPdf.arrayBuffer())
  assert.equal(apiBytes.subarray(0, 5).toString(), '%PDF-')
  assert.equal((await PDFDocument.load(apiBytes)).getPageCount(), 1)
  const pdfDownload = page.waitForEvent('download')
  const pdfAuthorization = page.waitForResponse(response => response.ok() && response.url().endsWith('/rpc/st_v6_security_report')
    && response.request().postDataJSON().p_period === 'weekly')
  await reports.getByRole('button', {name: 'Download PDF', exact: true}).click()
  assert.deepEqual(await (await pdfAuthorization).json(), weekly)
  const downloadBytes = await capture(pdfDownload)
  assert.equal(downloadBytes.subarray(0, 5).toString(), '%PDF-')
  const pdf = await PDFDocument.load(downloadBytes)
  assert.equal(pdf.getTitle(), 'SecTalk security report')
  assert.equal(pdf.getPageCount(), 1)
  console.log('Passed genuine staff MFA security reporting and authenticated, privacy-safe CSV/PDF downloads.')
} finally {
  await browser.close()
}
