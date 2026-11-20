// Native trusted-device proof, explicit account consent, and MFA-only case advisory.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHmac, randomUUID } from 'node:crypto'
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

assert.equal(app.origin, 'http://127.0.0.1:3522')
const [sender, recipient, reviewer] = await Promise.all([account('behavior_sender'), account('behavior_peer'), account('behavior_staff')])
sql("insert into sectalk_private.staff(user_id) values ('" + reviewer.id + "');")
const chat = data(await sender.client.rpc('st_request', { p_handle: recipient.handle }))
data(await recipient.client.rpc('st_respond', { p_chat: chat, p_accept: true }))
const messages = await Promise.all(Array.from({ length: 24 }, () => {
  const id = randomUUID()
  return sender.client.rpc('st_send', { p_chat: chat, p_id: id, p_body: 'Synthetic burst message' }).then(result => ({ id, result }))
}))
for (const { result } of messages) data(result)
for (let index = 0; index < 4; index++) {
  const id = randomUUID()
  const handle = 'beh_inv_' + suffix + '_' + index
  sql("insert into auth.users(id,email) values ('" + id + "','" + handle + "@example.invalid');"
    + "insert into public.st_profiles(id,handle,name) values ('" + id + "','" + handle + "','Synthetic invite target');")
  data(await sender.client.rpc('st_request', { p_handle: handle }))
}
const report = data(await recipient.client.rpc('st_v5_report', {
  p_chat: chat, p_message: messages[0].id, p_category: 'other', p_details: 'Synthetic sender-behavior case.',
}))
assert.equal((await recipient.client.rpc('st_v7_case_sender_behavior', { p_report: report })).error?.code, '42501')

const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
try {
  const nav = page => page.getByRole('navigation', { name: 'SecTalk features' })
  async function signIn(page, person) {
    await page.getByLabel('Email address', { exact: true }).fill(person.email)
    await page.getByLabel('Password', { exact: true }).fill(password)
    await page.locator('button.submit-auth').click()
    await nav(page).waitFor()
  }
  async function register(page) {
    await nav(page).getByRole('button', { name: 'Profile', exact: true }).click()
    await page.getByRole('button', { name: 'Devices and sessions', exact: true }).click()
    const trust = page.getByRole('region', { name: 'Device trust', exact: true })
    await trust.getByRole('button', { name: 'Register this device', exact: true }).click()
    const current = trust.getByRole('article').filter({ hasText: 'This registered device' })
    await current.getByRole('button', { name: 'Trust device', exact: true }).click()
    await current.getByLabel('Current password', { exact: true }).fill(password)
    await current.getByRole('button', { name: 'Confirm trust device', exact: true }).click()
    await current.getByText('Trusted', { exact: true }).waitFor()
    return trust.getByRole('region', { name: 'Optional browser safety link', exact: true })
  }
  const shared = await browser.newPage({ locale: 'en-US' })
  const staff = await browser.newPage({ locale: 'en-US' })
  await Promise.all([shared.goto(app.href), staff.goto(app.href)])
  await Promise.all([signIn(shared, sender), signIn(staff, reviewer)])
  let link = await register(shared)
  const firstProof = shared.waitForResponse(result => result.url().endsWith('/api/account/devices/reputation-link'))
  await link.getByRole('button', { name: 'Opt in and verify browser link', exact: true }).click()
  assert.equal((await firstProof).status(), 204)
  await link.getByText('Browser link verified.', { exact: true }).waitFor()
  await nav(shared).getByRole('button', { name: 'Sign out', exact: true }).click()
  await signIn(shared, recipient)
  link = await register(shared)
  await link.getByRole('button', { name: 'Opt in and verify browser link', exact: true }).waitFor()

  await nav(staff).getByRole('button', { name: 'Safety', exact: true }).click()
  await staff.getByRole('button', { name: 'Staff console', exact: true }).click()
  await staff.getByRole('button', { name: 'Set up authenticator', exact: true }).click()
  const secret = (await staff.locator('.mfa-setup code').textContent()).trim()
  await staff.getByLabel('Authenticator code', { exact: true }).fill(totp(secret))
  await staff.getByRole('button', { name: 'Verify access', exact: true }).click()
  const row = staff.getByRole('button').filter({ hasText: '@' + sender.handle })
  const behavior = staff.getByRole('region', { name: 'Sender behavior advisory' })
  await row.click()
  await behavior.getByText('No qualifying match', { exact: true }).waitFor()
  await behavior.getByText(/Behavior score/).waitFor()
  const counts = (await behavior.locator('dd').allTextContents()).slice(0,3).map(value => Number.parseInt(value, 10))
  assert.ok(counts[0] >= 12)
  assert.ok(counts[1] >= 5)
  assert.equal(counts[2], 0)

  const secondProof = shared.waitForResponse(result => result.url().endsWith('/api/account/devices/reputation-link'))
  await link.getByRole('button', { name: 'Opt in and verify browser link', exact: true }).click()
  const verification = await secondProof
  assert.equal(verification.status(), 204)
  assert.deepEqual(Object.keys(verification.request().postDataJSON()).sort(), ['challenge','identity','installation'])
  await link.getByText('Browser link verified.', { exact: true }).waitFor()
  await staff.getByRole('button', { name: 'Back to queue', exact: true }).click()
  await row.click()
  await behavior.getByText('Match present', { exact: true }).waitFor()
  assert.equal(await behavior.getByText('@' + recipient.handle).count(), 0)
  await link.getByRole('button', { name: 'Remove browser safety link', exact: true }).click()
  await link.getByText('Browser link removed.', { exact: true }).waitFor()
  await staff.getByRole('button', { name: 'Back to queue', exact: true }).click()
  await row.click()
  await behavior.getByText('No qualifying match', { exact: true }).waitFor()
  console.log('PASS: real sends and invitations, two opt-ins on one approved browser, MFA-only anonymous match, and withdrawal')
} finally {
  await browser.close()
}
