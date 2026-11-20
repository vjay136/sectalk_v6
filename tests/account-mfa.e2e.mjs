// Run against the isolated loopback application and Supabase project with TOTP enabled.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHmac, randomUUID } from 'node:crypto'
import { setTimeout } from 'node:timers/promises'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const key = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const admin = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const newClient = () => createClient(supabase.origin, key, options)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const handle = 'mfa_' + randomUUID().slice(0, 8)
const email = handle + '@example.org'
const password = randomUUID() + '1!Q'

function data(result) {
  if (result.error) throw result.error
  return result.data
}

let lastStep = 0
async function totp(secret, newFactor = false) {
  if (newFactor) lastStep = 0
  while (Math.floor(Date.now() / 30_000) === lastStep || Date.now() % 30_000 > 28_000) await setTimeout(200)
  lastStep = Math.floor(Date.now() / 30_000)
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bits = [...secret.toUpperCase().replace(/=+$/, '')].map(character => alphabet.indexOf(character).toString(2).padStart(5, '0')).join('')
  const key = Buffer.from(bits.match(/.{8}/g).map(part => Number.parseInt(part, 2)))
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(lastStep))
  const mac = createHmac('sha1', key).update(counter).digest()
  return String((mac.readUInt32BE(mac.at(-1) & 15) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}

const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
const button = (page, name) => page.getByRole('button', { name, exact: true })
const nav = page => page.getByRole('navigation', { name: 'SecTalk features' })

async function signIn(client) {
  return data(await client.auth.signInWithPassword({ email, password }))
}

async function signInBrowser(page) {
  await page.goto(new URL('/#account', app).href)
  await page.getByLabel('Email address', { exact: true }).fill(email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
}

async function readBatch(page) {
  await page.getByRole('heading', { name: 'Recovery codes', exact: true }).waitFor()
  const codes = await page.locator('.mfa-codes li code').allTextContents()
  assert.equal(codes.length, 8)
  assert.equal(new Set(codes).size, 8)
  assert.ok(codes.every(code => /^(?:[0-9A-F]{8}-){3}[0-9A-F]{8}$/.test(code)))
  return codes
}
function endCoolingOff() {
  execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-v', 'ON_ERROR_STOP=1',
    '-U', 'postgres', '-d', 'postgres'], {input: `update sectalk_private.st_v7_account_security_changes
      set ready_at=now()-interval '1 minute' where user_id='${user.id}' and kind='recovery';`})
}

try {
  const firstSession = newClient()
  await signIn(firstSession)
  data(await firstSession.rpc('st_save_profile', { p_handle: handle, p_name: 'MFA Tester' }))
  assert.equal((await firstSession.rpc('st_v7_generate_recovery_codes')).error?.code, '42501')
  assert.ok((await newClient().rpc('st_v7_account_recovery_status')).error)

  const page = await browser.newPage()
  await signInBrowser(page)
  await button(nav(page), 'Profile').click()
  await button(page, 'Security').click()
  await button(page, 'Set up authenticator').click()
  const secret = (await page.locator('.mfa-setup code').textContent()).trim()
  await page.getByLabel('Authenticator code', { exact: true }).fill(await totp(secret))
  await button(page, 'Verify authenticator').click()
  const original = await readBatch(page)
  await button(page, 'I saved my codes').click()
  assert.equal(await page.locator('.mfa-codes').count(), 0)

  await button(page, 'Replace recovery codes').click()
  await page.getByLabel('Authenticator code', { exact: true }).fill(await totp(secret))
  await button(page, 'Verify and generate codes').click()
  const replacement = await readBatch(page)
  assert.ok(replacement.every(code => !original.includes(code)))

  const challengePage = await browser.newPage()
  await signInBrowser(challengePage)
  await challengePage.getByRole('heading', { name: 'Verify your sign-in', exact: true }).waitFor()
  assert.equal(await nav(challengePage).count(), 0)
  await challengePage.getByLabel('Authenticator code', { exact: true }).fill(await totp(secret))
  await button(challengePage, 'Verify authenticator').click()
  await nav(challengePage).waitFor()

  const recoveryPage = await browser.newPage()
  await signInBrowser(recoveryPage)
  await button(recoveryPage, 'Use a recovery code').click()
  await recoveryPage.getByLabel('Recovery code', { exact: true }).fill(original[0])
  await button(recoveryPage, 'Reset authenticator').click()
  await recoveryPage.getByRole('alert').waitFor()
  assert.equal(await nav(recoveryPage).count(), 0)

  const alternate = newClient()
  const { session: beforeRecovery } = await signIn(alternate)
  await recoveryPage.getByLabel('Recovery code', { exact: true }).fill(replacement[0].toLowerCase())
  await button(recoveryPage, 'Reset authenticator').click()
  await recoveryPage.getByText(/^Recovery can continue after/).waitFor()
  assert.ok(data(await alternate.auth.getUser(beforeRecovery.access_token)).user)
  endCoolingOff()
  await recoveryPage.getByLabel('Recovery code', { exact: true }).fill(replacement[0].toLowerCase())
  await button(recoveryPage, 'Reset authenticator').click()
  await recoveryPage.getByText(/Your authenticator was reset and your sessions ended/).waitFor()
  assert.equal(data(await alternate.rpc('st_v7_recover_authenticator', { p_code: replacement[0] })), false)
  assert.ok((await alternate.auth.getUser(beforeRecovery.access_token)).error)

  await signInBrowser(recoveryPage)
  await nav(recoveryPage).waitFor()
  const afterReset = newClient()
  await signIn(afterReset)
  assert.equal(data(await afterReset.auth.mfa.getAuthenticatorAssuranceLevel()).currentLevel, 'aal1')
  assert.equal(data(await afterReset.auth.mfa.listFactors()).all.length, 0)
  assert.equal(data(await afterReset.rpc('st_v7_account_recovery_status')), 'missing')

  const nextFactor = data(await afterReset.auth.mfa.enroll({ factorType: 'totp' }))
  data(await afterReset.auth.mfa.challengeAndVerify({ factorId: nextFactor.id, code: await totp(nextFactor.totp.secret, true) }))
  const nextBatch = data(await afterReset.rpc('st_v7_generate_recovery_codes'))
  execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-v', 'ON_ERROR_STOP=1',
    '-U', 'postgres', '-d', 'postgres'], {input: `delete from sectalk_private.limits
      where actor='${user.id}' and action='account_authenticator_recovery';`})
  const contenders = [newClient(), newClient()]
  await Promise.all(contenders.map(signIn))
  const results = await Promise.all(contenders.map((client, index) => client.rpc('st_v7_recovery_security_reset', { p_code: nextBatch[index] })))
  assert.deepEqual(results.map(data).sort(), ['pending', 'unavailable'])
  endCoolingOff()
  const claimant = results.findIndex(result => result.data === 'pending')
  const completions = await Promise.all(contenders.map(client => client.rpc('st_v7_recovery_security_reset', {p_code: nextBatch[claimant]})))
  assert.deepEqual(completions.map(data).sort(), ['completed', 'unavailable'])
  console.log('Account MFA browser enrollment, rotation, sign-in, reset, session revocation, replay, and concurrent recovery checks passed.')
} finally {
  await browser.close()
  await admin.auth.admin.deleteUser(user.id)
}
