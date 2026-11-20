import assert from 'node:assert/strict'
import { createHash, createHmac, createPublicKey, randomUUID, verify } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { setTimeout } from 'node:timers/promises'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const suffix = randomUUID().slice(0, 8)
const password = randomUUID() + '1!Q'

function data(result) {
  assert.equal(result.error, null, result.error?.message)
  return result.data
}

async function account(role) {
  const handle = 'auditsign_' + role + '_' + suffix
  const email = handle + '@example.org'
  data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(supabase.origin, publicKey, options)
  const { session, user } = data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: 'Audit signing ' + role }))
  return { client, email, token: session.access_token, id: user.id }
}

async function totp(encoded) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bits = [...encoded.replace(/=+$/, '')].map(char => alphabet.indexOf(char).toString(2).padStart(5, '0')).join('')
  const key = Buffer.from(bits.match(/.{8}/g).map(group => parseInt(group, 2)))
  const timeLeft = 30000 - Date.now() % 30000
  if (timeLeft < 3000) await setTimeout(timeLeft + 50)
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)))
  const value = createHmac('sha1', key).update(counter).digest()
  return String((value.readUInt32BE(value.at(-1) & 15) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}

const [owner, outsider] = await Promise.all([account('owner'), account('other')])
const workspace = data(await owner.client.rpc('st_v2_create_workspace', { p_name: 'Signed audit ' + suffix }))
const exportUrl = new URL('/api/audit/export', app)
const keyResponse = await fetch(exportUrl)
assert.equal(keyResponse.status, 200)
const key = await keyResponse.json()
const publicBytes = Buffer.from(key.public_key_spki, 'base64url')
const publicExportKey = createPublicKey({ key: publicBytes, format: 'der', type: 'spki' })
assert.equal(key.key_id, createHash('sha256').update(publicBytes).digest('hex'))

async function request(token) {
  return fetch(exportUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) },
    body: JSON.stringify({ workspace, query: 'workspace created', source: 'workspace', from: null, before: null }),
  })
}

assert.equal((await request()).status, 401)
assert.equal((await request(owner.token)).status, 403)
assert.equal((await request(outsider.token)).status, 403)

const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
try {
  const page = await browser.newPage({ acceptDownloads: true })
  const button = (scope, name) => scope.getByRole('button', { name, exact: true })
  const nav = page.getByRole('navigation', { name: 'SecTalk features' })
  await page.goto(new URL('/#account', app).href)
  await page.getByLabel('Email address', { exact: true }).fill(owner.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await button(nav, 'Profile').click()
  await button(page, 'Security').click()
  await button(page, 'Set up authenticator').click()
  const secret = (await page.locator('.mfa-setup code').textContent()).trim()
  await page.getByLabel('Authenticator code', { exact: true }).fill(await totp(secret))
  await button(page, 'Verify authenticator').click()
  await page.getByRole('heading', { name: 'Recovery codes', exact: true }).waitFor()
  await button(nav, 'Search').click()
  await button(page, 'Audit logs').click()
  const audit = page.getByRole('region', { name: 'Audit log search' })
  await audit.getByLabel('Audit event, room, or ID').fill('workspace created')
  await audit.getByLabel('Log source').selectOption('workspace')
  await button(audit, 'Search audit logs').click()
  await audit.getByText('Displayed entries match the local audit journal.').waitFor()
  const downloaded = page.waitForEvent('download')
  await button(audit, 'Download signed audit').click()
  const download = await downloaded
  assert.equal(download.suggestedFilename(), 'sectalk-audit.json')
  const signed = JSON.parse(await readFile(await download.path(), 'utf8'))
  assert.equal(signed.algorithm, 'Ed25519')
  assert.equal(signed.key_id, key.key_id)
  const signature = Buffer.from(signed.signature, 'base64url')
  assert.equal(verify(null, Buffer.from(signed.payload), publicExportKey, signature), true)
  assert.equal(verify(null, Buffer.from(signed.payload + ' '), publicExportKey, signature), false)
  const payload = JSON.parse(signed.payload)
  assert.equal(payload.filters.workspace, workspace)
  assert.equal(payload.integrity, 'matched')
  assert.deepEqual(payload.entries.map(row => [row.event, row.actor]), [['workspace.created', owner.id]])
  const attempts = data(await owner.client.from('st_v2_workspace_audit').select('id')
    .eq('workspace_id', workspace).eq('event', 'workspace.audit_export_requested'))
  assert.equal(attempts.length, 1)
  console.log('Passed scoped integrity check, genuine TOTP audit download, Ed25519 validation and audit trail.')
} finally {
  await browser.close()
}
