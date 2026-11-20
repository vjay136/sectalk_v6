// Native Edge, synthetic direct-chat messages, and MFA-gated reviewer visibility.
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

assert.equal(app.origin, 'http://127.0.0.1:3520')
const [sender, recipient, reviewer] = await Promise.all([account('action_sender'),account('action_peer'),account('action_reviewer')])
sql("insert into sectalk_private.staff(user_id) values ('" + reviewer.id + "');")
const chat = data(await sender.client.rpc('st_request', { p_handle: recipient.handle }))
data(await recipient.client.rpc('st_respond', { p_chat: chat, p_accept: true }))
const low = 'I bought a gift card for the birthday.'
const credential = 'Please send your account password now.'
const link = 'Reference http://example.invalid/fixture and https://example.org/okay'
const content = 'Please send your intimate pictures.'
const high = 'I will hurt you.'
for (const p_body of [low,credential,link,content,high]) {
  data(await sender.client.rpc('st_send',{p_chat:chat,p_id:randomUUID(),p_body}))
}

const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
try {
  const nav = page => page.getByRole('navigation', { name: 'SecTalk features' })
  async function signIn(person) {
    const page = await browser.newPage({ locale: 'en-US' })
    await page.goto(app.href)
    await page.getByLabel('Email address', { exact: true }).fill(person.email)
    await page.getByLabel('Password', { exact: true }).fill(password)
    await page.locator('button.submit-auth').click()
    await nav(page).waitFor()
    return page
  }
  const [peerPage, staffPage] = await Promise.all([signIn(recipient), signIn(reviewer)])
  await peerPage.locator('.chat-item').filter({ hasText: sender.handle }).click()
  const messageFor = text => peerPage.locator('.message').filter({ hasText: text })
  await messageFor(low).getByText('Safety hint', { exact: true }).waitFor()
  await messageFor(credential).getByText('Possible safety concern', { exact: true }).waitFor()
  const defanged = messageFor('hxxp[:]//example[.]invalid/fixture')
  await defanged.getByText('Suspicious links shown as disabled text.', { exact: true }).waitFor()
  assert.equal(await defanged.locator('a').count(), 0)
  await defanged.getByText(/https:\/\/example.org\/okay/).waitFor()
  const reveal = peerPage.getByRole('button', { name: 'Reveal message', exact: true })
  await reveal.nth(1).waitFor()
  assert.equal(await messageFor(high).count(), 0)
  assert.equal(await messageFor(content).count(), 0)
  const held = messageFor('Message held on this device for your review.')
  await held.getByRole('button', { name: 'Reveal message', exact: true }).click()
  await messageFor(high).locator('.bubble').waitFor()
  await messageFor(high).getByRole('button', { name: 'Hide message', exact: true }).click()
  assert.equal(await messageFor(high).count(), 0)
  const blurred = messageFor('Hidden message preview')
  await blurred.getByRole('button', { name: 'Reveal message', exact: true }).click()
  await messageFor(content).locator('.bubble').waitFor()
  assert.deepEqual(data(await recipient.client.from('st_reports').select('id').eq('reporter',recipient.id)), [])

  await held.getByRole('button', { name: 'Report from safety warning', exact: true }).click()
  const report = peerPage.getByRole('dialog', { name: 'Report this message', exact: true })
  const priority = report.getByRole('checkbox', { name: 'Request urgent human review', exact: true })
  assert.equal(await priority.isChecked(), false)
  await priority.check()
  await report.getByLabel('Details', { exact: false }).fill('Synthetic review requested by the recipient.')
  const submitted = peerPage.waitForResponse(response => response.url().endsWith('/rpc/st_v7_request_priority_message_review'))
  await report.getByRole('button', { name: 'Submit report', exact: true }).click()
  assert.equal((await submitted).status(), 200)
  await peerPage.getByText('Priority review requested. Track it in the Safety center.', { exact: true }).waitFor()
  assert.equal((await recipient.client.rpc('st_v7_priority_abuse_queue')).error?.code, '42501')

  await nav(staffPage).getByRole('button', { name: 'Safety', exact: true }).click()
  await staffPage.getByRole('button', { name: 'Staff console', exact: true }).click()
  await staffPage.getByRole('button', { name: 'Set up authenticator', exact: true }).click()
  const secret = (await staffPage.locator('.mfa-setup code').textContent()).trim()
  await staffPage.getByLabel('Authenticator code', { exact: true }).fill(totp(secret))
  await staffPage.getByRole('button', { name: 'Verify access', exact: true }).click()
  const call = staffPage.getByRole('button').filter({ hasText: sender.handle }).filter({ hasText: 'Priority requested' })
  await call.waitFor()
  await call.click()
  await staffPage.getByText('Synthetic review requested by the recipient.', { exact: true }).waitFor()
  await staffPage.getByText(high, { exact: true }).waitFor()

  const file = randomUUID()
  const files = new URL('/api/files/publish', app)
  const evidence = Buffer.from('Synthetic document: https://fixture@example.invalid/notice')
  const authorization = { Authorization: 'Bearer ' + sender.session.access_token }
  data(await sender.client.rpc('st_v5_stage_file', { p_chat: chat,p_id: file,p_filename: 'quarantine-fixture.txt',p_bytes:evidence.length }))
  assert.equal((await fetch(new URL('/api/files/upload?file=' + file,app),{
    method:'POST',headers:{...authorization,'Content-Type':'text/plain'},body:evidence,
  })).status,200)
  const gated = await fetch(files,{method:'POST',headers:{...authorization,'Content-Type':'application/json'},
    body:JSON.stringify({file,mime:'text/plain',caption:'Synthetic quarantined attachment'})})
  assert.equal(gated.status,423)
  const scan = data(await sender.client.rpc('st_v6_my_attachment_quarantine')).find(row => row.file_id === file)
  assert.ok(['quarantined','awaiting_release'].includes(scan.state))
  assert.equal(scan.inspection_reason,'suspicious_link_format')
  assert.deepEqual(data(await recipient.client.rpc('st_v6_my_attachment_quarantine')), [])
  console.log('PASS: hint, warning, defang, private blur/hold/reveal, explicit priority to MFA review, and real managed file quarantine')
} finally {
  await browser.close()
}
