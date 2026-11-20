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
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const run = randomUUID().slice(0, 8)
const password = randomUUID() + '1!Q'
const file = randomUUID()
const filename = 'private-hold-fixture.txt'
const bytes = Buffer.from('Synthetic hold test attachment is private')
const accounts = []
let browser
let chat
let officerId

function data(result) {
  if (result.error) throw result.error
  return result.data
}

function sql(statement) {
  execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-v', 'ON_ERROR_STOP=1',
    '-U', 'postgres', '-d', 'postgres'], { input: statement, windowsHide: true })
}

async function account(role) {
  const handle = 'holdqa_' + role + '_' + run
  const email = handle + '@example.org'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  accounts.push(user.id)
  const client = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY, options)
  const { session } = data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: 'File Hold QA ' + role }))
  return { id: user.id, handle, email, client, authorization: 'Bearer ' + session.access_token }
}

function totp(secret) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bits = [...secret.toUpperCase().replace(/=+$/, '')]
    .map(character => alphabet.indexOf(character).toString(2).padStart(5, '0')).join('')
  const key = Buffer.from(bits.match(/.{8}/g).map(part => Number.parseInt(part, 2)))
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)))
  const mac = createHmac('sha1', key).update(counter).digest()
  return String((mac.readUInt32BE(mac.at(-1) & 15) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}

function getPreview(authorization) {
  return fetch(new URL('/api/files/preview?file=' + file, app), { headers: { Authorization: authorization } })
}

try {
  const owner = await account('owner')
  const peer = await account('peer')
  const officer = await account('staff')
  officerId = officer.id
  chat = data(await owner.client.rpc('st_request', { p_handle: peer.handle }))
  data(await peer.client.rpc('st_respond', { p_chat: chat, p_accept: true }))
  data(await owner.client.rpc('st_v5_stage_file', { p_chat: chat, p_id: file, p_filename: filename, p_bytes: bytes.length }))
  assert.equal((await fetch(new URL('/api/files/upload?file=' + file, app), {
    method: 'POST', headers: { Authorization: owner.authorization, 'Content-Type': 'text/plain' }, body: bytes,
  })).status, 200)
  assert.equal((await fetch(new URL('/api/files/publish', app), {
    method: 'POST', headers: { Authorization: owner.authorization, 'Content-Type': 'application/json' },
    body: JSON.stringify({ file, caption: '', mime: 'text/plain' }),
  })).status, 200)
  sql(`insert into sectalk_private.staff values('${officerId}');
    insert into sectalk_private.st_v6_direct_file_hold_scope(operator_id,file_id,authorization_reference)
      values('${officerId}','${file}','Local QA retention authority');`)
  assert.equal((await officer.client.rpc('st_v6_place_direct_file_hold', { p_file: file, p_reason: 'AAL1 must fail' })).error?.code, '42501')

  browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
  const page = await browser.newPage()
  await page.goto(app.href)
  await page.getByLabel('Email address', { exact: true }).fill(officer.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation', { name: 'SecTalk features' }).getByRole('button', { name: 'Safety', exact: true }).click()
  const tab = page.getByRole('button', { name: 'Attachment holds', exact: true })
  await page.getByRole('button', { name: 'Staff console', exact: true }).click()
  assert.equal(await tab.count(), 0)
  await page.getByRole('button', { name: 'Set up authenticator' }).click()
  const secret = (await page.locator('.mfa-setup code').textContent()).trim()
  await page.getByLabel('Authenticator code', { exact: true }).fill(totp(secret))
  await page.getByRole('button', { name: 'Verify access', exact: true }).click()
  await tab.waitFor()
  const [access] = await Promise.all([
    page.waitForResponse(response => response.url().endsWith('/rpc/st_v6_direct_hold_history')),
    tab.click(),
  ])
  const { authorization } = await access.request().allHeaders()
  const panel = page.getByRole('region', { name: 'Attachment holds' })
  assert.equal(await panel.getByLabel('Assigned attachment').inputValue(), file)
  assert.equal(await panel.getByText(filename, { exact: true }).count(), 0)
  assert.equal((await getPreview(authorization)).status, 404)
  await panel.getByLabel('Reason for hold').fill('Scoped synthetic preservation directive')
  await panel.getByRole('button', { name: 'Place hold' }).click()
  await panel.getByText('Active hold', { exact: true }).waitFor()

  assert.equal((await getPreview(peer.authorization)).status, 200)
  data(await owner.client.rpc('st_v5_message_action', { p_message: file, p_action: 'revoke' }))
  assert.equal((await getPreview(peer.authorization)).status, 404)
  data(await owner.client.rpc('st_v6_delete_attachment', { p_file: file }))
  sql(`update public.st_v5_files set purge_after=now()-interval '1 minute' where id='${file}';`)

  const purgeKey = process.env.SECTALK_FILE_PURGE_SECRET
  assert.ok(purgeKey?.length >= 32)
  const drain = () => fetch(new URL('/api/files/purge', app), { method: 'POST', headers: { Authorization: 'Bearer ' + purgeKey } })
  assert.equal((await drain()).status, 200)
  assert.deepEqual(Buffer.from(await data(await admin.storage.from('sectalk-chat-files').download(file)).arrayBuffer()), bytes)

  await panel.getByLabel('Reason for release').fill('Scoped preservation directive discharged')
  await panel.getByRole('button', { name: 'Release hold' }).click()
  await panel.getByText('Released hold', { exact: true }).waitFor()
  const result = await drain()
  assert.equal(result.status, 200)
  assert.ok((await result.json()).purged >= 1)
  assert.ok((await admin.storage.from('sectalk-chat-files').download(file)).error)
  console.log('Direct attachment legal holds passed with real staff TOTP, scoped placement/release, revocation and actual purge.')
} finally {
  await browser?.close()
  data(await admin.storage.from('sectalk-chat-files').remove([file]))
  sql(`delete from sectalk_private.st_v6_direct_file_holds where file_id='${file}';
    delete from sectalk_private.st_v6_file_downloads where file_id='${file}';
    delete from public.st_messages where id='${file}';
    ${chat ? `delete from public.st_chats where id='${chat}';` : ''}
    ${officerId ? `delete from sectalk_private.staff where user_id='${officerId}';` : ''}`)
  for (const id of accounts) data(await admin.auth.admin.deleteUser(id))
}
