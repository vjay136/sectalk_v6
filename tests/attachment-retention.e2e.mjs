import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
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
const sharePassword = 'retention-' + run
const file = randomUUID()
const filename = 'retention-' + run + '.txt'
const bytes = Buffer.from('Synthetic attachment to remove through private Storage')
const accounts = []
let browser
let chat

function data(result) {
  if (result.error) throw result.error
  return result.data
}

function sql(statement) {
  execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-v', 'ON_ERROR_STOP=1',
    '-U', 'postgres', '-d', 'postgres'], { input: statement, windowsHide: true })
}

async function account(role) {
  const handle = 'retqa_' + role + '_' + run
  const email = handle + '@example.org'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  accounts.push(user.id)
  const client = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY, options)
  const { session } = data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: 'Retention QA ' + role }))
  return { handle, email, client, headers: { Authorization: 'Bearer ' + session.access_token } }
}

function endpoint(path, init) {
  return fetch(new URL(path, app), init)
}

function json(path, headers, body) {
  return endpoint(path, { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify(body) })
}

async function library(page, actor) {
  await page.goto(app.href)
  await page.getByLabel('Email address', { exact: true }).fill(actor.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation', { name: 'SecTalk features' }).getByRole('button', { name: 'Files', exact: true }).click()
  const files = page.getByRole('region', { name: 'Chat files' })
  await files.locator('.release-row').filter({ hasText: filename }).getByRole('button', { name: 'View details' }).click()
  return page.getByRole('dialog', { name: 'Attachment details' })
}

try {
  const owner = await account('owner')
  const recipient = await account('peer')
  chat = data(await owner.client.rpc('st_request', { p_handle: recipient.handle }))
  data(await recipient.client.rpc('st_respond', { p_chat: chat, p_accept: true }))
  data(await owner.client.rpc('st_v5_stage_file', { p_chat: chat, p_id: file, p_filename: filename, p_bytes: bytes.length }))
  assert.equal((await endpoint('/api/files/upload?file=' + file, {
    method: 'POST', headers: { ...owner.headers, 'Content-Type': 'text/plain' }, body: bytes,
  })).status, 200)
  assert.equal((await json('/api/files/publish', owner.headers, { file, caption: '', mime: 'text/plain' })).status, 200)
  const shareToken = data(await owner.client.rpc('st_v6_create_file_share', {
    p_file: file, p_password: sharePassword, p_seconds: 900, p_downloads: 2,
  }))
  const share = () => json('/api/files/share', {}, { token: shareToken, password: sharePassword, action: 'view' })
  assert.equal((await share()).status, 200)
  const grant = await json('/api/files/download', recipient.headers, { file })
  assert.equal(grant.status, 200)
  const ticket = (await grant.json()).url
  assert.equal((await endpoint('/api/files/preview?file=' + file, { headers: recipient.headers })).status, 200)

  browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
  const peerPage = await browser.newPage()
  const peerDialog = await library(peerPage, recipient)
  await peerDialog.getByRole('heading', { name: filename }).waitFor()
  assert.equal(await peerDialog.getByRole('button', { name: 'Delete attachment' }).count(), 0)
  assert.equal((await recipient.client.rpc('st_v6_delete_attachment', { p_file: file })).error?.code, '42501')

  const ownerPage = await browser.newPage()
  const ownerDialog = await library(ownerPage, owner)
  ownerPage.once('dialog', dialog => dialog.accept())
  await ownerDialog.getByRole('button', { name: 'Delete attachment' }).click()
  await ownerDialog.waitFor({ state: 'detached' })
  await ownerPage.getByText('Deleted attachments', { exact: true }).click()
  await ownerPage.getByText('Eligible for storage purge', { exact: false }).waitFor()
  assert.equal((await endpoint('/api/files/preview?file=' + file, { headers: recipient.headers })).status, 404)
  assert.equal((await endpoint(ticket, { headers: recipient.headers })).status, 404)
  assert.equal((await json('/api/files/download', recipient.headers, { file })).status, 404)
  assert.equal((await share()).status, 404)
  assert.deepEqual(data(await recipient.client.rpc('st_v6_deleted_attachments')), [])
  assert.deepEqual(Buffer.from(await data(await admin.storage.from('sectalk-chat-files').download(file)).arrayBuffer()), bytes)

  const drainSecret = process.env.SECTALK_FILE_PURGE_SECRET
  assert.ok(drainSecret?.length >= 32)
  assert.equal((await endpoint('/api/files/purge', { method: 'POST', headers: owner.headers })).status, 401)
  const drain = () => endpoint('/api/files/purge', { method: 'POST', headers: { Authorization: 'Bearer ' + drainSecret } })
  assert.equal((await drain()).status, 200)
  assert.ok(!(await admin.storage.from('sectalk-chat-files').download(file)).error)

  sql(`update public.st_v5_files set purge_after=now()-interval '1 minute' where id='${file}';`)
  const job = data(await admin.rpc('st_v6_claim_attachment_purge', { p_limit: 20 })).find(row => row.file_id === file)
  assert.ok(job?.lease)
  assert.equal(data(await admin.rpc('st_v6_finish_attachment_purge', {
    p_file: file, p_lease: job.lease, p_removed: false,
  })), false)
  assert.equal((await drain()).status, 200)
  assert.ok(!(await admin.storage.from('sectalk-chat-files').download(file)).error)
  sql(`update public.st_v5_files set purge_next_at=now()-interval '1 minute' where id='${file}';`)
  const processed = await drain()
  assert.equal(processed.status, 200)
  assert.ok((await processed.json()).purged >= 1)
  assert.ok((await admin.storage.from('sectalk-chat-files').download(file)).error)
  assert.equal(data(await owner.client.rpc('st_v6_attachment_capacity')).stored_bytes, 0)
  await ownerPage.getByRole('button', { name: 'Refresh deleted attachments' }).click()
  await ownerPage.getByText('Storage purged', { exact: false }).waitFor()
  console.log('Attachment retention passed with private owner UI, immediately revoked access, bounded grace, retry, and actual Storage bytes removed.')
} finally {
  await browser?.close()
  data(await admin.storage.from('sectalk-chat-files').remove([file]))
  sql(`delete from sectalk_private.st_v6_file_downloads where file_id='${file}';
    delete from public.st_messages where id='${file}';
    ${chat ? `delete from public.st_chats where id='${chat}';` : ''}`)
  for (const id of accounts) data(await admin.auth.admin.deleteUser(id))
}
