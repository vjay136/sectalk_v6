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
const file = randomUUID()
const filename = 'access-history-' + run + '.txt'
const bytes = Buffer.from('Synthetic direct attachment for access-history verification')
const accounts = []
let chat
let browser

function data(result) {
  if (result.error) throw result.error
  return result.data
}

function sql(statement) {
  execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-v', 'ON_ERROR_STOP=1',
    '-U', 'postgres', '-d', 'postgres'], { input: statement, windowsHide: true })
}

async function account(role) {
  const handle = 'filehist_' + role + '_' + run
  const email = handle + '@example.org'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  accounts.push(user.id)
  const client = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY, options)
  const { session } = data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: 'File history QA ' + role }))
  return { handle, email, client, authorization: 'Bearer ' + session.access_token }
}

async function openLibrary(page, user) {
  await page.goto(app.href)
  await page.getByLabel('Email address', { exact: true }).fill(user.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation', { name: 'SecTalk features' }).getByRole('button', { name: 'Files', exact: true }).click()
  return page.getByRole('region', { name: 'Chat files' }).locator('.release-row').filter({ hasText: filename })
}

try {
  const owner = await account('owner')
  const recipient = await account('peer')
  chat = data(await owner.client.rpc('st_request', { p_handle: recipient.handle }))
  data(await recipient.client.rpc('st_respond', { p_chat: chat, p_accept: true }))
  data(await owner.client.rpc('st_v5_stage_file', { p_chat: chat, p_id: file, p_filename: filename, p_bytes: bytes.length }))
  assert.equal((await fetch(new URL('/api/files/upload?file=' + file, app), {
    method: 'POST', headers: { Authorization: owner.authorization, 'Content-Type': 'text/plain' }, body: bytes,
  })).status, 200)
  assert.equal((await fetch(new URL('/api/files/publish', app), {
    method: 'POST', headers: { Authorization: owner.authorization, 'Content-Type': 'application/json' },
    body: JSON.stringify({ file, caption: '', mime: 'text/plain' }),
  })).status, 200)
  assert.equal((await recipient.client.rpc('st_v6_file_access_history', { p_file: file })).error?.code, '42501')
  assert.deepEqual(data(await owner.client.rpc('st_v6_file_access_history', { p_file: file })).map(row => row.event), ['share'])

  browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
  const recipientPage = await browser.newPage({ acceptDownloads: true })
  const recipientRow = await openLibrary(recipientPage, recipient)
  await recipientRow.getByRole('button', { name: 'View details', exact: true }).click()
  const dialog = recipientPage.getByRole('dialog', { name: 'Attachment details' })
  await dialog.getByRole('heading', { name: filename, exact: true }).waitFor()
  assert.equal(await dialog.getByRole('heading', { name: 'Access history' }).count(), 0)
  await recipientPage.keyboard.press('Escape')
  const download = recipientPage.waitForEvent('download')
  await recipientRow.getByRole('button', { name: 'Download', exact: true }).click()
  assert.equal((await download).suggestedFilename(), filename)

  const ownerPage = await browser.newPage()
  const ownerRow = await openLibrary(ownerPage, owner)
  const reading = ownerPage.waitForResponse(response => response.url().endsWith('/rpc/st_v6_file_access_history'))
  await ownerRow.getByRole('button', { name: 'View details', exact: true }).click()
  const response = await reading
  assert.equal(response.status(), 200)
  const history = await response.json()
  for (const event of history) assert.deepEqual(Object.keys(event).sort(), ['event', 'occurred_at', 'participant'])
  assert.deepEqual(history.map(row => row.event + ':' + row.participant), [
    'view:owner', 'download:recipient', 'view:recipient', 'share:owner',
  ])
  const ownerHistory = ownerPage.getByRole('region', { name: 'Access history' })
  await ownerHistory.getByText('Shared in direct chat', { exact: true }).waitFor()
  await ownerHistory.getByText('Attachment downloaded', { exact: true }).waitFor()
  assert.equal(await ownerHistory.getByText('File details viewed', { exact: true }).count(), 2)

  const ownerDetails = ownerPage.getByRole('dialog', { name: 'Attachment details' })
  const sharePassword = 'synthetic-share-' + run
  await ownerDetails.getByText('Share links', { exact: true }).click()
  await ownerDetails.getByLabel('Share password').fill(sharePassword)
  await ownerDetails.getByLabel('Maximum downloads').fill('1')
  await ownerDetails.getByRole('button', { name: 'Create share link' }).click()
  const linkInput = ownerDetails.getByLabel('New share link')
  await linkInput.waitFor()
  const link = new URL(await linkInput.inputValue())
  assert.equal(link.pathname, '/shared-file')
  assert.equal(link.search, '')
  assert.match(link.hash, /^#[a-f0-9]{64}$/)
  assert.ok(!link.href.includes(sharePassword))

  const guest = await browser.newPage({ acceptDownloads: true })
  await guest.goto(link.href)
  await guest.getByLabel('Share password').fill('wrong-synthetic-password')
  await guest.getByRole('button', { name: 'Open shared attachment' }).click()
  await guest.getByText('The link or password is unavailable.', { exact: true }).waitFor()
  await guest.getByLabel('Share password').fill(sharePassword)
  await guest.getByRole('button', { name: 'Open shared attachment' }).click()
  await guest.getByText(filename, { exact: true }).waitFor()
  const guestDownload = guest.waitForEvent('download')
  await guest.getByRole('button', { name: 'Download attachment' }).click()
  assert.equal((await guestDownload).suggestedFilename(), filename)

  const redeem = (token, action) => fetch(new URL('/api/files/share', app), {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, password: sharePassword, action }),
  })
  assert.equal((await redeem(link.hash.slice(1), 'download')).status, 404)
  const parallelToken = data(await owner.client.rpc('st_v6_create_file_share', {
    p_file: file, p_password: sharePassword, p_seconds: 900, p_downloads: 1,
  }))
  const parallel = await Promise.all([redeem(parallelToken, 'download'), redeem(parallelToken, 'download')])
  assert.deepEqual(parallel.map(response => response.status).sort(), [200, 404])
  const accepted = parallel.find(response => response.ok)
  assert.match(accepted.headers.get('cache-control'), /no-store/)
  assert.deepEqual(Buffer.from(await accepted.arrayBuffer()), bytes)

  await ownerDetails.getByLabel('Share password').fill(sharePassword)
  await ownerDetails.getByRole('button', { name: 'Create share link' }).click()
  await ownerDetails.getByText('Expired or used up', { exact: false }).nth(1).waitFor()
  await ownerDetails.getByRole('button', { name: 'Revoke link', exact: true }).waitFor()
  const revokedToken = new URL(await linkInput.inputValue()).hash.slice(1)
  assert.notEqual(revokedToken, link.hash.slice(1))
  await ownerDetails.getByRole('button', { name: 'Revoke link', exact: true }).click()
  await ownerHistory.getByText('Share link revoked', { exact: true }).waitFor()
  assert.equal((await redeem(revokedToken, 'view')).status, 404)
  await ownerHistory.getByText('Share link details viewed', { exact: true }).waitFor()
  assert.equal(await ownerHistory.getByText('Shared attachment downloaded', { exact: true }).count(), 2)
  console.log('Attachment access history and password share links passed with owner, peer, guest, fetch, concurrent cap, and revoke.')
} finally {
  await browser?.close()
  data(await admin.storage.from('sectalk-chat-files').remove([file]))
  sql(`delete from sectalk_private.st_v6_file_downloads where file_id='${file}';
    delete from public.st_messages where id='${file}';
    ${chat ? `delete from public.st_chats where id='${chat}';` : ''}`)
  for (const id of accounts) data(await admin.auth.admin.deleteUser(id))
}
