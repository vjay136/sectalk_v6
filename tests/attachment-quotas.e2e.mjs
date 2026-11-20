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
const password = randomUUID() + '1!Q'
const run = randomUUID().slice(0, 8)
const bucket = 'sectalk-chat-files'
const accounts = []
const chats = []
const objects = []
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
  const handle = 'qafile_' + role + '_' + run
  const email = handle + '@example.org'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  accounts.push(user.id)
  const client = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY, options)
  const { session } = data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: 'Attachment QA ' + role }))
  return { id: user.id, handle, email, client, token: session.access_token }
}

async function connect(sender, recipient) {
  const chat = data(await sender.client.rpc('st_request', { p_handle: recipient.handle }))
  chats.push(chat)
  data(await recipient.client.rpc('st_respond', { p_chat: chat, p_accept: true }))
  return chat
}

function stage(actor, chat, id, name, bytes) {
  return actor.client.rpc('st_v5_stage_file', { p_chat: chat, p_id: id, p_filename: name, p_bytes: bytes })
}

function upload(actor, id, body) {
  return fetch(new URL('/api/files/upload?file=' + id, app), {
    method: 'POST', headers: { Authorization: 'Bearer ' + actor.token, 'Content-Type': 'text/plain' }, body,
  })
}

function capacity(account) {
  return account.client.rpc('st_v6_attachment_capacity').then(data)
}

const quoteList = values => values.map(value => "'" + value + "'").join(',')

try {
  const owner = await account('sender')
  const peer = await account('peer')
  const other = await account('other')
  const chat = await connect(owner, peer)
  const anotherChat = await connect(owner, other)
  sql(`
    insert into public.st_v2_subscriptions(user_id,plan,status,period_end)
      values('${owner.id}','basic','active',now()+interval '1 day');
    insert into sectalk_private.st_v6_attachment_policy(account_id,max_file_bytes,max_storage_bytes)
      values('${owner.id}',24,30);
  `)
  assert.deepEqual(await capacity(owner), {
    plan: 'basic', max_file_bytes: 24, max_storage_bytes: 30, stored_bytes: 0, reserved_bytes: 0,
  })
  assert.equal((await stage(owner, chat, randomUUID(), 'outside.txt', 25)).error?.code, 'PT413')

  const file = randomUUID()
  objects.push(file)
  assert.equal(data(await stage(owner, chat, file, 'bounded.txt', 3)), false)
  assert.ok((await owner.client.storage.from(bucket).upload(file, Buffer.from('abc'), {
    contentType: 'application/octet-stream',
  })).error)
  assert.equal((await upload(peer, file, 'abc')).status, 404)
  assert.equal((await upload(owner, file, 'abcd')).status, 409)
  assert.equal((await upload(owner, file, Buffer.from([0, 1, 0]))).status, 415)
  assert.equal((await capacity(owner)).stored_bytes, 0)
  assert.equal((await upload(owner, file, 'abc')).status, 200)
  assert.equal((await upload(owner, file, 'abc')).status, 200)
  const publication = await fetch(new URL('/api/files/publish', app), {
    method: 'POST', headers: { Authorization: 'Bearer ' + owner.token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ file, caption: '', mime: 'text/plain' }),
  })
  assert.equal(publication.status, 200)
  assert.equal((await capacity(owner)).stored_bytes, 3)
  assert.equal((await capacity(peer)).stored_bytes, 0)

  const races = await Promise.all([
    stage(owner, chat, randomUUID(), 'first-reservation.txt', 20),
    stage(owner, anotherChat, randomUUID(), 'second-reservation.txt', 20),
  ])
  assert.equal(races.filter(result => !result.error).length, 1)
  assert.equal(races.find(result => result.error).error.code, 'PT409')
  assert.equal((await capacity(owner)).reserved_bytes, 20)

  browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
  const page = await browser.newPage({ locale: 'en-US' })
  await page.goto(app.href)
  await page.getByLabel('Email address', { exact: true }).fill(owner.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await page.locator('.chat-item').filter({ hasText: 'Attachment QA peer' }).click()
  await page.getByText('24 B per attachment · 7 B storage available', { exact: true }).waitFor()
  const picker = page.locator('.composer input[type=file]')
  await picker.setInputFiles({ name: 'outside.txt', mimeType: 'text/plain', buffer: Buffer.alloc(25, 'a') })
  await page.getByRole('status').getByText('Your limit is 24 B per attachment.', { exact: true }).waitFor()
  await picker.setInputFiles({ name: 'browser-quota.txt', mimeType: 'text/plain', buffer: Buffer.from('hello') })
  const submitted = page.waitForResponse(response => new URL(response.url()).pathname === '/api/files/upload')
  await page.getByRole('button', { name: 'Send message', exact: true }).click()
  const browserUpload = await submitted
  objects.push(new URL(browserUpload.url()).searchParams.get('file'))
  assert.equal(browserUpload.status(), 200)
  await page.getByRole('button', { name: /browser-quota\.txt/ }).waitFor()
  await page.getByText('24 B per attachment · 2 B storage available', { exact: true }).waitFor()
  console.log('Attachment quotas passed in Edge and API with server bytes, isolated owners and competing reservations.')
} finally {
  await browser?.close()
  if (objects.length) data(await admin.storage.from(bucket).remove(objects))
  if (chats.length) sql(`delete from public.st_messages where chat_id in (${quoteList(chats)});
    delete from public.st_chats where id in (${quoteList(chats)});`)
  for (const id of accounts) data(await admin.auth.admin.deleteUser(id))
}
