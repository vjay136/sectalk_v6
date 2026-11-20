import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
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
const bucket = 'sectalk-chat-files'
const part = 256 * 1024
const bytes = Buffer.concat([Buffer.alloc(part, 65), Buffer.alloc(part, 66), Buffer.alloc(part, 67), Buffer.from('Harmless final part.')])
const filename = 'resumable-' + run + '.txt'
const hash = value => createHash('sha256').update(value).digest('hex')
const files = []
const accounts = []
let browser
let chat

function data(result) {
  if (result.error) throw result.error
  return result.data
}
function sql(statement) {
  return execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-At', '-v', 'ON_ERROR_STOP=1',
    '-U', 'postgres', '-d', 'postgres'], { input: statement, encoding: 'utf8', windowsHide: true }).trim()
}
async function account(role) {
  const handle = 'resqa_' + role + '_' + run
  const name = 'Resumable QA ' + role + ' ' + run
  const email = handle + '@example.invalid'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  accounts.push(user.id)
  const client = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY, options)
  const { session } = data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: name }))
  return { client, handle, name, email, headers: { Authorization: 'Bearer ' + session.access_token } }
}
const request = (path, init) => fetch(new URL(path, app), init)
const json = (path, actor, body) => request(path, {
  method: 'POST', headers: { ...actor.headers, 'Content-Type': 'application/json' }, body: JSON.stringify(body),
})
function transfer(actor, file, expected, action, offset, body, digest = body && hash(body)) {
  const append = action === 'chunk'
  return request('/api/files/resumable?file=' + file + (append ? '&offset=' + offset : '&action=' + action), {
    method: append ? 'PUT' : 'POST', body,
    headers: { ...actor.headers, 'X-SecTalk-Upload-SHA256': expected, 'X-SecTalk-File-Type': 'text/plain',
      ...(append ? { 'Content-Type': 'application/octet-stream', 'X-SecTalk-Chunk-SHA256': digest } : {}) },
  })
}
async function stage(actor, name, contents) {
  const file = randomUUID()
  files.push(file)
  data(await actor.client.rpc('st_v5_stage_file', { p_chat: chat, p_id: file, p_filename: name, p_bytes: contents.length }))
  return file
}

try {
  const sender = await account('sender')
  const recipient = await account('recipient')
  chat = data(await sender.client.rpc('st_request', { p_handle: recipient.handle }))
  data(await recipient.client.rpc('st_respond', { p_chat: chat, p_accept: true }))
  browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
  const page = await browser.newPage()
  const browserOffsets = []
  let uploadedFile
  let interrupted = false
  await page.route('**/api/files/resumable?*', async route => {
    const url = new URL(route.request().url())
    uploadedFile = url.searchParams.get('file')
    if (!files.includes(uploadedFile)) files.push(uploadedFile)
    if (route.request().method() === 'PUT') {
      const offset = Number(url.searchParams.get('offset'))
      browserOffsets.push(offset)
      if (offset === part && !interrupted) {
        interrupted = true
        const actual = await route.fetch()
        assert.equal(actual.status(), 200)
        assert.equal((await actual.json()).offset, 2 * part)
        await route.abort('internetdisconnected')
        return
      }
    }
    await route.continue()
  })
  await page.goto(app.href)
  await page.getByLabel('Email address', { exact: true }).fill(sender.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await page.locator('.chat-item').filter({ hasText: recipient.name }).click()
  await page.locator('.composer input[type=file]').setInputFiles({ name: filename, mimeType: 'text/plain', buffer: bytes })
  await page.getByRole('button', { name: 'Send message', exact: true }).click()
  const retry = page.getByRole('button', { name: 'Retry message', exact: true })
  await retry.waitFor()
  assert.equal(interrupted, true)
  assert.deepEqual(browserOffsets, [0, part])
  const expected = hash(bytes)
  const first = bytes.subarray(0, part)
  const last = bytes.subarray(3 * part)
  assert.deepEqual(await (await transfer(sender, uploadedFile, expected, 'status')).json(), { offset: 2 * part, uploaded: false })
  assert.deepEqual(await (await transfer(sender, uploadedFile, expected, 'chunk', 0, first)).json(), { offset: 2 * part, uploaded: false })
  assert.equal((await transfer(sender, uploadedFile, expected, 'chunk', 0, Buffer.alloc(part, 68))).status, 409)
  assert.equal((await transfer(sender, uploadedFile, expected, 'chunk', 3 * part, last)).status, 409)
  assert.equal((await transfer(sender, uploadedFile, expected, 'chunk', 2 * part, first, '0'.repeat(64))).status, 422)
  assert.equal((await transfer(sender, uploadedFile, '0'.repeat(64), 'status')).status, 409)
  assert.equal((await transfer(recipient, uploadedFile, expected, 'status')).status, 404)
  assert.equal((await json('/api/files/publish', sender, { file: uploadedFile, mime: 'text/plain', caption: '' })).status, 409)
  assert.ok((await admin.storage.from(bucket).download(uploadedFile)).error)
  assert.equal((await request('/api/files/upload?file=' + uploadedFile, {
    method: 'POST', headers: { ...sender.headers, 'Content-Type': 'text/plain' }, body: bytes,
  })).status, 409)

  const published = page.waitForResponse(response => response.url().endsWith('/api/files/publish') && response.status() === 200)
  await retry.click()
  await published
  assert.deepEqual(browserOffsets, [0, part, 2 * part, 3 * part])
  const stored = data(await admin.storage.from(bucket).download(uploadedFile))
  assert.deepEqual(Buffer.from(await stored.arrayBuffer()), bytes)
  const grant = await json('/api/files/download', recipient, { file: uploadedFile })
  assert.equal(grant.status, 200)
  const received = await request((await grant.json()).url, { headers: recipient.headers })
  assert.equal(received.status, 200)
  assert.deepEqual(Buffer.from(await received.arrayBuffer()), bytes)
  assert.ok((await recipient.client.storage.from(bucket).download(uploadedFile)).error)
  assert.equal(sql(`select count(*) from sectalk_private.st_v6_attachment_chunks where file_id='${uploadedFile}';`), '0')
  assert.equal(sql(`select state from sectalk_private.st_v6_attachment_scans where file_id='${uploadedFile}';`), 'clean')

  const legacyBytes = Buffer.from('A harmless upload made before resumable transfers.')
  const legacy = await stage(sender, 'legacy.txt', legacyBytes)
  assert.equal((await request('/api/files/upload?file=' + legacy, {
    method: 'POST', headers: { ...sender.headers, 'Content-Type': 'text/plain' }, body: legacyBytes,
  })).status, 200)
  assert.equal((await transfer(sender, legacy, '0'.repeat(64), 'status')).status, 409)
  assert.deepEqual(await (await transfer(sender, legacy, hash(legacyBytes), 'status')).json(),
    { offset: legacyBytes.length, uploaded: true })

  const wrongBytes = Buffer.from('A harmless wrong whole-file checksum.')
  const wrong = await stage(sender, 'wrong.txt', wrongBytes)
  assert.equal((await transfer(sender, wrong, '0'.repeat(64), 'status')).status, 200)
  assert.equal((await transfer(sender, wrong, '0'.repeat(64), 'chunk', 0, wrongBytes)).status, 200)
  assert.equal((await transfer(sender, wrong, '0'.repeat(64), 'assemble')).status, 422)
  assert.ok((await admin.storage.from(bucket).download(wrong)).error)

  const abandoned = await stage(sender, 'abandoned.txt', bytes)
  assert.equal((await transfer(sender, abandoned, expected, 'status')).status, 200)
  assert.equal((await transfer(sender, abandoned, expected, 'chunk', 0, first)).status, 200)
  const unfinished = await stage(sender, 'finalized-not-sent.txt', wrongBytes)
  const unfinishedHash = hash(wrongBytes)
  assert.equal((await transfer(sender, unfinished, unfinishedHash, 'status')).status, 200)
  assert.equal((await transfer(sender, unfinished, unfinishedHash, 'chunk', 0, wrongBytes)).status, 200)
  assert.equal((await transfer(sender, unfinished, unfinishedHash, 'assemble')).status, 200)
  const promoted = data(await admin.storage.from(bucket).download(unfinished))
  assert.deepEqual(Buffer.from(await promoted.arrayBuffer()), wrongBytes)
  const expiring = [wrong, abandoned, unfinished].map(id => "'" + id + "'").join(',')
  sql(`update public.st_v5_files set created_at=now()-interval '20 minutes',upload_lease_until=now()-interval '1 second'
    where id in (${expiring});`)
  assert.equal((await transfer(sender, abandoned, expected, 'status')).status, 404)
  const purge = await request('/api/files/purge', {
    method: 'POST', headers: { Authorization: 'Bearer ' + process.env.SECTALK_FILE_PURGE_SECRET },
  })
  assert.equal(purge.status, 200)
  assert.equal(sql(`select count(*) from sectalk_private.st_v6_attachment_uploads where file_id in (${expiring});`), '0')
  assert.equal(sql(`select count(*) from public.st_v5_files where id in (${expiring}) and purged_at is not null;`), '3')
  assert.ok((await admin.storage.from(bucket).download(unfinished)).error)
  console.log('Resumable upload passed in Edge with an acknowledged server chunk and lost client response, exact Storage bytes, ACLs, verification and expired chunk cleanup.')
} finally {
  await browser?.close()
  if (files.length) {
    data(await admin.storage.from(bucket).remove(files))
    const ids = files.map(file => "'" + file + "'").join(',')
    sql(`delete from sectalk_private.st_v6_file_downloads where file_id in (${ids});
      delete from public.st_messages where id in (${ids});
      delete from public.st_v5_files where id in (${ids});`)
  }
  if (chat) sql(`delete from public.st_chats where id='${chat}';`)
  for (const id of accounts) data(await admin.auth.admin.deleteUser(id))
}
