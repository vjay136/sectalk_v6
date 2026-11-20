import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import sharp from 'sharp'
import { previewPdf } from './fixtures/preview-pdf.mjs'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const run = randomUUID().slice(0, 8)
const password = randomUUID() + '1!Q'
const accounts = []
const files = []
const workerEnabled = process.env.SECTALK_TEST_PDF_PREVIEW_WORKER === '1'
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
  const handle = 'prevqa_' + role + '_' + run
  const email = handle + '@example.org'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  accounts.push(user.id)
  const client = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY, options)
  const { session } = data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: 'Attachment Preview QA ' + role }))
  return { handle, email, client, authorization: 'Bearer ' + session.access_token }
}

async function publish(actor, name, mime, bytes) {
  const file = randomUUID()
  files.push(file)
  data(await actor.client.rpc('st_v5_stage_file', { p_chat: chat, p_id: file, p_filename: name, p_bytes: bytes.length }))
  assert.equal((await fetch(new URL('/api/files/upload?file=' + file, app), {
    method: 'POST', headers: { Authorization: actor.authorization, 'Content-Type': mime }, body: bytes,
  })).status, 200)
  assert.equal((await fetch(new URL('/api/files/publish', app), {
    method: 'POST', headers: { Authorization: actor.authorization, 'Content-Type': 'application/json' },
    body: JSON.stringify({ file, caption: '', mime }),
  })).status, 200)
  return file
}

function preview(actor, file) {
  return fetch(new URL('/api/files/preview?file=' + file, app), {
    headers: actor ? { Authorization: actor.authorization } : {},
  })
}

try {
  const sender = await account('sender')
  const recipient = await account('peer')
  const outsider = await account('outsider')
  chat = data(await sender.client.rpc('st_request', { p_handle: recipient.handle }))
  data(await recipient.client.rpc('st_respond', { p_chat: chat, p_accept: true }))
  const source = await sharp({ create: { width: 1200, height: 600, channels: 3, background: '#77aacc' } })
    .withMetadata({ orientation: 1 }).jpeg().toBuffer()
  assert.ok((await sharp(source).metadata()).exif)
  const image = await publish(sender, 'safe-preview.jpg', 'image/jpeg', source)
  const oversized = await publish(sender, 'oversized-preview.jpg', 'image/jpeg',
    await sharp({ create: { width: 4097, height: 1, channels: 3, background: '#335566' } }).jpeg().toBuffer())
  const markup = '<script>globalThis.__previewActive = true</script>'
  const text = await publish(sender, 'literal-preview.txt', 'text/plain', Buffer.from(markup + '\u202e\n' + 'x'.repeat(9000)))
  const pdf = await publish(sender, 'raster-required.pdf', 'application/pdf', previewPdf())
  if (workerEnabled) {
    const broken = await publish(sender, 'invalid-preview.pdf', 'application/pdf', Buffer.from('%PDF-1.4\n%%EOF\n'))
    assert.equal((await preview(recipient, broken)).status, 415)
  }

  assert.equal((await preview(null, image)).status, 401)
  assert.equal((await preview(outsider, image)).status, 404)
  assert.equal((await preview(recipient, oversized)).status, 415)
  const pdfPreview = await preview(recipient, pdf)
  assert.equal(pdfPreview.status, workerEnabled ? 200 : 503)
  if (workerEnabled) {
    assert.equal(pdfPreview.headers.get('content-type'), 'image/png')
    const raster = await sharp(Buffer.from(await pdfPreview.arrayBuffer())).metadata()
    assert.equal(raster.format, 'png')
    assert.equal(raster.width, 768)
    assert.equal(raster.height, 384)
  }
  const png = await preview(recipient, image)
  assert.equal(png.status, 200)
  assert.equal(png.headers.get('content-type'), 'image/png')
  assert.equal(png.headers.get('x-content-type-options'), 'nosniff')
  assert.match(png.headers.get('cache-control'), /no-store/)
  const transformed = await sharp(Buffer.from(await png.arrayBuffer())).metadata()
  assert.equal(transformed.format, 'png')
  assert.equal(transformed.width, 768)
  assert.equal(transformed.height, 384)
  assert.equal(transformed.exif, undefined)

  const excerpt = await preview(recipient, text)
  assert.equal(excerpt.status, 200)
  assert.match(excerpt.headers.get('content-type'), /^application\/json/)
  const payload = await excerpt.json()
  assert.equal(payload.truncated, true)
  assert.ok(payload.text.startsWith(markup) && payload.text.length <= 8192 && !payload.text.includes('\u202e'))

  browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
  const page = await browser.newPage()
  await page.goto(app.href)
  await page.getByLabel('Email address', { exact: true }).fill(recipient.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation', { name: 'SecTalk features' }).getByRole('button', { name: 'Files', exact: true }).click()
  const fileRegion = page.getByRole('region', { name: 'Chat files' })
  const dialog = page.getByRole('dialog', { name: 'Attachment details' })
  const details = name => fileRegion.locator('.release-row').filter({ hasText: name })
    .getByRole('button', { name: 'View details', exact: true }).click()
  await details('safe-preview.jpg')
  await dialog.getByRole('button', { name: 'Load preview' }).click()
  const displayed = dialog.getByRole('img', { name: 'Preview of safe-preview.jpg' })
  await displayed.waitFor()
  assert.equal(await displayed.evaluate(element => element.src.startsWith('blob:')), true)
  await page.keyboard.press('Escape')
  await details('literal-preview.txt')
  await dialog.getByRole('button', { name: 'Load preview' }).click()
  await dialog.getByText('Showing the first part of this text file.').waitFor()
  assert.ok((await dialog.locator('pre').textContent()).startsWith(markup))
  assert.equal(await dialog.locator('pre script').count(), 0)
  assert.equal(await page.evaluate(() => globalThis.__previewActive), undefined)
  await page.keyboard.press('Escape')
  await details('raster-required.pdf')
  await dialog.getByRole('button', { name: 'Load preview' }).click()
  if (workerEnabled) {
    await dialog.getByRole('img', { name: 'Preview of raster-required.pdf' }).waitFor()
    await dialog.getByText('First page', { exact: true }).waitFor()
  } else await dialog.getByText('PDF preview is unavailable here.').waitFor()

  data(await sender.client.rpc('st_v5_message_action', { p_message: image, p_action: 'revoke' }))
  assert.equal((await preview(recipient, image)).status, 404)
  data(await sender.client.rpc('st_v5_message_action', { p_message: pdf, p_action: 'revoke' }))
  assert.equal((await preview(recipient, pdf)).status, 404)
  console.log('Attachment previews passed in Edge and API with PNG re-encoding, bounded text, revocation, and PDF ' +
    (workerEnabled ? 'rasterization.' : 'fail-closed fallback.'))
} finally {
  await browser?.close()
  if (files.length) {
    data(await admin.storage.from('sectalk-chat-files').remove(files))
    const ids = files.map(file => "'" + file + "'").join(',')
    sql(`delete from sectalk_private.st_v6_file_downloads where file_id in (${ids});
      delete from public.st_messages where id in (${ids});`)
  }
  if (chat) sql(`delete from public.st_chats where id='${chat}';`)
  for (const id of accounts) data(await admin.auth.admin.deleteUser(id))
}
