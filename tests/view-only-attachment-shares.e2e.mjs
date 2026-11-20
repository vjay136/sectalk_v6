import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import sharp from 'sharp'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const run = randomUUID().slice(0, 8)
const password = randomUUID() + '1!Q'
const sharePassword = 'synthetic-view-' + run
const file = randomUUID()
const filename = 'view-only-' + run + '.txt'
const original = Buffer.from('<b>Original private text ' + run + ' & literal &amp; markup</b>')
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
  const handle = 'viewqa_' + role + '_' + run
  const email = handle + '@example.org'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  accounts.push(user.id)
  const client = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY, options)
  const { session } = data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: 'View-only QA ' + role }))
  return { handle, email, client, authorization: 'Bearer ' + session.access_token }
}
const share = (token, action, secret = sharePassword) => fetch(new URL('/api/files/share', app), {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token, action, password: secret }),
})

try {
  const owner = await account('owner')
  const peer = await account('peer')
  chat = data(await owner.client.rpc('st_request', { p_handle: peer.handle }))
  data(await peer.client.rpc('st_respond', { p_chat: chat, p_accept: true }))
  data(await owner.client.rpc('st_v5_stage_file', { p_chat: chat, p_id: file, p_filename: filename, p_bytes: original.length }))
  assert.equal((await fetch(new URL('/api/files/upload?file=' + file, app), {
    method: 'POST', headers: { Authorization: owner.authorization, 'Content-Type': 'text/plain' }, body: original,
  })).status, 200)
  assert.equal((await fetch(new URL('/api/files/publish', app), {
    method: 'POST', headers: { Authorization: owner.authorization, 'Content-Type': 'application/json' },
    body: JSON.stringify({ file, caption: '', mime: 'text/plain' }),
  })).status, 200)
  const parameters = { p_file: file, p_password: sharePassword, p_seconds: 900, p_downloads: 1,
    p_view_only: true, p_watermark: false }
  assert.equal((await peer.client.rpc('st_v6_create_file_share', parameters)).error?.code, '42501')

  browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
  const uploaderPage = await browser.newPage()
  await uploaderPage.goto(app.href)
  await uploaderPage.getByLabel('Email address', { exact: true }).fill(owner.email)
  await uploaderPage.getByLabel('Password', { exact: true }).fill(password)
  await uploaderPage.locator('button.submit-auth').click()
  await uploaderPage.getByRole('navigation', { name: 'SecTalk features' }).getByRole('button', { name: 'Files', exact: true }).click()
  await uploaderPage.getByRole('region', { name: 'Chat files' }).locator('.release-row').filter({ hasText: filename })
    .getByRole('button', { name: 'View details' }).click()
  const details = uploaderPage.getByRole('dialog', { name: 'Attachment details' })
  await details.getByText('Share links', { exact: true }).click()
  await details.getByLabel('Link access').selectOption('preview')
  assert.equal(await details.getByLabel('Watermark previews').isChecked(), true)
  await details.getByLabel('Share password').fill(sharePassword)
  await details.getByLabel('Maximum previews').fill('1')
  await details.getByRole('button', { name: 'Create share link' }).click()
  const input = details.getByLabel('New share link')
  await input.waitFor()
  const link = new URL(await input.inputValue())
  const token = link.hash.slice(1)
  assert.equal(link.search, '')

  assert.equal((await share(token, 'view', 'synthetic-wrong-password')).status, 404)
  const denied = await share(token, 'download')
  assert.equal(denied.status, 404)
  assert.ok(!(await denied.text()).includes(original.toString()))
  assert.equal((await share(token, 'preview_peek')).status, 400)
  assert.equal((await fetch(new URL('/api/files/download', app), {
    method: 'POST', headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ file }),
  })).status, 401)
  const info = await share(token, 'view')
  assert.deepEqual(await info.json(), { filename, size_bytes: original.length, view_only: true })

  const guest = await browser.newPage()
  await guest.goto(link.href)
  await guest.getByLabel('Share password').fill(sharePassword)
  await guest.getByRole('button', { name: 'Open shared attachment' }).click()
  const show = guest.getByRole('button', { name: 'Preview attachment' })
  await show.waitFor()
  assert.equal(await guest.getByRole('button', { name: 'Download attachment', exact: true }).count(), 0)
  const [response] = await Promise.all([
    guest.waitForResponse(response => response.url().endsWith('/api/files/share')),
    show.click(),
  ])
  assert.equal(response.status(), 200)
  assert.equal(response.headers()['content-type'], 'image/png')
  const image = guest.getByRole('img', { name: 'Preview of ' + filename })
  await image.waitFor()
  const rendered = await image.evaluate(async element => {
    await element.decode()
    const canvas = document.createElement('canvas')
    canvas.width = element.naturalWidth
    canvas.height = element.naturalHeight
    const context = canvas.getContext('2d')
    context.drawImage(element, 0, 0)
    return { width: canvas.width, footer: [...context.getImageData(0, canvas.height - 1, 1, 1).data] }
  })
  assert.deepEqual(rendered, { width: 768, footer: [23, 36, 53, 255] })
  assert.equal(await guest.getByText(original.toString(), { exact: true }).count(), 0)
  assert.equal((await share(token, 'preview')).status, 404)

  const binary = data(await owner.client.rpc('st_v6_create_file_share', parameters))
  const png = Buffer.from(await (await share(binary, 'preview')).arrayBuffer())
  assert.equal((await sharp(png).metadata()).format, 'png')
  assert.equal(png.includes(original), false)

  const expires = data(await owner.client.rpc('st_v6_create_file_share', parameters))
  sql(`update sectalk_private.st_v6_file_share_links set expires_at=now()-interval '1 second'
    where token_hash=extensions.digest('${expires}','sha256');`)
  assert.equal((await share(expires, 'preview')).status, 404)
  const revoked = data(await owner.client.rpc('st_v6_create_file_share', parameters))
  const linkId = data(await owner.client.rpc('st_v6_list_file_shares', { p_file: file }))[0].id
  data(await owner.client.rpc('st_v6_revoke_file_share', { p_file: file, p_link: linkId }))
  assert.equal((await share(revoked, 'preview')).status, 404)
  await details.getByRole('button', { name: 'Refresh history' }).click()
  const previewEvents = details.getByText('View-only preview opened', { exact: true })
  await previewEvents.nth(1).waitFor()
  assert.equal(await previewEvents.count(), 2)
  console.log('View-only links passed in Edge: scoped creation, watermarked PNG, direct download bypass denial, cap, expiry, revoke and audit.')
} finally {
  await browser?.close()
  data(await admin.storage.from('sectalk-chat-files').remove([file]))
  sql(`delete from sectalk_private.st_v6_file_downloads where file_id='${file}';
    delete from public.st_messages where id='${file}';
    ${chat ? `delete from public.st_chats where id='${chat}';` : ''}`)
  for (const id of accounts) data(await admin.auth.admin.deleteUser(id))
}
