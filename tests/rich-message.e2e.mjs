// Run against the isolated loopback app and Supabase stack.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const serviceKey = process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const admin = createClient(supabase.origin, serviceKey, options)
const password = randomUUID() + '1!Q'
const suffix = randomUUID().slice(0, 8)

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

async function account(handlePrefix) {
  const handle = handlePrefix + '_' + suffix
  const email = handle + '@example.org'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(supabase.origin, publicKey, options)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: handle }))
  return { id: user.id, handle, email, client }
}
const first = await account('rich_first')
const second = await account('rich_second')
const chat = data(await first.client.rpc('st_request', { p_handle: second.handle }))
data(await second.client.rpc('st_respond', { p_chat: chat, p_accept: true }))
const workspace = data(await first.client.rpc('st_v2_create_workspace', { p_name: 'Rich formatting QA' }))
const room = randomUUID()
const roomName = 'Rich room ' + suffix
const channelName = 'rich-channel-' + suffix
data(await first.client.rpc('st_v6_room_create', { p_id: room, p_workspace: workspace, p_name: roomName, p_kind: 'public', p_template: 'blank' }))
const channel = data(await first.client.rpc('st_v2_create_channel', { p_workspace: workspace, p_name: channelName }))
data(await first.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: second.handle }))
const invite = data(await second.client.from('st_v2_invites').select('id').eq('workspace_id', workspace).single())
data(await second.client.rpc('st_v2_reply_invite', { p_invite: invite.id, p_accept: true }))
data(await second.client.rpc('st_v6_room_membership', { p_room: room, p_action: 'join' }))

const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
const button = (scope, name) => scope.getByRole('button', { name, exact: true })
const nav = page => page.getByRole('navigation', { name: 'SecTalk features' })
const target = 'https://approved-a.example.invalid/start?strip=preview-credential#also-strip'
const initial = '**Direct bold** *direct emphasis* `direct inline` [documentation](' + target + ') [unsafe](javascript:alert) ![remote image](https://blocked.example.invalid/icon.png) <img src=x onerror=alert()>'
async function open(person) {
  const page = await browser.newPage()
  await page.goto(new URL('/#account', app).href, { waitUntil: 'domcontentloaded' })
  await page.getByLabel('Email address', { exact: true }).fill(person.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await nav(page).waitFor()
  return page
}
async function previewPreference(scope, enabled) {
  const settings = scope.locator('details.rich-message-formatting')
  await settings.locator('summary').focus()
  if (!await settings.evaluate(element => element.open)) await settings.locator('summary').press('Enter')
  await settings.getByLabel('Enable link previews on this device').setChecked(enabled)
}
async function destinationHits() {
  const response = await fetch('http://127.0.0.1:3530/hits', {
    headers: { Authorization: 'Bearer ' + process.env.SECTALK_URL_INSPECTION_WORKER_TOKEN }, signal: AbortSignal.timeout(2000),
  })
  assert.ok(response.ok)
  return response.json()
}
try {
  const a = await open(first)
  const b = await open(second)
  await a.locator('.chat-item').filter({ hasText: second.handle }).click()
  await b.locator('.chat-item').filter({ hasText: first.handle }).click()
  await a.getByLabel('Write a message', { exact: true }).fill(initial)
  await button(a, 'Send message').click()
  const received = b.locator('.message').filter({ hasText: 'Direct bold' })
  await received.locator('.rich-message strong').filter({ hasText: 'Direct bold' }).waitFor()
  await received.locator('em').filter({ hasText: 'direct emphasis' }).waitFor()
  await received.locator('code').filter({ hasText: 'direct inline' }).waitFor()
  const linked = received.getByRole('button', { name: /documentation/ })
  await linked.waitFor()
  assert.equal(await received.getByRole('link', { name: /documentation/ }).count(), 0)
  assert.equal(await received.getByRole('button', { name: /unsafe|remote image/ }).count(), 0)
  assert.equal(await received.locator('.rich-message img').count(), 0)
  await received.getByText(/<img src=x onerror=alert\(\)>/).waitFor()
  assert.equal(await button(received, 'Check link preview').count(), 0)
  const oldHits = await destinationHits()
  await previewPreference(b, true)
  await button(received, 'Check link preview').waitFor()
  assert.deepEqual(await destinationHits(), oldHits, 'toggle does not trigger a managed request')
  const requested = b.waitForRequest(request => request.url().endsWith('/api/safety/url-inspection'))
  await button(received, 'Check link preview').click()
  assert.deepEqual((await requested).postDataJSON(), { url: 'https://approved-a.example.invalid/start' })
  await received.getByRole('status').getByText(/approved-b\.example\.invalid.*HTTP 204/).waitFor()
  assert.deepEqual((await destinationHits()).slice(oldHits.length), [
    { url: '/start', method: 'HEAD', host: 'approved-a.example.invalid', credentials: false },
    { url: '/landing', method: 'HEAD', host: 'approved-b.example.invalid', credentials: false },
  ])
  await previewPreference(b, false)
  assert.equal(await button(received, 'Check link preview').count(), 0)
  const author = a.locator('.message').filter({ hasText: 'Direct bold' })
  await author.getByLabel('Message actions', { exact: true }).click()
  await button(author, 'Edit message').click()
  const edit = a.getByRole('dialog', { name: 'Edit message', exact: true })
  assert.equal(await edit.getByRole('textbox', { name: 'Message', exact: true }).inputValue(), initial)
  await edit.getByRole('textbox', { name: 'Message', exact: true }).fill('**Direct edited** [blocked](https://unapproved.example.invalid/test)')
  await button(edit, 'Save changes').click()
  const changed = b.locator('.message').filter({ hasText: 'Direct edited' })
  await changed.locator('.rich-message strong').filter({ hasText: 'Direct edited' }).waitFor()
  await previewPreference(b, true)
  await button(changed, 'Check link preview').click()
  await changed.getByRole('status').getByText('Link preview unavailable.', { exact: true }).waitFor()
  assert.equal((await destinationHits()).length, oldHits.length + 2)

  async function openRoom(page) {
    await button(nav(page), 'Rooms').click()
    await page.getByRole('button', { name: new RegExp(roomName) }).click()
    return page.getByRole('region', { name: roomName, exact: true })
  }
  const ar = await openRoom(a)
  const br = await openRoom(b)
  await ar.getByLabel('Write a room message', { exact: true }).fill('**Room bold** [documentation](' + target + ')')
  await button(ar, 'Send').click()
  const roomPost = br.getByRole('article').filter({ hasText: 'Room bold' })
  await roomPost.locator('.rich-message strong').filter({ hasText: 'Room bold' }).waitFor()
  await button(roomPost, 'Check link preview').waitFor()
  const roomAuthor = ar.getByRole('article').filter({ hasText: 'Room bold' })
  await roomAuthor.getByText('Room message actions', { exact: true }).click()
  await button(roomAuthor, 'Edit message').click()
  await ar.getByLabel('Edit room message', { exact: true }).fill('*Room edited*')
  await button(ar, 'Save edit').click()
  await br.locator('.rich-message em').filter({ hasText: 'Room edited' }).waitFor()

  async function openChannel(page) {
    await button(page, 'Workspace channels').click()
    await page.getByRole('combobox', { name: /^Channel/ }).first().selectOption(channel)
    return page.getByRole('region', { name: '#' + channelName, exact: true })
  }
  const ac = await openChannel(a)
  const bc = await openChannel(b)
  await ac.getByLabel('Channel message', { exact: true }).fill('**Channel bold** [documentation](' + target + ')')
  await button(ac, 'Send message').click()
  const channelPost = bc.getByRole('article').filter({ hasText: 'Channel bold' })
  await channelPost.locator('.rich-message strong').filter({ hasText: 'Channel bold' }).waitFor()
  await button(channelPost, 'Check link preview').waitFor()
  console.log('Real direct send/edit, managed room send/edit, and channel send rendered safe Markdown. Explicit guarded preview and preference verified.')
} finally {
  await browser.close()
  await Promise.allSettled([first, second].map(person => admin.auth.admin.deleteUser(person.id)))
}
