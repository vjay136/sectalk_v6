// Run against the isolated loopback app and Supabase stack.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.hostname, '127.0.0.1')
const key = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const serviceKey = process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
assert.ok(key && serviceKey)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(supabase.href, serviceKey, options)
const suffix = randomUUID().slice(0, 8)
const password = randomUUID() + '1!Q'

function result(response) {
  if (response.error) throw new Error(response.error.message)
  return response.data
}

async function account(handle, name) {
  handle += '_' + suffix
  const email = handle + '@example.org'
  result(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(supabase.href, key, options)
  result(await client.auth.signInWithPassword({ email, password }))
  result(await client.rpc('st_save_profile', { p_handle: handle, p_name: name }))
  return { client, email, handle, name }
}

const [owner, peer] = await Promise.all([account('typing_a', 'Typing Owner'), account('typing_b', 'Typing Peer')])
const chat = result(await owner.client.rpc('st_request', { p_handle: peer.handle }))
result(await peer.client.rpc('st_respond', { p_chat: chat, p_accept: true }))
const workspace = result(await owner.client.rpc('st_v2_create_workspace', { p_name: 'Typing workspace ' + suffix }))
result(await owner.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: peer.handle }))
const invitation = result(await peer.client.from('st_v2_invites').select('id').eq('workspace_id', workspace).single())
result(await peer.client.rpc('st_v2_reply_invite', { p_invite: invitation.id, p_accept: true }))
const title = 'Typing room ' + suffix
const room = result(await owner.client.rpc('st_v6_room_create', {
  p_workspace: workspace, p_id: randomUUID(), p_name: title, p_kind: 'public', p_template: 'blank',
}))
result(await peer.client.rpc('st_v6_room_membership', { p_room: room, p_action: 'join' }))
const thread = randomUUID()
result(await owner.client.rpc('st_v6_room_post', { p_room: room, p_id: thread, p_body: 'Typing test thread' }))

const exact = name => ({ name, exact: true })
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
const policy = (container, share) => container.getByRole('button', { ...exact('Share my typing'), pressed: share })

async function open(person, contact) {
  const page = await browser.newPage()
  await page.goto(new URL('/#account', app).href)
  await page.getByLabel('Email address', { exact: true }).fill(person.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation', exact('SecTalk features')).waitFor()
  await page.locator('.chat-item').filter({ hasText: contact.name }).click()
  await policy(page, true).waitFor()
  return page
}

async function openRoom(page) {
  await page.getByRole('navigation', exact('SecTalk features')).getByRole('button', exact('Rooms')).click()
  await page.getByRole('region', exact('Room directory')).getByRole('button', { name: new RegExp(title) }).click()
  const panel = page.getByRole('region', exact(title))
  await policy(panel, true).waitFor()
  return panel
}

try {
  const [sender, receiver] = await Promise.all([open(owner, peer), open(peer, owner)])
  const directComposer = sender.getByLabel('Write a message', { exact: true })
  const directIndicator = receiver.getByText('Contact is typing…', { exact: true })
  const directPulse = sender.waitForResponse(response => response.url().endsWith('/rpc/st_v2_typing'))
  await directComposer.fill('Visible draft')
  const directResponse = await directPulse
  if (!directResponse.ok()) assert.fail(await directResponse.text())
  assert.ok(result(await peer.client.rpc('st_v2_chat_status', { p_chat: chat })).typing_until, 'Direct pulse is missing in peer status')
  await directIndicator.waitFor()
  await policy(sender, true).click()
  await policy(sender, false).waitFor()
  await directIndicator.waitFor({ state: 'hidden' })
  await directComposer.fill('Private draft')
  assert.equal(result(await peer.client.rpc('st_v2_chat_status', { p_chat: chat })).typing_until, null)

  const [senderRoom, receiverRoom] = await Promise.all([openRoom(sender), openRoom(receiver)])
  const roomIndicator = receiverRoom.getByText('Someone is typing…', { exact: true })
  const controls = panel => panel.getByRole('button', { name: /^Open thread/ })
  await Promise.all([controls(senderRoom).click(), controls(receiverRoom).click()])
  const reply = senderRoom.getByLabel('Write a reply', { exact: true })
  await policy(senderRoom, true).waitFor()
  const roomPulse = sender.waitForResponse(response => response.url().endsWith('/rpc/st_v6_room_typing'))
  await reply.fill('Visible thread draft')
  const roomResponse = await roomPulse
  if (!roomResponse.ok()) assert.fail(await roomResponse.text())
  await roomIndicator.waitFor()
  assert.equal(result(await peer.client.rpc('st_v6_room_typing_status', { p_room: room, p_parent: null })).typing_until, null)
  await policy(senderRoom, true).click()
  await policy(senderRoom, false).waitFor()
  await roomIndicator.waitFor({ state: 'hidden' })
  await reply.fill('Private thread draft')
  assert.equal(result(await peer.client.rpc('st_v6_room_typing_status', { p_room: room, p_parent: thread })).typing_until, null)

  console.log('Passed browser typing indicators, opt-out, and thread scoping with two signed-in accounts.')
} finally {
  await browser.close()
}
