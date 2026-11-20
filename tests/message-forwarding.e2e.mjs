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

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

async function account(handlePrefix, name) {
  const handle = handlePrefix + '_' + suffix
  const email = handle + '@example.org'
  data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(supabase.href, key, options)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: name }))
  return { client, email, handle, name }
}

const sender = await account('fwd_sender', 'Forward Sender')
const original = await account('fwd_original', 'Original Author')
const receiver = await account('fwd_receiver', 'Forward Receiver')
async function connect(contact) {
  const id = data(await sender.client.rpc('st_request', { p_handle: contact.handle }))
  data(await contact.client.rpc('st_respond', { p_chat: id, p_accept: true }))
  return id
}
const originChat = await connect(original)
await connect(receiver)
const directBody = 'This is a direct message to forward.'
data(await original.client.rpc('st_send', { p_chat: originChat, p_id: randomUUID(), p_body: directBody }))

const workspace = data(await sender.client.rpc('st_v2_create_workspace', { p_name: 'Forward browser ' + suffix }))
data(await sender.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: receiver.handle }))
const membership = data(await receiver.client.from('st_v2_invites').select('id').eq('workspace_id', workspace).single())
data(await receiver.client.rpc('st_v2_reply_invite', { p_invite: membership.id, p_accept: true }))
async function createRoom(name, kind) {
  return data(await sender.client.rpc('st_v6_room_create', {
    p_workspace: workspace, p_id: randomUUID(), p_name: name, p_kind: kind, p_template: 'blank',
  }))
}
const sourceName = 'Forward origin'
const targetName = 'Forward target'
const privateName = 'Restricted Room'
const sourceRoom = await createRoom(sourceName, 'public')
const targetRoom = await createRoom(targetName, 'public')
const privateRoom = await createRoom(privateName, 'private')
data(await receiver.client.rpc('st_v6_room_membership', { p_room: targetRoom, p_action: 'join' }))
const roomBody = 'This is a room message to forward.'
data(await sender.client.rpc('st_v6_room_post', { p_room: sourceRoom, p_id: randomUUID(), p_body: roomBody }))
data(await sender.client.rpc('st_v6_room_post', {
  p_room: privateRoom, p_id: randomUUID(), p_body: 'This private message stays in the room.',
}))

const exact = name => ({ name, exact: true })
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
async function open(person) {
  const page = await browser.newPage()
  await page.goto(new URL('/#account', app).href)
  await page.getByLabel('Email address', { exact: true }).fill(person.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation', exact('SecTalk features')).waitFor()
  return page
}
const chat = (page, contact) => page.locator('.chat-item').filter({ hasText: contact.name }).click()
const rooms = page => page.getByRole('navigation', exact('SecTalk features')).getByRole('button', exact('Rooms')).click()
const room = async (page, name) => {
  await page.getByRole('region', exact('Room directory')).getByRole('button', { name: new RegExp(name) }).click()
  return page.getByRole('region', exact(name))
}

try {
  const [sendPage, receivePage] = await Promise.all([open(sender), open(receiver)])
  await chat(sendPage, original)
  const directPost = sendPage.locator('.message').filter({ hasText: directBody })
  await directPost.getByLabel('Message actions', { exact: true }).click()
  await directPost.getByRole('button', exact('Forward message')).click()
  const directDialog = sendPage.getByRole('dialog', exact('Forward message'))
  const directSelect = directDialog.getByRole('combobox')
  await directSelect.selectOption({ label: receiver.name + ' (@' + receiver.handle + ')' })
  await directDialog.getByRole('button', exact('Forward')).click()
  await directDialog.waitFor({ state: 'hidden' })
  await chat(receivePage, sender)
  const received = receivePage.locator('.message').filter({ hasText: directBody })
  await received.getByText('Forwarded', { exact: true }).waitFor()
  assert.doesNotMatch(await received.innerText(), new RegExp(original.name))
  await received.getByRole('button', exact('Report message')).waitFor()

  await rooms(sendPage)
  const restricted = await room(sendPage, privateName)
  await restricted.getByText('This private message stays in the room.', { exact: true }).waitFor()
  await restricted.getByText('Room message actions', { exact: true }).click()
  assert.equal(await restricted.getByRole('button', exact('Forward message')).count(), 0)

  const source = await room(sendPage, sourceName)
  const roomPost = source.getByRole('article').filter({ hasText: roomBody })
  await roomPost.getByText('Room message actions', { exact: true }).click()
  await roomPost.getByRole('button', exact('Forward message')).click()
  const roomDialog = sendPage.getByRole('dialog', exact('Forward message'))
  const roomSelect = roomDialog.getByRole('combobox')
  await roomSelect.selectOption({ label: targetName })
  assert.equal(await roomSelect.getByRole('option', exact(privateName)).count(), 0)
  await roomDialog.getByRole('button', exact('Forward')).click()
  await roomDialog.waitFor({ state: 'hidden' })

  await rooms(receivePage)
  const destination = await room(receivePage, targetName)
  await destination.getByRole('article').filter({ hasText: roomBody }).getByText('Forwarded', { exact: true }).waitFor()

  const target = await room(sendPage, targetName)
  await target.getByRole('button', exact('Settings')).click()
  const policy = target.getByRole('button', exact('Allow message forwarding'))
  await policy.click()
  await target.getByRole('button', { ...exact('Allow message forwarding'), pressed: false }).waitFor()
  const originAfterPolicy = await room(sendPage, sourceName)
  await originAfterPolicy.getByText('Room message actions', { exact: true }).click()
  await originAfterPolicy.getByRole('button', exact('Forward message')).click()
  await sendPage.getByText('No eligible rooms in this workspace.', { exact: true }).waitFor()
  console.log('Passed direct and room forwarding, recipient labels, report availability, and public room forwarding policy.')
} finally {
  await browser.close()
}
