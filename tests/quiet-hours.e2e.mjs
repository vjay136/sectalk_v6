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
const suffix = randomUUID().slice(0, 8)
const password = randomUUID() + '1!Q'

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

async function account(name) {
  const handle = name.toLowerCase().replaceAll(' ', '_') + '_' + suffix
  const email = handle + '@example.org'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(supabase.origin, publicKey, options)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: name }))
  return { name, handle, id: user.id, email, client }
}

const owner = await account('Quiet Owner')
const peer = await account('Quiet Peer')
const other = await account('Quiet Other')
async function connect(contact) {
  const chat = data(await owner.client.rpc('st_request', { p_handle: contact.handle }))
  data(await contact.client.rpc('st_respond', { p_chat: chat, p_accept: true }))
  return chat
}
const chat = await connect(peer)
const otherChat = await connect(other)
const roomOptions = { p_name: 'Quiet room ' + suffix, p_kind: 'public', p_template: 'blank' }
const room = randomUUID()
const secondRoom = randomUUID()
const workspace = data(await owner.client.rpc('st_v2_create_workspace', { p_name: 'Quiet rooms ' + suffix }))
data(await owner.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: peer.handle }))
const invite = data(await peer.client.from('st_v2_invites').select('id').eq('workspace_id',workspace).single())
data(await peer.client.rpc('st_v2_reply_invite', { p_invite: invite.id, p_accept: true }))
const general = data(await owner.client.from('st_v2_channels').select('id').eq('workspace_id',workspace).eq('name','general').single())
for (const [id, name] of [[room, roomOptions.p_name], [secondRoom, 'Other room ' + suffix]]) {
  data(await owner.client.rpc('st_v6_room_create', { ...roomOptions, p_id: id, p_workspace: workspace, p_name: name }))
  data(await peer.client.rpc('st_v6_room_membership', { p_room: id, p_action: 'join' }))
}
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })

const nav = page => page.getByRole('navigation', { name: 'SecTalk features' })
const goto = (page, name) => nav(page).getByRole('button', { name, exact: true }).click()
const selectChat = (page, contact) => page.locator('.chat-item').filter({ hasText: contact.name }).click()
const receivedAlert = page => page.locator('.toast').getByText('New direct message in your inbox.', { exact: true })
const quietNotice = 'Notifications are quiet now.'
const regularNotice = 'Notifications are enabled.'
const time = offset => new Date(Date.now() + offset * 3600_000).toISOString().slice(11, 16)
const rpcQuiet = (client, chatId) => client.rpc('st_v6_quiet_active', { p_chat: chatId }).then(data)
const send = (person, chatId, body) => person.client.rpc('st_send', { p_chat: chatId, p_id: randomUUID(), p_body: body }).then(data)

try {
  async function open(person) {
    const page = await browser.newPage({ timezoneId: 'UTC' })
    await page.goto(new URL('/#account', app).href)
    await page.getByLabel('Email address', { exact: true }).fill(person.email)
    await page.getByLabel('Password', { exact: true }).fill(password)
    await page.locator('button.submit-auth').click()
    await nav(page).waitFor()
    return page
  }
  async function availability(page) {
    await goto(page, 'Profile')
    await page.getByRole('button', { name: 'Availability', exact: true }).click()
    await page.getByRole('heading', { name: 'Do not disturb' }).waitFor()
  }
  async function schedule(scope, status) {
    await scope.getByLabel('Schedule quiet hours').check()
    await scope.getByLabel('Starts at').fill(time(-1))
    await scope.getByLabel('Ends at').fill(time(1))
    await scope.getByLabel('Time zone', { exact: true }).fill('UTC')
    if (status) await scope.getByLabel('Status during quiet hours (optional)', { exact: true }).fill(status)
    await scope.getByRole('button', { name: 'Save quiet hours' }).click()
    await scope.getByText('Quiet hours saved.', { exact: true }).waitFor()
    await scope.getByText(quietNotice, { exact: true }).waitFor()
  }
  async function removeSchedule(scope) {
    await scope.getByLabel('Schedule quiet hours').uncheck()
    await scope.getByRole('button', { name: 'Save quiet hours' }).click()
    await scope.getByText(regularNotice, { exact: true }).waitFor()
  }
  async function waitForQuietDecision(page, chatId, action) {
    const response = page.waitForResponse(result => result.ok() && result.url().endsWith('/rpc/st_v6_direct_alert_quiet')
      && result.request().postDataJSON().p_chat === chatId)
    await action()
    const result = await response
    return result.json()
  }

  const [ownerPage, peerPage] = await Promise.all([open(owner), open(peer)])
  await selectChat(peerPage, owner)
  const peerAvailability = peerPage.getByLabel('Contact availability', { exact: true })
  await peerAvailability.filter({ hasText: /^Offline$/ }).waitFor()
  data(await owner.client.rpc('st_v5_profile_details_save', { p_status: 'Available for questions', p_refresh_photo: false }))
  await peerPage.getByText('Available for questions', { exact: true }).waitFor()
  await availability(ownerPage)
  await ownerPage.getByLabel(/Availability for approved contacts/).selectOption('online')
  await peerAvailability.filter({ hasText: /^Online$/ }).waitFor()

  await schedule(ownerPage, 'Focus time')
  await peerAvailability.filter({ hasText: /^Busy$/ }).waitFor()
  await peerPage.getByText('Focus time', { exact: true }).waitFor()
  assert.equal(data(await other.client.rpc('st_v6_effective_availability', { p_user: peer.id })), null)
  assert.equal(await rpcQuiet(owner.client, otherChat), true)
  assert.equal(await waitForQuietDecision(ownerPage, chat, () => send(peer, chat, 'Message during quiet hours')), true)
  assert.equal(await receivedAlert(ownerPage).count(), 0)
  await removeSchedule(ownerPage)
  await peerAvailability.filter({ hasText: /^Online$/ }).waitFor()
  await peerPage.getByText('Available for questions', { exact: true }).waitFor()

  await goto(ownerPage, 'Inbox')
  await selectChat(ownerPage, peer)
  await ownerPage.getByRole('log', { name: 'Messages', exact: true }).getByText('Message during quiet hours', { exact: true }).waitFor()
  await ownerPage.getByRole('button', { name: 'Chat quiet hours', exact: true }).click()
  const dialog = ownerPage.getByRole('dialog', { name: 'Chat quiet hours' })
  await dialog.getByLabel('Mute notifications').click()
  await dialog.getByText(quietNotice, { exact: true }).waitFor()
  assert.equal(await rpcQuiet(owner.client, otherChat), false)
  await dialog.getByLabel('Mute notifications').click()
  await dialog.getByText(regularNotice, { exact: true }).waitFor()
  await schedule(dialog)
  assert.equal(await rpcQuiet(owner.client, otherChat), false)
  await removeSchedule(dialog)
  await dialog.getByRole('button', { name: 'Snooze notifications', exact: true }).click()
  await dialog.getByRole('button', { name: 'End snooze', exact: true }).waitFor()
  await dialog.getByRole('button', { name: 'Close dialog', exact: true }).click()
  await goto(ownerPage, 'Calls')

  assert.equal(await waitForQuietDecision(ownerPage, chat, () => send(peer, chat, 'Message during chat snooze')), true)
  assert.equal(await receivedAlert(ownerPage).count(), 0)
  assert.equal(await waitForQuietDecision(ownerPage, otherChat, () => send(other, otherChat, 'Message from another chat')), false)
  await receivedAlert(ownerPage).waitFor()
  await ownerPage.getByRole('button', { name: 'Dismiss notice' }).click()

  let callId
  assert.equal(await waitForQuietDecision(ownerPage, chat, async () => {
    callId = data(await peer.client.rpc('st_place_call', { p_chat: chat, p_video: false }))
  }), true)
  await ownerPage.getByText('Ringing', { exact: true }).waitFor()
  assert.equal(await ownerPage.getByRole('region', { name: 'Audio call', exact: true }).count(), 0)
  const ending = ownerPage.waitForResponse(result => result.ok() && result.url().endsWith('/rpc/st_v6_direct_alert_quiet'))
  data(await peer.client.rpc('st_call_status', { p_call: callId, p_accept: false }))
  assert.equal(await (await ending).json(), true)
  assert.equal(await ownerPage.getByText('The caller cancelled.', { exact: true }).count(), 0)
  data(await owner.client.rpc('st_v6_set_quiet_snooze', { p_chat: chat, p_minutes: 0 }))
  callId = data(await peer.client.rpc('st_place_call', { p_chat: chat, p_video: false }))
  const call = ownerPage.getByRole('region', { name: 'Audio call', exact: true })
  await call.getByRole('button', { name: 'Answer', exact: true }).waitFor()
  data(await peer.client.rpc('st_call_status', { p_call: callId, p_accept: false }))
  await call.waitFor({ state: 'detached' })
  await goto(ownerPage, 'Rooms')
  await ownerPage.getByRole('button', { name: new RegExp(roomOptions.p_name) }).click()
  await ownerPage.getByRole('button', { name: 'Room quiet hours', exact: true }).click()
  const preferences = ownerPage.locator('.quiet-hours')
  const roomAlert = ownerPage.locator('.toast').getByText('New activity in one of your rooms.', { exact: true })
  const post = (id, body) => peer.client.rpc('st_v6_room_post', { p_room: id, p_id: randomUUID(), p_body: body }).then(data)
  const dismiss = () => ownerPage.getByRole('button', { name: 'Dismiss notice', exact: true }).click()
  await preferences.getByLabel('Mute notifications').click()
  await preferences.getByText(quietNotice, { exact: true }).waitFor()
  await post(room, 'Muted room message')
  await ownerPage.getByText('Muted room message', { exact: true }).waitFor()
  assert.equal(await roomAlert.count(), 0)
  await post(secondRoom, 'Other room still alerts')
  await roomAlert.waitFor()
  await dismiss()
  await preferences.getByLabel('Mute notifications').click()
  await preferences.getByText(regularNotice, { exact: true }).waitFor()
  await preferences.getByRole('button', { name: 'Snooze notifications' }).click()
  await preferences.getByRole('button', { name: 'End snooze' }).waitFor()
  await post(room, 'Snoozed room message')
  await ownerPage.getByText('Snoozed room message', { exact: true }).waitFor()
  assert.equal(await roomAlert.count(), 0)
  await preferences.getByRole('button', { name: 'End snooze' }).click()
  await preferences.getByText(regularNotice, { exact: true }).waitFor()
  await schedule(preferences)
  await post(room, 'Scheduled quiet room message')
  await ownerPage.getByText('Scheduled quiet room message', { exact: true }).waitFor()
  assert.equal(await roomAlert.count(), 0)
  await removeSchedule(preferences)
  await post(room, 'Room alerts resumed')
  await roomAlert.waitFor()
  await dismiss()
  await ownerPage.getByRole('button', { name: 'Workspace channels', exact: true }).click()
  await ownerPage.getByText('Channel quiet hours', { exact: true }).click()
  const channelPreferences = ownerPage.locator('.quiet-hours')
  await channelPreferences.getByLabel('Mute notifications').click()
  await channelPreferences.getByText(quietNotice, { exact: true }).waitFor()
  const channelPost = body => peer.client.rpc('st_v2_post', { p_channel: general.id, p_id: randomUUID(), p_body: body }).then(data)
  const channelAlert = ownerPage.locator('.toast').getByText('New activity in one of your workspace channels.', { exact: true })
  await channelPost('Muted channel post')
  await ownerPage.getByText('Muted channel post', { exact: true }).waitFor()
  assert.equal(await channelAlert.count(), 0)
  await channelPreferences.getByLabel('Mute notifications').click()
  await channelPreferences.getByText(regularNotice, { exact: true }).waitFor()
  await channelPost('Channel alerts resumed')
  await channelAlert.waitFor()
  console.log('Passed custom status and account, direct chat, room and channel quiet controls, including live alert scope.')
} finally {
  await browser.close()
}
