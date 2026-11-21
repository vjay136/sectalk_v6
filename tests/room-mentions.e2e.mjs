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

async function account(name) {
  const handle = name.toLowerCase() + '_' + suffix
  const email = handle + '@example.org'
  data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(supabase.href, key, options)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: name }))
  return { client, email, handle }
}

const owner = await account('MentionOwner')
const member = await account('MentionPeer')
const workspace = data(await owner.client.rpc('st_v2_create_workspace', { p_name: 'Mention browser ' + suffix }))
data(await owner.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: member.handle }))
const invite = data(await member.client.from('st_v2_invites').select('id').eq('workspace_id', workspace).single())
data(await member.client.rpc('st_v2_reply_invite', { p_invite: invite.id, p_accept: true }))
const title = 'Mention room ' + suffix
const room = data(await owner.client.rpc('st_v6_room_create', {
  p_workspace: workspace, p_id: randomUUID(), p_name: title, p_kind: 'public', p_template: 'blank',
}))
data(await member.client.rpc('st_v6_room_membership', { p_room: room, p_action: 'join' }))
const chat = data(await owner.client.rpc('st_request', { p_handle: member.handle }))
data(await member.client.rpc('st_respond', { p_chat: chat, p_accept: true }))
const priorCall = data(await owner.client.rpc('st_place_call', { p_chat: chat, p_video: true }))
const twoDaysAgo = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString()
data(await admin.from('st_calls').update({ expires_at: twoDaysAgo, created_at: twoDaysAgo }).eq('id', priorCall))
const recentCall = data(await owner.client.rpc('st_place_call', { p_chat: chat, p_video: false }))
data(await admin.from('st_calls').update({ expires_at: new Date(Date.now() - 1000).toISOString() }).eq('id', recentCall))
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
const exact = name => ({ name, exact: true })
const goto = (page, name) => page.getByRole('navigation', exact('SecTalk features')).getByRole('button', exact(name)).click()

try {
  async function open(person) {
    const page = await browser.newPage()
    await page.goto(new URL('/#account', app).href)
    await page.getByLabel('Email address', { exact: true }).fill(person.email)
    await page.getByLabel('Password', { exact: true }).fill(password)
    await page.locator('button.submit-auth').click()
    await page.getByRole('navigation', exact('SecTalk features')).waitFor()
    return page
  }

  const [sender, recipient, secondDevice] = await Promise.all([open(owner), open(member), open(member)])
  await Promise.all([goto(recipient, 'Notifications'), goto(secondDevice, 'Notifications')])
  await secondDevice.getByRole('button', exact('Unread')).click()
  await secondDevice.getByText('You have no unread notifications.', { exact: true }).waitFor()
  const meetingTitles = ['Notification check ' + suffix, 'Bulk notification check ' + suffix]
  const start = new Date(Date.now() + 60 * 60 * 1000)
  const end = new Date(start.getTime() + 30 * 60 * 1000)
  for (const title of meetingTitles) {
    data(await owner.client.rpc('st_v3_schedule', {
      p_workspace: workspace, p_id: randomUUID(), p_title: title, p_agenda: '',
      p_start: start.toISOString(), p_end: end.toISOString(),
    }))
  }
  const meetingNotice = (page, title) => page.getByRole('article').filter({ has: page.getByText(title, { exact: true }) })
  for (const title of meetingTitles) {
    await meetingNotice(recipient, title).getByRole('button', exact('Mark read')).waitFor()
    await meetingNotice(secondDevice, title).waitFor()
  }
  await meetingNotice(recipient, meetingTitles[0]).getByRole('button', exact('Mark read')).click()
  await meetingNotice(secondDevice, meetingTitles[0]).waitFor({ state: 'detached' })
  await meetingNotice(secondDevice, meetingTitles[1]).waitFor()
  await recipient.getByRole('button', exact('Mark all read')).click()
  await secondDevice.getByText('You have no unread notifications.', { exact: true }).waitFor()
  await secondDevice.getByRole('button', exact('All updates')).click()
  for (const title of meetingTitles) {
    await meetingNotice(secondDevice, title).waitFor()
    assert.equal(await meetingNotice(secondDevice, title).getByRole('button', exact('Mark read')).count(), 0)
  }
  console.log('Passed two-session meeting notification delivery and individual and bulk read synchronization.')

  await goto(recipient, 'Notifications')
  await recipient.getByRole('button', exact('Mentions')).click()
  await recipient.getByText('You have no notifications yet.', { exact: true }).waitFor()
  await goto(sender, 'Rooms')
  await sender.getByRole('region', exact('Room directory')).getByRole('button', { name: new RegExp(title) }).click()
  const composer = sender.getByRole('region', exact(title))
  const body = 'Please review @' + member.handle
  await composer.getByLabel('Write a room message').fill(body)
  await composer.getByRole('button', exact('Send')).click()
  await composer.getByText(body, { exact: true }).waitFor()
  data(await owner.client.rpc('st_v6_room_post', { p_room: room, p_id: randomUUID(), p_body: '@channel Team update' }))

  const direct = recipient.getByRole('article').filter({ hasText: 'You were mentioned directly' })
  await direct.getByText(title, { exact: true }).waitFor()
  await recipient.getByText('Everyone in your room was mentioned', { exact: true }).waitFor()
  assert.match(await recipient.getByRole('article').first().innerText(), /You were mentioned directly/)
  await direct.getByRole('button', exact('View room')).click()
  await recipient.getByRole('region', exact(title)).getByText(body, { exact: true }).waitFor()
  await goto(recipient, 'Notifications')
  await recipient.getByRole('button', exact('Mentions')).click()
  await recipient.getByRole('button', exact('Unread')).click()
  await recipient.getByText('Everyone in your room was mentioned', { exact: true }).waitFor()
  assert.equal(await recipient.getByText('You were mentioned directly', { exact: true }).count(), 0)

  await recipient.getByRole('button', exact('Digest')).click()
  const missed = recipient.getByRole('region', exact('Missed calls'))
  const mentions = recipient.getByRole('region', exact('Mentions'))
  await missed.getByText('Missed audio call', { exact: true }).waitFor()
  assert.equal(await missed.getByText('Missed video call', { exact: true }).count(), 0)
  await recipient.getByRole('button', exact('Last 7 days')).click()
  await missed.getByText('Missed video call', { exact: true }).waitFor()
  await mentions.getByText('You were mentioned directly', { exact: true }).waitFor()
  await mentions.getByRole('button', exact('View room')).first().click()
  await recipient.getByRole('region', exact(title)).getByText(body, { exact: true }).waitFor()
  await goto(recipient, 'Notifications')
  await recipient.getByRole('button', exact('Digest')).click()
  await missed.getByRole('button', exact('Open conversation')).click()
  await recipient.getByRole('heading', exact('MentionOwner')).waitFor()
  console.log('Passed browser room composer, live mentions, priority, room navigation and unread state.')
  console.log('Passed browser digest periods, grouped missed calls and mentions, and both conversation links.')
} finally {
  await browser.close()
}
