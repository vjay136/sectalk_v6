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

const sender = await account('pref_sender')
const receiver = await account('pref_receiver')
const chat = data(await sender.client.rpc('st_request', { p_handle: receiver.handle }))
data(await receiver.client.rpc('st_respond', { p_chat: chat, p_accept: true }))
const workspace = data(await sender.client.rpc('st_v2_create_workspace', { p_name: 'Priority workspace' }))
data(await sender.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: receiver.handle }))
const invite = data(await receiver.client.from('st_v2_invites').select('id').eq('workspace_id', workspace).single())
data(await receiver.client.rpc('st_v2_reply_invite', { p_invite: invite.id, p_accept: true }))
const room = randomUUID()
data(await sender.client.rpc('st_v6_room_create', { p_id: room, p_workspace: workspace,
  p_name: 'Priority room', p_kind: 'public', p_template: 'blank' }))
data(await receiver.client.rpc('st_v6_room_membership', { p_room: room, p_action: 'join' }))

const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
try {
  const page = await browser.newPage()
  const nav = page.getByRole('navigation', { name: 'SecTalk features' })
  const preferences = page.getByRole('group', { name: 'Alert categories' })
  const dm = preferences.getByRole('checkbox', { name: 'Direct messages', exact: true })
  const call = preferences.getByRole('checkbox', { name: 'Calls', exact: true })
  const security = preferences.getByRole('checkbox', { name: 'Safety and security', exact: true })
  const toast = page.locator('.toast')
  const dmAlert = page.locator('.toast').getByText('New direct message in your inbox.', { exact: true })
  const callPrompt = page.getByRole('region', { name: 'Audio call', exact: true })

  async function openPreferences() {
    await nav.getByRole('button', { name: 'Notifications', exact: true }).click()
    await page.getByRole('button', { name: 'Preferences', exact: true }).click()
    await dm.waitFor()
  }

  async function toggle(control) {
    const response = page.waitForResponse(result => result.ok()
      && result.url().endsWith('/rpc/st_v6_set_notification_preference'))
    await control.click()
    await response
    await page.getByText('Notification preference saved.', { exact: true }).waitFor()
  }

  async function liveDecision(category, perform) {
    const response = page.waitForResponse(result => result.ok()
      && result.url().endsWith('/rpc/st_v6_direct_alert_quiet')
      && result.request().postDataJSON().p_chat === chat
      && result.request().postDataJSON().p_category === category)
    const value = await perform()
    return [await (await response).json(), value]
  }

  const send = body => sender.client.rpc('st_send', { p_chat: chat, p_id: randomUUID(), p_body: body }).then(data)
  const place = () => sender.client.rpc('st_place_call', { p_chat: chat, p_video: false }).then(data)
  const cancel = id => sender.client.rpc('st_call_status', { p_call: id, p_accept: false }).then(data)
  const mention = () => sender.client.rpc('st_v6_room_post', { p_room: room, p_id: randomUUID(),
    p_body: 'Hello @' + receiver.handle }).then(data)
  const setQuiet = muted => receiver.client.rpc('st_v6_set_quiet_mute', { p_chat: null, p_muted: muted }).then(data)
  const dismiss = () => toast.getByRole('button', { name: 'Dismiss notice' }).click()

  await page.goto(new URL('/#account', app).href)
  await page.getByLabel('Email address', { exact: true }).fill(receiver.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await nav.waitFor()
  await openPreferences()
  const controls = await preferences.getByRole('checkbox').all()
  assert.equal(controls.length, 8)
  for (const control of controls) assert.equal(await control.isChecked(), true)

  await toggle(dm)
  const [dmMuted] = await liveDecision('dm', () => send('Muted category'))
  assert.equal(dmMuted, true)
  assert.equal(await dmAlert.count(), 0)
  assert.equal(await call.isChecked(), true)

  const callId = await place()
  await callPrompt.getByRole('button', { name: 'Answer', exact: true }).waitFor()
  await cancel(callId)
  await callPrompt.waitFor({ state: 'detached' })

  await page.reload()
  await openPreferences()
  assert.equal(await dm.isChecked(), false)
  assert.equal(data(await sender.client.rpc('st_v6_notification_preferences')).dm, true)
  await toggle(dm)
  await toggle(call)
  const [callMuted, silentCall] = await liveDecision('call', place)
  assert.equal(callMuted, true)
  assert.equal(await callPrompt.count(), 0)
  await cancel(silentCall)
  const [dmEnabled] = await liveDecision('dm', () => send('Enabled category'))
  assert.equal(dmEnabled, false)
  await dmAlert.waitFor()
  await dismiss()

  await mention()
  await toast.getByText('High-priority alert', { exact: true }).waitFor()
  await toast.getByText('You were mentioned directly in a room.', { exact: true }).waitFor()
  const [ordinary] = await liveDecision('dm', () => send('Ordinary message alongside a high alert'))
  assert.equal(ordinary, false)
  assert.equal(await dmAlert.count(), 0)
  await dismiss()
  await dmAlert.waitFor()
  await dismiss()

  await toggle(security)
  await setQuiet(true)
  data(await admin.from('st_v5_account_notices').insert({ user_id: receiver.id, action: 'warn' }))
  const critical = toast.getByText('Critical security notice', { exact: true })
  await critical.waitFor()
  assert.equal(await toast.getAttribute('role'), 'alert')
  await setQuiet(false)
  await mention()
  const [stillOrdinary] = await liveDecision('dm', () => send('Ordinary message alongside a critical alert'))
  assert.equal(stillOrdinary, false)
  assert.equal(await critical.count(), 1)
  assert.equal(await toast.getByText('High-priority alert', { exact: true }).count(), 0)
  await dismiss()
  await dmAlert.waitFor()

  console.log('Passed browser notification preferences, persistence, live alert precedence, and critical quiet-hour bypass.')
} finally {
  await browser.close()
}
