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

async function account(prefix) {
  const handle = prefix + '_' + suffix
  const email = handle + '@example.org'
  data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(supabase.origin, publicKey, options)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: handle }))
  return { handle, email, client }
}

const [owner, member] = await Promise.all([account('policy_owner'), account('policy_member')])
const workspace = data(await owner.client.rpc('st_v2_create_workspace', { p_name: 'Alert policy workspace' }))
data(await owner.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: member.handle }))
const invite = data(await member.client.from('st_v2_invites').select('id').eq('workspace_id', workspace).single())
data(await member.client.rpc('st_v2_reply_invite', { p_invite: invite.id, p_accept: true }))
const room = randomUUID()
data(await owner.client.rpc('st_v6_room_create', { p_id: room, p_workspace: workspace,
  p_name: 'Alert policy room', p_kind: 'public', p_template: 'blank' }))
data(await member.client.rpc('st_v6_room_membership', { p_room: room, p_action: 'join' }))
data(await member.client.rpc('st_v6_set_notification_preference', { p_category: 'mention', p_enabled: false }))
data(await member.client.rpc('st_v6_set_quiet_mute', { p_chat: null, p_muted: true }))

const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
try {
  const nav = page => page.getByRole('navigation', { name: 'SecTalk features' })
  const policy = page => page.getByRole('region', { name: 'Notification policy' })
  async function open(person) {
    const page = await browser.newPage()
    await page.goto(new URL('/#account', app).href)
    await page.getByLabel('Email address', { exact: true }).fill(person.email)
    await page.getByLabel('Password', { exact: true }).fill(password)
    await page.locator('button.submit-auth').click()
    await nav(page).waitFor()
    await page.getByText('Live updates', { exact: true }).waitFor()
    await nav(page).getByRole('button', { name: 'Workspaces', exact: true }).click()
    await policy(page).waitFor()
    return page
  }

  const [ownerPage, memberPage] = await Promise.all([open(owner), open(member)])
  const settings = policy(ownerPage)
  const save = settings.getByRole('button', { name: 'Save notification policy', exact: true })
  const quietLimit = settings.getByLabel('Maximum quiet minutes', { exact: true })
  const toast = memberPage.locator('.toast')
  assert.equal(await policy(memberPage).getByRole('button', { name: 'Save notification policy' }).count(), 0)

  await settings.getByRole('checkbox', { name: 'Room mentions', exact: true }).check()
  await quietLimit.fill('60')
  await save.click()
  await settings.getByText('Notification policy saved.', { exact: true }).waitFor()
  assert.deepEqual(data(await member.client.rpc('st_v6_workspace_notification_settings', { p_workspace: workspace })),
    { mandatory_categories: ['mention'], max_quiet_minutes: 60 })

  const post = body => owner.client.rpc('st_v6_room_post', { p_room: room, p_id: randomUUID(), p_body: body }).then(data)
  await post('Required mention @' + member.handle)
  await toast.getByText('You were mentioned directly in a room.', { exact: true }).waitFor()
  await toast.getByRole('button', { name: 'Dismiss notice' }).click()
  await quietLimit.fill('0')
  await save.click()
  await settings.getByText('Notification policy saved.', { exact: true }).waitFor()
  await post('Ordinary update after quiet policy cap')
  await toast.getByText('New activity in one of your rooms.', { exact: true }).waitFor()

  console.log('Passed workspace notification policy editor, member read scope, mandatory delivery, and quiet limit.')
} finally {
  await browser.close()
}
