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
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(supabase.origin, publicKey, options)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: handle }))
  return { id: user.id, handle, email, client }
}

const [owner, receiver, offline] = await Promise.all([
  account('admin_owner'), account('admin_receiver'), account('admin_offline'),
])
const workspace = data(await owner.client.rpc('st_v2_create_workspace', { p_name: 'Admin alert audit workspace' }))
for (const person of [receiver, offline]) {
  data(await owner.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: person.handle }))
  const invite = data(await person.client.from('st_v2_invites').select('id').eq('workspace_id', workspace).single())
  data(await person.client.rpc('st_v2_reply_invite', { p_invite: invite.id, p_accept: true }))
  data(await owner.client.rpc('st_v2_set_member', { p_workspace: workspace, p_member: person.id, p_role: 'admin' }))
}
const room = randomUUID()
const roomName = 'Admin alert audit room'
data(await owner.client.rpc('st_v6_room_create', { p_id: room, p_workspace: workspace,
  p_name: roomName, p_kind: 'admin', p_template: 'blank' }))

const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
try {
  async function open(person) {
    const page = await browser.newPage()
    await page.goto(new URL('/#account', app).href)
    await page.getByLabel('Email address', { exact: true }).fill(person.email)
    await page.getByLabel('Password', { exact: true }).fill(password)
    await page.locator('button.submit-auth').click()
    await page.getByRole('navigation', { name: 'SecTalk features' }).waitFor()
    await page.getByText('Live updates', { exact: true }).waitFor()
    return page
  }

  const [sender, recipient] = await Promise.all([open(owner), open(receiver)])
  await sender.getByRole('navigation', { name: 'SecTalk features' })
    .getByRole('button', { name: 'Rooms', exact: true }).click()
  await sender.getByRole('region', { name: 'Room directory' })
    .getByRole('button', { name: new RegExp(roomName) }).click()
  const adminRoom = sender.getByRole('region', { name: roomName, exact: true })
  const auditTab = adminRoom.getByRole('button', { name: 'Audit', exact: true })
  await auditTab.click()
  const audit = adminRoom.getByRole('region', { name: 'Admin notification delivery' })
  await audit.getByText('No notification delivery records yet.', { exact: true }).waitFor()
  await adminRoom.getByRole('button', { name: 'Messages', exact: true }).click()
  await adminRoom.getByLabel('Write a room message').fill('Admin post with receipt')
  const receipt = recipient.waitForResponse(response => response.ok()
    && response.url().endsWith('/rpc/st_v6_ack_admin_notification'))
  await adminRoom.getByRole('button', { name: 'Send', exact: true }).click()
  const receiptCall = await receipt
  assert.match(receiptCall.request().postDataJSON().p_receipt, /^[a-f0-9-]{36}$/)
  await recipient.locator('.toast').getByText('New activity in a workspace admin room.', { exact: true }).waitFor()
  await auditTab.click()
  await audit.getByText('Browser receipt recorded', { exact: true }).waitFor()
  assert.equal(await audit.getByText('Admin post with receipt', { exact: true }).count(), 0)
  assert.equal(await audit.getByText(receiver.handle, { exact: false }).count(), 0)
  console.log('Passed admin post browser delivery, recipient acknowledgment, and room-scoped audit status.')
} finally {
  await browser.close()
}
