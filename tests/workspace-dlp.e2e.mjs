import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { verifyStaffPanel } from './workspace-admin-fixture.mjs'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const backend = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(backend.origin, 'http://127.0.0.1:55321')
const sdk = { auth: { persistSession: false, autoRefreshToken: false } }
const key = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const service = createClient(backend.href, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, sdk)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
const run = randomUUID().slice(0, 8)
const password = randomUUID() + '!1q'
const users = []
let workspace

function data(result) {
  if (result.error) throw result.error
  return result.data
}
async function account(role) {
  const handle = `dlp_${role}_${run}`
  const email = handle + '@example.invalid'
  const { user } = data(await service.auth.admin.createUser({ email, password, email_confirm: true }))
  users.push(user.id)
  const client = createClient(backend.href, key, sdk)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: role + ' DLP fixture' }))
  const page = await browser.newPage()
  await page.goto(app.href)
  await page.getByLabel('Email address', { exact: true }).fill(email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await nav(page).waitFor()
  return { handle, client, page }
}
const nav = page => page.getByRole('navigation', { name: 'SecTalk features' })

try {
  const owner = await account('owner')
  const member = await account('member')
  const room = randomUUID()
  const roomName = 'DLP room ' + run
  workspace = data(await owner.client.rpc('st_v2_create_workspace', { p_name: 'DLP workspace ' + run }))
  data(await owner.client.rpc('st_v6_room_create', { p_id: room, p_workspace: workspace, p_name: roomName, p_kind: 'public', p_template: 'blank' }))
  data(await owner.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: member.handle }))
  const invitations = data(await member.client.from('st_v2_invites').select('id').eq('workspace_id', workspace))
  data(await member.client.rpc('st_v2_reply_invite', { p_invite: invitations[0].id, p_accept: true }))
  data(await member.client.rpc('st_v6_room_membership', { p_room: room, p_action: 'join' }))

  await nav(owner.page).getByRole('button', { name: 'Workspaces', exact: true }).click()
  await owner.page.getByRole('group', { name: 'Workspace sections' }).getByRole('button', { name: 'Data loss controls', exact: true }).click()
  const policy = owner.page.getByRole('region', { name: 'Data loss controls' })
  await verifyStaffPanel(policy)
  await policy.getByRole('button', { name: 'Save data loss rules', exact: true }).waitFor()
  await policy.getByLabel('Email addresses', { exact: true }).selectOption('warn')
  await policy.getByLabel('Payment card numbers', { exact: true }).selectOption('block')
  await policy.getByLabel('Health record identifiers', { exact: true }).selectOption('redact')
  await policy.getByLabel('Credentials', { exact: true }).selectOption('redact')
  await policy.getByRole('button', { name: 'Save data loss rules', exact: true }).click()
  await policy.getByText('Workspace data loss policy saved.', { exact: true }).waitFor()
  assert.equal((await member.client.rpc('st_v7_workspace_dlp', { p_workspace: workspace })).error?.code, '42501')

  async function openRoom(page) {
    await nav(page).getByRole('button', { name: 'Rooms', exact: true }).click()
    await page.getByRole('button', { name: new RegExp(roomName) }).click()
    return page.getByRole('region', { name: roomName, exact: true })
  }
  const viewing = await openRoom(owner.page)
  const sender = await openRoom(member.page)
  const composer = sender.getByLabel('Write a room message', { exact: true })
  const send = sender.getByRole('button', { name: 'Send', exact: true })
  const warningText = 'An email for the fixture is qa-notice@example.invalid.'
  await composer.fill(warningText)
  await send.click()
  const warning = sender.getByRole('alertdialog', { name: 'Sensitive information warning' })
  await warning.getByText(/may contain Email addresses/).waitFor()
  await warning.getByRole('button', { name: 'Keep editing', exact: true }).click()
  assert.equal(await composer.inputValue(), warningText)
  assert.equal(await viewing.getByText(warningText, { exact: true }).count(), 0)
  await send.click()
  await warning.getByRole('button', { name: 'Send after warning', exact: true }).click()
  await viewing.getByText(warningText, { exact: true }).waitFor()

  await composer.fill('Generated sample 4111 1111 1111 1111')
  await send.click()
  await sender.getByRole('alert').filter({ hasText: 'Workspace policy blocked this message' }).waitFor()
  assert.equal(await viewing.getByText('Generated sample 4111 1111 1111 1111', { exact: true }).count(), 0)
  await composer.fill('Fixture MRN: SYNTH-303 and API key=fixture_only_token')
  await send.click()
  await viewing.getByText('Fixture […] and […]', { exact: true }).waitFor()
  const edit = sender.getByRole('article').filter({ hasText: 'Fixture […] and […]' })
  await edit.getByText('Room message actions', { exact: true }).click()
  await edit.getByRole('button', { name: 'Edit message', exact: true }).click()
  await sender.getByLabel('Edit room message', { exact: true }).fill('Updated patient ID: SYNTH-505')
  await sender.getByRole('button', { name: 'Save edit', exact: true }).click()
  await viewing.getByText('Updated […]', { exact: true }).waitFor()
  console.log('Verified real workspace policy management, exact warning confirmation, block before delivery, and live redaction on send and edit.')
} finally {
  await browser.close()
  if (workspace) execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1',
    '-U', 'postgres', '-d', 'postgres'], { input: `delete from public.st_v2_workspaces where id='${workspace}';`, windowsHide: true })
  for (const user of users) data(await service.auth.admin.deleteUser(user))
}
