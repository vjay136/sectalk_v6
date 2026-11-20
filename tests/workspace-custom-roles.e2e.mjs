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
const owner = await account('roles_owner')
const member = await account('roles_member')
const workspace = data(await owner.client.rpc('st_v2_create_workspace', { p_name: 'Scoped custom roles ' + suffix }))
data(await owner.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: member.handle }))
const invite = data(await member.client.from('st_v2_invites').select('id').eq('workspace_id', workspace).single())
data(await member.client.rpc('st_v2_reply_invite', { p_invite: invite.id, p_accept: true }))
const group = randomUUID()
const other = randomUUID()
for (const [id, name] of [[group,'Scoped Team'],[other,'Unrelated Team']]) {
  data(await owner.client.rpc('st_v6_workspace_group_create', { p_workspace: workspace, p_id: id, p_kind: 'team',
    p_name: name, p_description: 'Synthetic team fixture' }))
}
const { verifyStaffPanel } = await import('./workspace-admin-fixture.mjs')
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
const button = (scope, name) => scope.getByRole('button', { name, exact: true })
const nav = page => page.getByRole('navigation', { name: 'SecTalk features' })
const panel = page => page.getByRole('region', { name: 'Workspace custom roles' })
const groups = page => page.getByRole('region', { name: 'Workspace groups and teams' })
async function open(person) {
  const page = await browser.newPage()
  await page.goto(new URL('/#account', app).href, { waitUntil: 'domcontentloaded' })
  await page.getByLabel('Email address', { exact: true }).fill(person.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await button(nav(page), 'Workspaces').click()
  return page
}
async function selectTeam(page, label) {
  await button(page, 'Groups & teams').click()
  await button(groups(page), label).click()
  await groups(page).getByRole('heading', { name: label, exact: true }).waitFor()
}
function rename(target) {
  return member.client.rpc('st_v6_workspace_group_change', { p_workspace: workspace, p_id: target, p_action: 'rename',
    p_name: 'Unauthorised update', p_description: '' })
}
try {
  const [a,b] = await Promise.all([open(owner), open(member)])
  await button(a, 'Custom roles').click()
  const controls = panel(a)
  await button(controls, 'Set up authenticator').waitFor()
  assert.equal(await button(controls,'Save role revision').count(),0)
  assert.equal(await button(b,'Custom roles').count(),0)
  await verifyStaffPanel(controls)
  await controls.getByLabel('Role name').fill('Scoped team editor')
  await controls.getByRole('combobox', { name: /Directory entry/ }).selectOption(group)
  await controls.getByRole('checkbox', { name: 'Edit directory details' }).check()
  await controls.getByRole('checkbox', { name: 'Archive entry' }).check()
  await controls.getByRole('checkbox', { name: 'Restore entry' }).check()
  await controls.getByLabel('Required device trust').selectOption('managed')
  await button(controls,'Save role revision').click()
  await controls.getByText('Current revision 1', { exact: true }).waitFor()
  await controls.getByRole('combobox', { name: /Assign to member/ }).selectOption(member.id)
  await button(controls,'Assign role').click()
  await controls.getByText('Role assigned.', { exact: true }).waitFor()

  const simulator = controls.getByRole('form', { name: 'Simulate role decision' })
  await button(simulator,'Simulate role decision').click()
  await controls.getByText('Simulation denied: Device trust', { exact: true }).waitFor()
  await simulator.getByLabel('Test device trust').selectOption('managed')
  await button(simulator,'Simulate role decision').click()
  await controls.getByText('Simulation allowed', { exact: true }).waitFor()
  await selectTeam(b,'Scoped Team')
  assert.equal((await rename(group)).error?.code, '42501')
  assert.equal(await groups(b).getByText('Edit team', { exact: true }).count(),0)

  await controls.getByLabel('Required device trust').selectOption('any')
  await button(controls,'Save role revision').click()
  await controls.getByText('Current revision 2', { exact: true }).waitFor()
  await groups(b).getByText('Edit team', { exact: true }).click()
  await groups(b).getByLabel('New name', { exact: true }).fill('Delegated edit')
  await button(groups(b), 'Save changes').click()
  await groups(b).getByRole('heading', { name: 'Delegated edit', exact: true }).waitFor()
  await button(groups(b), 'Archive team').click()
  await groups(b).getByLabel('Show archived entries only').check()
  await button(groups(b), 'Delegated edit').click()
  await button(groups(b), 'Restore team').click()
  await groups(b).getByText('No archived teams.',{exact:true}).waitFor()
  assert.equal((await rename(other)).error?.code, '42501')
  assert.equal((await member.client.rpc('st_v6_workspace_group_change', { p_workspace: workspace, p_id: group,
    p_action: 'member_added', p_user: member.id })).error?.code,'42501')
  await button(controls,'Revoke role').click()
  await controls.getByText('Role revoked.', { exact: true }).waitFor()
  assert.equal((await rename(group)).error?.code,'42501')
  const ownerToken = await a.evaluate(() => {
    const key = Object.keys(localStorage).find(name => name.endsWith('-auth-token'))
    return JSON.parse(localStorage.getItem(key)).access_token
  })
  const current = createClient(supabase.origin, publicKey, { ...options,
    global: { headers: { Authorization: 'Bearer ' + ownerToken } } })
  const role = data(await current.rpc('st_v7_workspace_custom_roles', { p_workspace: workspace })).roles[0]
  const write = name => current.rpc('st_v7_workspace_custom_roles', {
    p_workspace: workspace, p_role: role.id, p_revision: role.revision, p_action: 'save',
    p_definition: { name, target: group, permissions: ['rename'], device: 'any', enabled: true },
  })
  const simultaneous = await Promise.all([write('Concurrent A'), write('Concurrent B')])
  assert.equal(simultaneous.filter(result => !result.error).length, 1)
  assert.equal(simultaneous.find(result => result.error).error.code, 'PT409')
  console.log('Passed native owner MFA, versioned editor, hypothetical explanation, real delegated edit/archive/restore and immediate revocation.')
} finally {
  await browser.close()
  await Promise.allSettled([owner, member].map(person => admin.auth.admin.deleteUser(person.id)))
}
