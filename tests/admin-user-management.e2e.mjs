import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { totpCode, verifyStaffPanel } from './workspace-admin-fixture.mjs'

const origin = new URL(process.env.SECTALK_STORAGE_TEST_URL)
const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
assert.equal(origin.origin, 'http://127.0.0.1:55321')
assert.equal(app.hostname, '127.0.0.1')
const key = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const service = createClient(origin.href, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const suffix = randomUUID().slice(0, 8)
const password = randomUUID() + '1!q'
const users = []
const workspaces = []
let avatarPath
let browser

function data(result) {
  if (result.error) throw result.error
  return result.data
}
function sql(statement) {
  return execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-At',
    '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres'], { input: statement, encoding: 'utf8', windowsHide: true }).trim()
}
async function account(role) {
  const handle = 'adm_' + role + '_' + suffix
  const name = 'QA ' + role + ' ' + suffix
  const email = handle + '@example.invalid'
  const { user } = data(await service.auth.admin.createUser({ email, password, email_confirm: true }))
  users.push(user.id)
  const client = createClient(origin.href, key, options)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: name }))
  return { id: user.id, client, name, handle, email }
}
async function createWorkspace(actor, name) {
  const id = data(await actor.client.rpc('st_v2_create_workspace', { p_name: name }))
  workspaces.push(id)
  return id
}
async function join(owner, member, id) {
  data(await owner.client.rpc('st_v2_invite', { p_workspace: id, p_handle: member.handle }))
  const invite = data(await member.client.from('st_v2_invites').select('id').eq('workspace_id', id).single())
  data(await member.client.rpc('st_v2_reply_invite', { p_invite: invite.id, p_accept: true }))
}
const nav = page => page.getByRole('navigation', { name: 'SecTalk features' })
async function signIn(page, actor) {
  await page.getByLabel('Email address', { exact: true }).fill(actor.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await nav(page).waitFor()
}
async function pageFor(actor) {
  const page = await browser.newPage()
  await page.goto(app.href)
  await signIn(page, actor)
  return page
}
function browserToken(page) {
  return page.evaluate(() => {
    const sessionKey = Object.keys(localStorage).find(name => /^sb-.+-auth-token$/.test(name))
    return JSON.parse(localStorage.getItem(sessionKey)).access_token
  })
}
async function browserClient(page) {
  const token = await browserToken(page)
  return createClient(origin.href, key, { ...options, global: { headers: { Authorization: 'Bearer ' + token } } })
}
async function workspacePeople(page, workspace) {
  await nav(page).getByRole('button', { name: 'Workspaces', exact: true }).click()
  const chooser = page.getByRole('combobox', { name: 'Active workspace' })
  await chooser.locator('option[value="' + workspace + '"]').waitFor({ state: 'attached' })
  if (await chooser.inputValue() !== workspace) await chooser.selectOption(workspace)
  await page.getByRole('group', { name: 'Workspace sections' }).getByRole('button', { name: 'People', exact: true }).click()
  return page.getByRole('region', { name: 'Manage workspace members' })
}
async function selectPerson(panel, member) {
  await panel.getByLabel('Name or handle', { exact: true }).fill(member.handle)
  await panel.getByRole('button', { name: 'Search members', exact: true }).click()
  await panel.getByRole('button', { name: member.name + ' (@' + member.handle + ')', exact: true }).click()
  await panel.getByRole('heading', { name: member.name, exact: true }).waitFor()
}
async function openAccountAdministration(page, secret) {
  await nav(page).getByRole('button', { name: 'Safety', exact: true }).click()
  await page.getByRole('group', { name: 'Safety center sections' }).getByRole('button', { name: 'Account administration', exact: true }).click()
  await verifyStaffPanel(page, secret)
  return page.getByRole('region', { name: 'Account administration' })
}
async function selectAccount(panel, actor) {
  await panel.getByLabel('Name or handle', { exact: true }).fill(actor.handle)
  await panel.getByRole('button', { name: 'Search accounts', exact: true }).click()
  await panel.getByRole('button', { name: actor.name + ' (@' + actor.handle + ')', exact: true }).click()
  await panel.getByRole('heading', { name: actor.name, exact: true }).waitFor()
}
async function confirm(panel, action, reason) {
  await panel.getByRole('button', { name: action, exact: true }).click()
  await panel.getByLabel('Case reference and reason', { exact: true }).fill(reason)
  const delivered = panel.page().waitForResponse(response => response.url().endsWith('/rpc/st_v7_account_admin_action'))
  await panel.getByRole('button', { name: 'Confirm ' + action.toLowerCase(), exact: true }).click()
  const response = await delivered
  assert.ok(response.ok(), await response.text())
}
const setMember = (client, workspace, member, action) => client.rpc('st_v2_set_member', {
  p_workspace: workspace, p_member: member.id, p_role: action,
})
const adminAction = (client, actor, action) => client.rpc('st_v7_account_admin_action', {
  p_user: actor.id, p_action: action, p_reason: 'CASE QA record and justification',
})

try {
  const [owner, member, operator, reviewer, staff, target] = await Promise.all(
    ['owner','member','operator','reviewer','staff','target'].map(account),
  )
  const alpha = await createWorkspace(owner, 'Admin Alpha ' + suffix)
  const beta = await createWorkspace(staff, 'Admin Beta ' + suffix)
  await join(owner, member, alpha)
  await join(staff, member, beta)
  sql("insert into sectalk_private.st_v7_account_operators(user_id,capability) values ('" + operator.id + "','operator'),('" + reviewer.id + "','reviewer');"
    + "insert into sectalk_private.staff(user_id) values ('" + staff.id + "');")
  assert.equal((await setMember(owner.client, alpha, member, 'suspend')).error?.code, '42501')
  assert.equal((await adminAction(operator.client, target, 'force_logout')).error?.code, '42501')
  assert.equal((await operator.client.rpc('st_v7_account_admin_directory')).error?.code, '42501')
  assert.equal(data(await staff.client.rpc('st_v7_account_operator_access')), 'none')
  assert.equal((await member.client.rpc('st_v7_workspace_people', { p_workspace: alpha })).error?.code, '42501')

  browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
  const ownerPage = await pageFor(owner)
  const people = await workspacePeople(ownerPage, alpha)
  await people.getByRole('button', { name: 'Verify to manage members', exact: true }).click()
  const ownerSecret = await verifyStaffPanel(people)
  await selectPerson(people, member)
  const verifiedOwner = await browserClient(ownerPage)
  assert.equal((await verifiedOwner.rpc('st_v7_workspace_people', { p_workspace: beta })).error?.code, '42501')
  assert.equal((await adminAction(verifiedOwner, member, 'force_logout')).error?.code, '42501')
  await people.getByLabel('Change access', { exact: true }).selectOption('admin')
  await people.getByRole('button', { name: 'Apply access change', exact: true }).click()
  await people.getByText(/ · admin · Active · Joined /).waitFor()
  await people.getByRole('button', { name: 'Suspend access', exact: true }).click()
  await people.getByText(/ · admin · Suspended · Joined /).waitFor()
  assert.deepEqual(data(await member.client.from('st_v2_workspaces').select('id')).map(row => row.id), [beta])
  await people.getByLabel('Workspace role', { exact: true }).selectOption('admin')
  await people.getByLabel('Workspace access', { exact: true }).selectOption('suspended')
  await selectPerson(people, member)
  await people.getByRole('button', { name: 'Restore access', exact: true }).click()
  await people.getByText('No members match these filters.', { exact: true }).waitFor()
  assert.deepEqual(data(await member.client.from('st_v2_workspaces').select('id')).map(row => row.id).sort(), [alpha, beta].sort())
  assert.equal(sql("select count(*) from public.st_v2_workspace_audit where workspace_id='" + alpha + "' and target='" + member.id
    + "' and event in ('member.admin','member.suspend','member.restore');"), '3')
  const memberPage = await pageFor(member)
  const adminPeople = await workspacePeople(memberPage, alpha)
  await adminPeople.getByRole('button', { name: 'Verify to manage members', exact: true }).click()
  await verifyStaffPanel(adminPeople)
  await selectPerson(adminPeople, owner)
  assert.equal(await adminPeople.getByRole('button', { name: 'Suspend access', exact: true }).count(), 0)
  assert.ok((await setMember(await browserClient(memberPage), alpha, owner, 'suspend')).error)
  sql("update auth.mfa_amr_claims set updated_at=now()-interval '6 minutes' where authentication_method='totp' and session_id in (select id from auth.sessions where user_id='" + owner.id + "');")
  assert.equal((await setMember(verifiedOwner, alpha, member, 'suspend')).error?.code, '42501')
  await people.getByLabel('Authenticator code', { exact: true }).waitFor({ timeout: 20000 })
  await verifyStaffPanel(people, ownerSecret)
  await people.getByRole('button', { name: 'Search members', exact: true }).waitFor()

  const targetPage = await pageFor(target)
  await nav(targetPage).getByRole('button', { name: 'Profile', exact: true }).click()
  await targetPage.getByRole('button', { name: 'Security', exact: true }).click()
  await targetPage.getByRole('button', { name: 'Set up authenticator', exact: true }).click()
  const targetSecret = (await targetPage.locator('.mfa-setup code').textContent()).trim()
  await targetPage.getByLabel('Authenticator code', { exact: true }).fill(await totpCode(targetSecret))
  await targetPage.getByRole('button', { name: 'Verify authenticator', exact: true }).click()
  await targetPage.getByRole('heading', { name: 'Recovery codes', exact: true }).waitFor()
  const verifiedTarget = await browserClient(targetPage)
  const targetSecurity = targetPage.getByRole('region', { name: 'Account security changes' })
  const operatorPage = await pageFor(operator)
  const accountPanel = await openAccountAdministration(operatorPage)
  await accountPanel.getByLabel('Account status', { exact: true }).selectOption('restricted')
  await accountPanel.getByLabel('Name or handle', { exact: true }).fill(target.name)
  await accountPanel.getByRole('button', { name: 'Search accounts', exact: true }).click()
  await accountPanel.getByText('No accounts match these filters.', { exact: true }).waitFor()
  await accountPanel.getByLabel('Account status', { exact: true }).selectOption('active')
  await selectAccount(accountPanel, staff)
  await accountPanel.getByText('Account-wide actions are unavailable for this profile.', { exact: true }).waitFor()
  const verifiedOperator = await browserClient(operatorPage)
  assert.equal((await adminAction(verifiedOperator, staff, 'force_logout')).error?.code, '42501')
  await selectAccount(accountPanel, target)
  await confirm(accountPanel, 'Request authenticator reset', 'QA-121 customer requested recovery')
  await targetSecurity.getByText('An account operator requested this reset.', { exact: false }).waitFor()
  await targetSecurity.getByRole('button', { name: 'Cancel security request', exact: true }).click()
  await targetSecurity.getByText('Security request cancelled.', { exact: true }).waitFor()
  await selectAccount(accountPanel, staff)
  await selectAccount(accountPanel, target)
  await confirm(accountPanel, 'Request authenticator reset', 'QA-122 new customer recovery request')
  await accountPanel.getByText('Authenticator reset requested.', { exact: true }).waitFor()

  const reviewerPage = await pageFor(reviewer)
  const reviewerPanel = await openAccountAdministration(reviewerPage)
  await selectAccount(reviewerPanel, target)
  const verifiedReviewer = await browserClient(reviewerPage)
  assert.equal(await reviewerPanel.getByRole('button', { name: 'End all sessions', exact: true }).count(), 0)
  assert.equal((await adminAction(verifiedReviewer, target, 'reset_completed')).error?.code, '22023')
  assert.equal((await adminAction(verifiedReviewer, target, 'force_logout')).error?.code, '42501')
  assert.equal((await adminAction(verifiedOperator, target, 'reset_completed')).error?.code, '42501')
  assert.equal(sql("select count(*) from auth.mfa_factors where user_id='" + target.id + "' and status='verified';"), '1')
  assert.equal(sql("select ready_at-requested_at=interval '24 hours' from sectalk_private.st_v7_account_security_changes where user_id='" + target.id + "';"), 't')
  sql("update sectalk_private.st_v7_account_security_changes set ready_at=now()-interval '1 minute' where user_id='" + target.id + "';")
  assert.equal((await verifiedTarget.rpc('st_v7_account_security_change', { p_action: 'continue', p_kind: 'authenticator' })).error?.code, '22023')
  await selectAccount(reviewerPanel, staff)
  await selectAccount(reviewerPanel, target)
  await confirm(reviewerPanel, 'Approve authenticator reset', 'QA-122 independent identity review')
  await reviewerPanel.getByText('Authenticator reset approved.', { exact: true }).waitFor()
  await targetPage.getByLabel('Email address', { exact: true }).waitFor({ timeout: 30000 })
  assert.equal(sql("select count(*) from auth.mfa_factors where user_id='" + target.id + "';"), '0')
  assert.equal(sql("select count(*) from auth.sessions where user_id='" + target.id + "';"), '0')
  assert.equal((await adminAction(verifiedReviewer, target, 'reset_completed')).error?.code, '22023')

  await signIn(targetPage, target)
  const otherDevice = await pageFor(target)
  const staleToken = await browserToken(otherDevice)
  const stale = await browserClient(otherDevice)
  assert.equal(data(await stale.auth.getUser(staleToken)).user.id, target.id)
  const photo = new Uint8Array([255,216,255,217]).buffer
  avatarPath = target.id + '.jpg'
  data(await stale.storage.from('sectalk-avatars').upload(avatarPath, photo, { contentType: 'image/jpeg' }))
  data(await stale.storage.from('sectalk-avatars').download(avatarPath))
  await selectAccount(accountPanel, staff)
  await selectAccount(accountPanel, target)
  await confirm(accountPanel, 'End all sessions', 'QA-123 customer requested all sessions end')
  await accountPanel.getByText('All sessions ended.', { exact: true }).waitFor()
  await Promise.all([targetPage, otherDevice].map(page => page.getByLabel('Email address', { exact: true }).waitFor({ timeout: 30000 })))
  assert.equal(data(await stale.rpc('st_v7_current_session_valid')), false)
  assert.ok((await stale.auth.getUser(staleToken)).error)
  assert.ok((await stale.from('st_profiles').select('id').eq('id', target.id)).error)
  assert.ok((await stale.storage.from('sectalk-avatars').download(avatarPath)).error)
  assert.equal(sql("select count(*) from auth.sessions where user_id='" + target.id + "';"), '0')
  assert.equal(sql("select count(*) from sectalk_private.st_v7_account_admin_audit where target='" + target.id
    + "' and action in ('force_logout','reset_requested','reset_completed');"), '4')
  assert.equal(sql("select count(distinct actor) from sectalk_private.st_v7_account_admin_audit where target='" + target.id
    + "' and action in ('reset_requested','reset_completed');"), '2')
  assert.equal(sql("select count(*) from sectalk_private.st_v7_account_security_events where user_id='" + target.id
    + "' and (kind='sessions' or (kind='authenticator' and action='cancelled'));"), '2')
  await signIn(targetPage, target)
  data(await (await browserClient(targetPage)).storage.from('sectalk-avatars').download(avatarPath))
  console.log('Passed workspace directory, fresh TOTP, role and suspension isolation, account operator and reviewer controls, cancellable delayed reset, audit, and two-device force logout.')
} finally {
  await browser?.close()
  if (avatarPath) data(await service.storage.from('sectalk-avatars').remove([avatarPath]))
  for (const workspace of workspaces) sql("delete from public.st_v2_workspaces where id='" + workspace + "';")
  for (const user of users) {
    sql("delete from sectalk_private.st_v7_account_admin_audit where actor='" + user + "' or target='" + user
      + "'; delete from sectalk_private.staff where user_id='" + user + "'; delete from auth.users where id='" + user + "';")
  }
}
