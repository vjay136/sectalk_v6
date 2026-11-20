import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash, createHmac, randomUUID } from 'node:crypto'
import { setTimeout } from 'node:timers/promises'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const service = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const run = randomUUID().slice(0, 8)
const password = randomUUID() + '1!Q'
const accounts = []
const workspaces = []
let browser

function data(result) {
  if (result.error) throw result.error
  return result.data
}
function sql(statement) {
  return execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-At', '-v', 'ON_ERROR_STOP=1',
    '-U', 'postgres', '-d', 'postgres'], { input: statement, encoding: 'utf8', windowsHide: true }).trim()
}
async function account(role) {
  const handle = 'feat_' + role + '_' + run
  const email = handle + '@example.invalid'
  const { user } = data(await service.auth.admin.createUser({ email, password, email_confirm: true }))
  accounts.push(user.id)
  const client = createClient(supabase.origin, publicKey, options)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: 'Feature QA ' + role }))
  return { id: user.id, handle, email, client }
}
async function totp(secret) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bits = [...secret.replace(/=+$/, '').toUpperCase()].map(character =>
    alphabet.indexOf(character).toString(2).padStart(5, '0')).join('')
  const bytes = Buffer.from(bits.match(/.{8}/g).map(part => Number.parseInt(part, 2)))
  const remaining = 30000 - Date.now() % 30000
  if (remaining < 3000) await setTimeout(remaining + 50)
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)))
  const mac = createHmac('sha1', bytes).update(counter).digest()
  return String((mac.readUInt32BE(mac.at(-1) & 15) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}
const nav = page => page.getByRole('navigation', { name: 'SecTalk features' })
const workspaceTabs = page => page.getByRole('group', { name: 'Workspace sections' })
const panel = page => page.getByRole('region', { name: 'Workspace features' })
const feature = (page, title) => panel(page).getByRole('article').filter({ has: page.getByRole('heading', { name: title, exact: true }) })
const pause = (client, workspace, name, paused) => client.rpc('st_v6_set_tenant_feature_pause', {
  p_workspace: workspace, p_feature: name, p_paused: paused,
})
const available = (client, workspace, name) => client.rpc('st_v6_feature_available', { p_workspace: workspace, p_feature: name })
const task = (actor, room, title) => actor.client.rpc('st_v6_task_create', {
  p_id: randomUUID(), p_room: room, p_chat: null, p_title: title,
})
const date = new Date(Date.now() + 86400000)
date.setUTCSeconds(0, 0)
const end = new Date(date.getTime() + 3600000)
const schedule = (client, workspace, title) => client.rpc('st_v6_schedule_series', {
  p_workspace: workspace, p_id: randomUUID(), p_title: title, p_agenda: '', p_start: date.toISOString(),
  p_end: end.toISOString(), p_frequency: 'daily', p_count: 3, p_zone: 'UTC',
})
async function login(actor) {
  const page = await browser.newPage({ timezoneId: 'UTC' })
  await page.goto(app.href)
  await page.getByLabel('Email address', { exact: true }).fill(actor.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  return page
}
async function openFeatures(page) {
  await nav(page).getByRole('button', { name: 'Workspaces', exact: true }).click()
  await workspaceTabs(page).getByRole('button', { name: 'Features', exact: true }).click()
  await panel(page).getByRole('heading', { name: 'Room task creation', exact: true }).waitFor()
}
async function verify(page) {
  await panel(page).getByRole('button', { name: 'Verify to change features' }).click()
  await panel(page).getByRole('button', { name: 'Set up authenticator' }).click()
  const secret = (await panel(page).locator('.mfa-setup code').textContent()).trim()
  await panel(page).getByLabel('Authenticator code', { exact: true }).fill(await totp(secret))
  await panel(page).getByRole('button', { name: 'Verify access', exact: true }).click()
  await feature(page, 'Room task creation').getByRole('button', { name: /^(Pause feature|Restore inherited access)$/ }).waitFor()
  const token = await page.evaluate(() => {
    const key = Object.keys(localStorage).find(name => /^sb-.+-auth-token$/.test(name))
    return JSON.parse(localStorage.getItem(key)).access_token
  })
  return createClient(supabase.origin, publicKey, { ...options, global: { headers: { Authorization: 'Bearer ' + token } } })
}
const apiRead = token => fetch(new URL('/api/v1/workspace', app), { headers: { Authorization: 'Bearer ' + token } })
async function roomTasks(page, name) {
  await nav(page).getByRole('button', { name: 'Rooms', exact: true }).click()
  await page.getByRole('button', { name: new RegExp(name) }).click()
  await page.getByRole('group', { name: 'Room tabs' }).getByRole('button', { name: 'Tasks', exact: true }).click()
}

try {
  const owner = await account('owner')
  const admin = await account('admin')
  const second = await account('second')
  const member = await account('member')
  sql(`insert into public.st_v2_subscriptions(user_id,plan,status,period_end)
    values('${owner.id}','business','active',now()+interval '10 days');`)
  const alpha = data(await owner.client.rpc('st_v2_create_workspace', { p_name: 'Alpha features ' + run }))
  workspaces.push(alpha)
  const beta = data(await second.client.rpc('st_v2_create_workspace', { p_name: 'Beta features ' + run }))
  workspaces.push(beta)
  for (const actor of [admin, member]) {
    data(await owner.client.rpc('st_v2_invite', { p_workspace: alpha, p_handle: actor.handle }))
    const invite = data(await actor.client.from('st_v2_invites').select('id').eq('workspace_id', alpha).single())
    data(await actor.client.rpc('st_v2_reply_invite', { p_invite: invite.id, p_accept: true }))
  }
  sql(`update public.st_v2_members set role='admin' where workspace_id='${alpha}' and user_id='${admin.id}';`)
  const alphaRoom = randomUUID()
  const betaRoom = randomUUID()
  const nameA = 'Alpha task room ' + run
  const nameB = 'Beta task room ' + run
  for (const [actor, workspace, room, name] of [[owner, alpha, alphaRoom, nameA], [second, beta, betaRoom, nameB]]) {
    data(await actor.client.rpc('st_v6_room_create', { p_workspace: workspace, p_id: room, p_name: name, p_kind: 'public', p_template: 'blank' }))
  }
  assert.equal(data(await member.client.rpc('st_v6_tenant_feature_state', { p_workspace: alpha })), null)
  assert.ok((await pause(owner.client, alpha, 'task_creation', true)).error)
  assert.equal(data(await available(second.client, beta, 'integration_api')), false)
  assert.equal(data(await available(owner.client, alpha, 'integration_api')), true)

  browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
  const adminPage = await login(admin)
  await openFeatures(adminPage)
  const verifiedAdmin = await verify(adminPage)
  assert.ok((await pause(verifiedAdmin, beta, 'task_creation', true)).error)
  assert.ok((await pause(verifiedAdmin, alpha, 'integration_api', true)).error)
  assert.equal(await feature(adminPage, 'Workspace API').getByRole('button', { name: 'Pause feature' }).count(), 0)
  await feature(adminPage, 'Room task creation').getByRole('button', { name: 'Pause feature' }).click()
  await feature(adminPage, 'Room task creation').getByText('Paused by a workspace administrator.').waitFor()
  await feature(adminPage, 'Recurring meetings').getByRole('button', { name: 'Pause feature' }).click()
  await feature(adminPage, 'Recurring meetings').getByText('Paused by a workspace administrator.').waitFor()
  assert.ok((await task(owner, alphaRoom, 'Blocked tenant task')).error)
  assert.ok((await schedule(owner.client, alpha, 'Blocked tenant series')).error)
  assert.equal(data(await available(owner.client, null, 'task_creation')), true)

  const betaPage = await login(second)
  await openFeatures(betaPage)
  await feature(betaPage, 'Workspace API').getByText('Requires a Team or Enterprise workspace plan.').waitFor()
  await verify(betaPage)
  await feature(betaPage, 'Workspace API').getByRole('button', { name: 'Pause feature' }).click()
  await feature(betaPage, 'Workspace API').getByRole('button', { name: 'Restore inherited access' }).click()
  await feature(betaPage, 'Workspace API').getByText('Unavailable · Release default', { exact: true }).waitFor()
  const betaTask = 'Created in the second workspace'
  await roomTasks(betaPage, nameB)
  await betaPage.getByText('Create a task', { exact: true }).click()
  await betaPage.getByLabel('Task title', { exact: true }).fill(betaTask)
  await betaPage.getByRole('button', { name: 'Create task', exact: true }).click()
  await betaPage.getByRole('heading', { name: betaTask, exact: true }).waitFor()
  data(await schedule(second.client, beta, 'Allowed series ' + run))

  const ownerPage = await login(owner)
  await openFeatures(ownerPage)
  const verifiedOwner = await verify(ownerPage)
  await feature(ownerPage, 'Room task creation').getByRole('button', { name: 'Restore inherited access' }).click()
  await feature(ownerPage, 'Room task creation').getByText('Available · Release default', { exact: true }).waitFor()
  await feature(ownerPage, 'Recurring meetings').getByRole('button', { name: 'Restore inherited access' }).click()
  await feature(ownerPage, 'Recurring meetings').getByText('Available · Release default', { exact: true }).waitFor()
  data(await task(owner, alphaRoom, 'Restored task'))
  data(await schedule(verifiedOwner, alpha, 'Restored series ' + run))

  await workspaceTabs(ownerPage).getByRole('button', { name: 'Integrations', exact: true }).click()
  const keys = ownerPage.getByRole('region', { name: 'Workspace integrations' })
  await keys.getByLabel('Label', { exact: true }).fill('Flag fixture API key')
  await keys.getByRole('button', { name: 'Create API key', exact: true }).click()
  const credential = keys.getByText(/^sectalk_api_/)
  await credential.waitFor()
  const apiKey = await credential.textContent()
  const read = await apiRead(apiKey)
  assert.equal(read.status, 200)
  assert.equal((await read.json()).data.id, alpha)
  await openFeatures(ownerPage)
  await feature(ownerPage, 'Workspace API').getByRole('button', { name: 'Pause feature' }).click()
  await feature(ownerPage, 'Workspace API').getByText('Paused by a workspace administrator.').waitFor()
  assert.equal((await apiRead(apiKey)).status, 403)
  assert.equal((await verifiedOwner.rpc('st_v6_create_integration_key', {
    p_workspace: alpha, p_label: 'Blocked issuance', p_prefix: 'flagcheck1', p_digest: 'c'.repeat(64),
    p_scopes: ['workspace:read'], p_lifetime_days: 30,
  })).error?.code, '42501')
  await workspaceTabs(ownerPage).getByRole('button', { name: 'Integrations', exact: true }).click()
  await keys.getByText('Workspace API access is unavailable under the current feature settings.').waitFor()
  assert.equal(await keys.getByRole('button', { name: 'Create API key', exact: true }).count(), 0)
  await keys.getByRole('button', { name: 'Revoke API key', exact: true }).waitFor()
  await openFeatures(ownerPage)
  await feature(ownerPage, 'Workspace API').getByRole('button', { name: 'Restore inherited access' }).click()
  await feature(ownerPage, 'Workspace API').getByText('Available · Release default', { exact: true }).waitFor()
  assert.equal((await apiRead(apiKey)).status, 200)
  sql(`update public.st_v2_subscriptions set plan='basic' where user_id='${owner.id}';`)
  assert.equal((await apiRead(apiKey)).status, 403)
  sql(`update public.st_v2_subscriptions set plan='business' where user_id='${owner.id}';`)
  assert.equal((await apiRead(apiKey)).status, 200)

  sql(`begin;
    update sectalk_private.st_v6_flag_rules set killed=true where scope='global' and feature='integration_api';
    do $$ begin
      if sectalk_private.st_v6_feature_allowed('integration_api','${owner.id}','${alpha}') then
        raise exception 'Global emergency stop did not override restored tenant access';
      end if;
      begin
        perform public.st_v6_integration_read('${createHash('sha256').update(apiKey).digest('hex')}','workspace',null,1);
        raise exception 'API read ignored the global emergency stop';
      exception when insufficient_privilege then null; end;
    end $$;
    rollback;`)
  assert.equal((await apiRead(apiKey)).status, 200)
  assert.equal(sql(`select count(*) from public.st_v2_workspace_audit where workspace_id='${alpha}'
    and event in ('workspace.feature.task_creation.paused','workspace.feature.task_creation.restored',
      'workspace.feature.integration_api.paused','workspace.feature.integration_api.restored');`), '4')
  console.log('Tenant feature controls passed in Edge and SQL with two tenants, MFA roles, live tasks, series, team tier, API issuance and a global emergency stop.')
} finally {
  await browser?.close()
  for (const workspace of workspaces) sql(`delete from public.st_v2_workspaces where id='${workspace}';`)
  for (const actor of accounts) data(await service.auth.admin.deleteUser(actor))
}
