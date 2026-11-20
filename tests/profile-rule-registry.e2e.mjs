import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const local = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.origin, 'http://127.0.0.1:3519')
assert.equal(local.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const service = createClient(local.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const suffix = randomUUID().slice(0, 8)
const password = randomUUID() + '1!Q'
const roster = []
let workspace
let browser

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}
function sql(statement) {
  return execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-At', '-v', 'ON_ERROR_STOP=1',
    '-U', 'postgres', '-d', 'postgres'], { input: statement, encoding: 'utf8', windowsHide: true }).trim()
}
async function account(handle, name) {
  const email = handle + '@example.invalid'
  const { user } = data(await service.auth.admin.createUser({ email, password, email_confirm: true }))
  assert.match(user.id, /^[a-f0-9-]{36}$/)
  roster.push(user.id)
  const client = createClient(local.origin, process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY, options)
  const { session } = data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: name }))
  return { id: user.id, handle, name, email, client, token: session.access_token }
}
const evaluate = (actor, fields = {}) => fetch(new URL('/api/workspaces/rule-registry', app), {
  method: 'POST', headers: { 'Content-Type': 'application/json', ...(actor ? { Authorization: 'Bearer ' + actor.token } : {}) },
  body: JSON.stringify({ workspace, ...fields }), signal: AbortSignal.timeout(8000),
})

try {
  const [owner, manager, member] = await Promise.all([
    account('rules_casey_' + suffix, 'Casey Reed'),
    account('rules_casey_' + suffix + 'x', 'Independent display'),
    account('rules_other_' + suffix, 'Unrelated member'),
  ])
  workspace = data(await owner.client.rpc('st_v2_create_workspace', { p_name: 'Rule rollout ' + suffix }))
  assert.match(workspace, /^[a-f0-9-]{36}$/)
  for (const person of [manager, member]) {
    data(await owner.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: person.handle }))
    const invite = data(await person.client.from('st_v2_invites').select('id').eq('workspace_id', workspace).single())
    data(await person.client.rpc('st_v2_reply_invite', { p_invite: invite.id, p_accept: true }))
  }
  sql("update public.st_v2_members set role='admin' where workspace_id='" + workspace + "' and user_id='" + manager.id + "';")
  data(await owner.client.rpc('st_v6_set_impersonation_watch', { p_workspace: workspace, p_member: owner.id, p_tier: 'executive' }))
  assert.equal((await evaluate(null)).status, 401)
  assert.equal((await evaluate(owner)).status, 409)
  assert.equal((await evaluate(manager)).status, 403)
  assert.equal((await evaluate(member)).status, 403)

  browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
  async function open(person) {
    const page = await browser.newPage({ locale: 'en-US' })
    await page.goto(app.href)
    await page.getByLabel('Email address', { exact: true }).fill(person.email)
    await page.getByLabel('Password', { exact: true }).fill(password)
    await page.locator('button.submit-auth').click()
    await page.getByRole('navigation', { name: 'SecTalk features' }).getByRole('button', { name: 'Workspaces', exact: true }).click()
    return page
  }
  const [a, b] = await Promise.all([open(owner), open(manager)])
  const tab = (page, name) => page.getByRole('group', { name: 'Workspace sections', exact: true })
    .getByRole('button', { name, exact: true })
  const registry = page => page.getByRole('region', { name: 'Impersonation rule registry', exact: true })
  await tab(a, 'AI settings').click()
  await tab(b, 'Impersonation watch').click()
  const watch = b.getByRole('region', { name: 'Impersonation watch', exact: true })
  const advisory = watch.getByText('Similar-looking username', { exact: true })
  const noSignals = watch.getByText('No similar profiles found in the active workspace roster.', { exact: true })
  await advisory.waitFor()

  const controls = registry(a)
  const stage = 'Stage Profile rules v2 as shadow'
  const promote = 'Promote evaluated shadow'
  await controls.getByRole('button', { name: stage, exact: true }).click()
  await controls.getByText('Shadow version staged.', { exact: true }).waitFor()
  assert.ok(await controls.getByRole('button', { name: promote, exact: true }).isDisabled())
  await watch.getByRole('button', { name: 'Refresh watch list', exact: true }).click()
  await advisory.waitFor()
  assert.equal(data(await manager.client.rpc('st_v7_workspace_active_profile_rules', { p_workspace: workspace })), 'profile-rules-v1')

  const response = a.waitForResponse(item => item.url().endsWith('/api/workspaces/rule-registry'))
  await controls.getByRole('button', { name: 'Run synthetic shadow evaluation', exact: true }).click()
  const result = await response
  assert.equal(result.status(), 200)
  assert.deepEqual(result.request().postDataJSON(), { workspace })
  assert.equal(result.headers()['cache-control'], 'private, no-store')
  const evaluation = await evaluate(owner)
  assert.equal(evaluation.status, 200)
  const summary = await evaluation.json()
  assert.deepEqual(summary, { corpus: 'synthetic-profile-pairs-v1', cases: 8, disagreements: 2,
    active: { tp: 4, fp: 2, tn: 2, fn: 0 }, shadow: { tp: 3, fp: 1, tn: 3, fn: 1 } })
  await controls.getByText('Synthetic evaluation recorded.', { exact: true }).waitFor()
  await controls.getByRole('table', { name: 'Synthetic evaluation counts', exact: true }).waitFor()

  await tab(b, 'AI settings').click()
  await registry(b).getByRole('heading', { name: 'Latest synthetic evaluation', exact: true }).waitFor()
  assert.equal(await registry(b).getByRole('button', { name: promote, exact: true }).count(), 0)
  await controls.getByRole('button', { name: promote, exact: true }).click()
  await controls.getByText('The evaluated version is now active.', { exact: true }).waitFor()
  await tab(b, 'Impersonation watch').click()
  await noSignals.waitFor()
  assert.equal(await advisory.count(), 0)

  await controls.getByRole('button', { name: 'Roll back to prior version', exact: true }).click()
  await controls.getByText('The previous rule version is active again.', { exact: true }).waitFor()
  await watch.getByRole('button', { name: 'Refresh watch list', exact: true }).click()
  await advisory.waitFor()
  await controls.getByText(/Rolled back to profile-rules-v1/).waitFor()
  console.log('PASS: actual browser classifier remained active in shadow, promoted the evaluated challenger, and restored the former runtime on rollback')
} finally {
  await browser?.close()
  if (workspace) sql("delete from public.st_v2_workspaces where id='" + workspace + "';")
  await Promise.allSettled(roster.map(id => service.auth.admin.deleteUser(id)))
}
