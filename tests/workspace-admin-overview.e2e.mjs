import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const suffix = randomUUID().slice(0, 8)
const password = randomUUID() + '1!Q'

function data(result) {
  assert.equal(result.error, null, result.error?.message)
  return result.data
}

async function account(role) {
  const handle = 'overview_' + role + '_' + suffix
  const email = handle + '@example.org'
  data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(supabase.origin, publicKey, options)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: 'Overview ' + role }))
  return { client, handle, email }
}

const [owner, member] = await Promise.all([account('owner'), account('peer')])
const workspace = data(await owner.client.rpc('st_v2_create_workspace', { p_name: 'Overview ' + suffix }))
data(await owner.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: member.handle }))
const invite = data(await member.client.from('st_v2_invites').select('id').eq('workspace_id', workspace).single())
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
try {
  const button = (scope, name) => scope.getByRole('button', { name, exact: true })
  async function open(person) {
    const page = await browser.newPage()
    await page.goto(new URL('/#account', app).href)
    await page.getByLabel('Email address', { exact: true }).fill(person.email)
    await page.getByLabel('Password', { exact: true }).fill(password)
    await page.locator('button.submit-auth').click()
    await button(page.getByRole('navigation', { name: 'SecTalk features' }), 'Workspaces').click()
    return page
  }
  const ownerPage = await open(owner)
  const tabs = ownerPage.getByRole('group', { name: 'Workspace sections' })
  await button(tabs, 'Overview').click()
  const overview = ownerPage.getByRole('region', { name: 'Workspace overview' })
  await overview.getByText('Ready', { exact: true }).waitFor()
  await overview.getByText('1 of 5', { exact: true }).waitFor()
  await overview.getByText('1 pending invitation', { exact: true }).waitFor()
  await overview.getByText('Activity totals are withheld for small groups.', { exact: true }).waitFor()

  data(await member.client.rpc('st_v2_reply_invite', { p_invite: invite.id, p_accept: true }))
  const memberPage = await open(member)
  const memberTabs = memberPage.getByRole('group', { name: 'Workspace sections' })
  await memberTabs.waitFor()
  assert.equal(await button(memberTabs, 'Overview').count(), 0)
  assert.equal((await member.client.rpc('st_v6_workspace_admin_overview', { p_workspace: workspace })).error?.code, '42501')

  data(await owner.client.rpc('st_v6_workspace_link_create', {
    p_workspace: workspace, p_email: 'overview-test-' + suffix + '@example.org', p_hours: 1,
  }))
  await button(overview, 'Refresh overview').click()
  await overview.getByText('2 of 5', { exact: true }).waitFor()
  await overview.getByText('1 invitation link expires within 24 hours', { exact: true }).waitFor()
  await ownerPage.route('**/api/ready', route => route.fulfill({ status: 503, json: { status: 'not_ready' } }))
  await button(overview, 'Refresh overview').click()
  await overview.getByText('Service readiness check failed', { exact: true }).waitFor()
  await overview.getByText('2 of 5', { exact: true }).waitFor()
  console.log('Passed workspace admin role, ready and degraded states, live seat counts and invite alerts.')
} finally {
  await browser.close()
}
