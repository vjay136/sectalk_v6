import assert from 'node:assert/strict'
import { createHmac, randomUUID } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { setTimeout } from 'node:timers/promises'
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

async function totp(secret) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bits = [...secret.replace(/=+$/, '')].map(char => alphabet.indexOf(char).toString(2).padStart(5, '0')).join('')
  const key = Buffer.from(bits.match(/.{8}/g).map(group => parseInt(group, 2)))
  const remaining = 30000 - Date.now() % 30000
  if (remaining < 3000) await setTimeout(remaining + 50)
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)))
  const value = createHmac('sha1', key).update(counter).digest()
  return String((value.readUInt32BE(value.at(-1) & 15) & 0x7fffffff) % 1000000).padStart(6, '0')
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
  const pageErrors = []
  ownerPage.on('pageerror', error => pageErrors.push(error.message))
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
  await ownerPage.unroute('**/api/ready')

  const analyticsTabs = ownerPage.getByRole('group', { name: 'Workspace overview tabs' })
  await button(analyticsTabs, 'Analytics').click()
  const analytics = ownerPage.getByRole('region', { name: 'Workspace analytics' })
  await analytics.getByRole('alert').filter({ hasText: 'Verify your authenticator' }).waitFor()
  assert.equal((await member.client.rpc('st_v6_workspace_analytics', { p_workspace: workspace })).error?.code, '42501')
  const room = randomUUID()
  data(await owner.client.rpc('st_v6_room_create', {
    p_id: room, p_workspace: workspace, p_name: 'Protected analytics test', p_kind: 'private', p_template: 'blank',
  }))
  assert.match(workspace, /^[0-9a-f-]{36}$/i)
  execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres'], {
    input: "insert into sectalk_private.st_v6_call_qos(day,event_key,reporter_key,mode,metric,bucket,workspace_id) " +
      "select (now() at time zone 'UTC')::date-1,sha256(convert_to('" + workspace +
      "'||n,'UTF8')),sha256(convert_to('qa-'||(n%5),'UTF8')),'meeting','join','connected','" + workspace +
      "' from generate_series(1,10) n;",
    windowsHide: true,
  })
  const ownerNav = ownerPage.getByRole('navigation', { name: 'SecTalk features' })
  await button(ownerNav, 'Profile').click()
  await button(ownerPage, 'Security').click()
  await button(ownerPage, 'Set up authenticator').click()
  const secret = (await ownerPage.locator('.mfa-setup code').textContent()).trim()
  await ownerPage.getByLabel('Authenticator code').fill(await totp(secret))
  await button(ownerPage, 'Verify authenticator').click()
  await ownerPage.getByRole('heading', { name: 'Recovery codes', exact: true }).waitFor()
  await button(ownerNav, 'Workspaces').click()
  await button(tabs, 'Overview').click()
  await button(analyticsTabs, 'Analytics').click()
  await analytics.getByText('100% connected across 10+ sampled joins', { exact: true }).waitFor()
  await analytics.getByText('1 classified Confidential or Restricted', { exact: true }).waitFor()
  await analytics.getByText('Activity totals are withheld for small groups.', { exact: true }).waitFor()
  assert.deepEqual(pageErrors, [])
  console.log('Passed workspace admin role, ready and degraded states, live seats, invite alerts and verified analytics.')
} finally {
  await browser.close()
}
