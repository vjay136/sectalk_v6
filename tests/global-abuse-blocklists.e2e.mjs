import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { fixtureAuthenticator, verifyStaffPanel } from './workspace-admin-fixture.mjs'

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
const file = randomUUID()
const workspaceFile = randomUUID()
const bytes = Buffer.from('Harmless global policy attachment fixture ' + suffix + '\n')
const digest = createHash('sha256').update(bytes).digest('hex')
const domain = 'qa-' + suffix + '.example.invalid'
let workspace, chat, browser

function data(result) {
  if (result.error) throw result.error
  return result.data
}
function sql(statement) {
  return execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-At',
    '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres'], { input: statement, encoding: 'utf8', windowsHide: true }).trim()
}
async function account(role) {
  const handle = 'plt_' + role + '_' + suffix
  const email = handle + '@example.invalid'
  const { user } = data(await service.auth.admin.createUser({ email, password, email_confirm: true }))
  users.push(user.id)
  const client = createClient(origin.href, key, options)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: 'Blocklist QA ' + role }))
  return { id: user.id, handle, email, client }
}
async function request(path, client, type, body, extra = {}) {
  const { session } = data(await client.auth.getSession())
  return fetch(new URL(path, app), { method: 'POST',
    headers: { Authorization: 'Bearer ' + session.access_token, 'Content-Type': type, ...extra }, body })
}
const publish = client => request('/api/files/publish', client, 'application/json',
  JSON.stringify({ file, caption: 'Policy QA fixture', mime: 'text/plain' }))
const registerWebhook = client => request('/api/integrations/webhooks', client, 'application/json', JSON.stringify({
  action: 'create', workspace, label: 'Local domain policy test', topics: ['room.created'], destination: 'https://sub.' + domain + '/receiver',
}))
const rule = (panel, value) => panel.getByRole('listitem').filter({ has: panel.page().getByText(value, { exact: true }) })
async function add(panel, kind, input, canonical = input) {
  await panel.getByLabel('Indicator type', { exact: true }).selectOption(kind)
  await panel.getByLabel('Indicator', { exact: true }).fill(input)
  await panel.getByLabel('Duration in days', { exact: true }).fill('1')
  await panel.getByLabel('Case reference and reason', { exact: true }).fill('QA-240 synthetic and temporary rule')
  const response = panel.page().waitForResponse(result => result.url().endsWith('/rpc/st_v7_add_abuse_block'))
  await panel.getByRole('button', { name: 'Add block', exact: true }).click()
  const delivered = await response
  assert.ok(delivered.ok(), await delivered.text())
  await rule(panel, canonical).getByRole('button', { name: 'Release block', exact: true }).waitFor()
}
async function release(panel, indicator) {
  const current = rule(panel, indicator)
  await current.getByRole('button', { name: 'Release block', exact: true }).click()
  await current.getByLabel('Release reason', { exact: true }).fill('QA-241 fixture verified for release')
  await current.getByRole('button', { name: 'Confirm release', exact: true }).click()
  await current.waitFor({ state: 'detached' })
}

try {
  const [operator, uploader, recipient] = await Promise.all(['operator','uploader','recipient'].map(account))
  sql("insert into sectalk_private.st_v7_abuse_blocklist_operators values('" + operator.id + "'); "
    + "insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values('" + uploader.id
    + "','business','active',now()+interval '2 days');")
  assert.equal(data(await operator.client.rpc('st_v7_abuse_blocklist_access')), 'mfa')
  assert.equal((await operator.client.rpc('st_v7_abuse_blocks')).error?.code, '42501')
  assert.equal(data(await uploader.client.rpc('st_v7_abuse_blocklist_access')), 'none')
  assert.equal((await uploader.client.rpc('st_v7_add_abuse_block', {
    p_kind: 'domain', p_value: domain, p_reason: 'QA-240 unauthorized member', p_days: 1,
  })).error?.code, '42501')
  assert.ok((await uploader.client.rpc('st_v7_upload_digest_blocked', { p_hash: digest })).error)
  workspace = data(await uploader.client.rpc('st_v2_create_workspace', { p_name: 'Global abuse QA ' + suffix }))
  chat = data(await uploader.client.rpc('st_request', { p_handle: recipient.handle }))
  data(await recipient.client.rpc('st_respond', { p_chat: chat, p_accept: true }))

  await fixtureAuthenticator(uploader.client)
  const originalHook = await registerWebhook(uploader.client)
  assert.equal(originalHook.status, 201)
  assert.ok(data(await uploader.client.rpc('st_v6_workspace_link_create', {
    p_workspace: workspace, p_email: 'nobody@sub.' + domain, p_hours: 1,
  })).token)
  assert.equal(data(await uploader.client.rpc('st_v5_stage_file', {
    p_chat: chat, p_id: file, p_filename: 'fixture.txt', p_bytes: bytes.length,
  })), false)
  assert.equal((await request('/api/files/upload?file=' + file, uploader.client, 'text/plain', bytes)).status, 200)

  browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
  const page = await browser.newPage()
  await page.goto(app.href)
  await page.getByLabel('Email address', { exact: true }).fill(operator.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation', { name: 'SecTalk features' }).getByRole('button', { name: 'Safety', exact: true }).click()
  await page.getByRole('group', { name: 'Safety center sections' }).getByRole('button', { name: 'Global abuse blocklists', exact: true }).click()
  await verifyStaffPanel(page)
  const panel = page.getByRole('region', { name: 'Global abuse blocklists', exact: true })
  await panel.getByText('Add a block', { exact: true }).click()

  await add(panel, 'domain', domain.toUpperCase() + '.', domain)
  const deniedHook = await registerWebhook(uploader.client)
  assert.equal(deniedHook.status, 400)
  assert.match((await deniedHook.json()).error, /platform abuse policy/)
  assert.ok((await uploader.client.rpc('st_v6_workspace_link_create', {
    p_workspace: workspace, p_email: 'another@sub.' + domain, p_hours: 1,
  })).error)

  await add(panel, 'sha256', digest)
  const rejected = await publish(uploader.client)
  assert.equal(rejected.status, 422)
  assert.match((await rejected.json()).error, /platform policy/)
  assert.equal(sql("select message_id is null from public.st_v5_files where id='" + file + "';"), 't')
  const workspaceRejected = await request('/api/workspace-files?workspace=' + workspace + '&file=' + workspaceFile,
    uploader.client, 'text/plain', bytes, { 'x-sectalk-file-name': 'fixture.txt' })
  assert.equal(workspaceRejected.status, 422)
  assert.match((await workspaceRejected.json()).error, /platform policy/)
  assert.equal(sql("select count(*) from storage.objects where bucket_id='sectalk-workspace-files' and name='"
    + workspace + '/' + workspaceFile + "';"), '0')

  const rangeParts = [suffix.slice(0,4), suffix.slice(4)].map(part => Number.parseInt(part,16).toString(16))
  const documentationRange = '2001:db8:' + rangeParts.join(':') + '::/64'
  await add(panel, 'cidr', documentationRange)
  await release(panel, documentationRange)
  await release(panel, digest)
  const published = await publish(uploader.client)
  assert.equal(published.status, 200, await published.text())
  await release(panel, domain)
  assert.equal((await registerWebhook(uploader.client)).status, 201)
  assert.ok(data(await uploader.client.rpc('st_v6_workspace_link_create', {
    p_workspace: workspace, p_email: 'another@sub.' + domain, p_hours: 1,
  })).token)

  await panel.getByLabel('Block status', { exact: true }).selectOption('closed')
  await panel.getByRole('button', { name: 'Apply filters', exact: true }).click()
  await rule(panel, domain).getByText(/QA-241 fixture verified for release/).waitFor()
  assert.equal(sql("select count(*) from sectalk_private.st_v7_abuse_blocks where created_by='" + operator.id
    + "' and revoked_by='" + operator.id + "' and expires_at-created_at=interval '1 day';"), '3')
  assert.equal(sql("select count(*) from sectalk_private.st_v6_malware_hashes where sha256=decode('" + digest + "','hex');"), '0')
} finally {
  await browser?.close()
  await service.storage.from('sectalk-chat-files').remove([file])
  if (workspace) sql("delete from public.st_v2_workspaces where id='" + workspace + "';")
  if (chat) sql("delete from public.st_v5_files where id='" + file + "'; delete from public.st_messages where chat_id='" + chat
    + "'; delete from public.st_chats where id='" + chat + "';")
  for (const user of users) {
    sql("delete from sectalk_private.st_v7_abuse_blocks where created_by='" + user + "'; delete from auth.users where id='" + user + "';")
  }
}
console.log('Passed fresh TOTP operator UI, all three rule types, subdomain webhook and invitation enforcement, real attachment bytes, release and durable audit.')
