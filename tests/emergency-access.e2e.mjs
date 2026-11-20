import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHmac, randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const auth = { persistSession: false, autoRefreshToken: false }
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const admin = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, { auth })
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const password = randomUUID() + '1!Q'
const suffix = randomUUID().slice(0, 8)
const workspaceName = 'Emergency review ' + suffix
const source = 'Confidential case fixture ' + suffix
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
const users = []
let workspace
let operatorId

function value(result) {
  assert.equal(result.error, null, result.error?.message)
  return result.data
}

function sql(statement) {
  execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1',
    '-U', 'postgres', '-d', 'postgres'], { input: statement, windowsHide: true })
}

async function account(label) {
  const handle = 'eg_' + label + '_' + suffix
  const email = handle + '@example.invalid'
  const { user } = value(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  users.push(user.id)
  const client = createClient(supabase.origin, publicKey, { auth })
  value(await client.auth.signInWithPassword({ email, password }))
  value(await client.rpc('st_save_profile', { p_handle: handle, p_name: 'Emergency ' + label }))
  return { id: user.id, handle, email, client }
}

function totp(secret) {
  const digits = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bits = [...secret.toUpperCase().replace(/=+$/, '')]
    .map(character => digits.indexOf(character).toString(2).padStart(5, '0')).join('')
  const key = Buffer.from(bits.match(/.{8}/g).map(group => parseInt(group, 2)))
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)))
  const hash = createHmac('sha1', key).update(counter).digest()
  return String((hash.readUInt32BE(hash.at(-1) & 15) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}

const button = (scope, name) => scope.getByRole('button', { name, exact: true })
const nav = page => page.getByRole('navigation', { name: 'SecTalk features' })

async function open(person) {
  const page = await browser.newPage()
  await page.goto(new URL('/#account', app).href, { waitUntil: 'domcontentloaded', timeout: 90000 })
  await page.getByLabel('Email address', { exact: true }).fill(person.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  return page
}

async function enroll(page, completion) {
  await button(page, 'Set up authenticator').click()
  const secret = (await page.locator('.mfa-setup code').textContent()).trim()
  await page.getByLabel('Authenticator code', { exact: true }).fill(totp(secret))
  await button(page, completion).click()
}

try {
  const [owner, reporter, operator] = await Promise.all([account('owner'), account('peer'), account('ops')])
  operatorId = operator.id
  workspace = value(await owner.client.rpc('st_v2_create_workspace', { p_name: workspaceName }))
  value(await owner.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: reporter.handle }))
  const invite = value(await reporter.client.from('st_v2_invites').select('id').eq('workspace_id', workspace).single())
  value(await reporter.client.rpc('st_v2_reply_invite', { p_invite: invite.id, p_accept: true }))
  const room = randomUUID()
  const post = randomUUID()
  value(await owner.client.rpc('st_v6_room_create', { p_id: room, p_workspace: workspace, p_name: 'Emergency fixture room', p_kind: 'public', p_template: 'blank' }))
  value(await reporter.client.rpc('st_v6_room_membership', { p_room: room, p_action: 'join' }))
  value(await owner.client.rpc('st_v6_room_post', { p_room: room, p_id: post, p_body: source }))
  const report = value(await reporter.client.rpc('st_v6_submit_room_report', {
    p_room: room, p_post: post, p_category: 'threat', p_details: 'Private report notes remain private.', p_share: true,
  }))
  sql(`insert into sectalk_private.staff(user_id) values('${operator.id}');
    insert into sectalk_private.st_v6_tenant_operators(account_id) values('${operator.id}');`)
  assert.equal((await reporter.client.rpc('st_v6_break_glass_list', { p_workspace: workspace })).error?.code, '42501')
  assert.equal((await operator.client.rpc('st_v6_request_break_glass', {
    p_report: report, p_justification: 'Unauthenticated assurance should not be enough.',
  })).error?.code, '42501')
  assert.deepEqual(value(await operator.client.from('st_v6_room_posts').select('body').eq('id', post)), [])

  const [opsPage, ownerPage] = await Promise.all([open(operator), open(owner)])
  await button(nav(ownerPage), 'Safety').click()
  const readyNotices = ownerPage.waitForResponse(response => response.ok() && response.url().endsWith('/rpc/st_v6_my_emergency_notices'))
  await button(ownerPage, 'Account notices').click()
  await readyNotices
  await button(nav(opsPage), 'Safety').click()
  await button(opsPage, 'Tenant operations').click()
  await enroll(opsPage, 'Verify access')
  await button(opsPage, 'Emergency access').click()
  const ops = opsPage.getByRole('region', { name: 'Emergency access', exact: true })
  const request = opsPage.waitForResponse(response => response.ok() && response.url().endsWith('/rpc/st_v6_request_break_glass'))
  await ops.getByLabel('Workspace room report ID').fill(report)
  await ops.getByLabel('Why is emergency access needed?').fill('Review an urgent safety escalation from this workspace.')
  await button(ops, 'Request emergency access').click()
  const requested = await request
  const grant = await requested.json()
  const operatorAuthorization = (await requested.request().allHeaders()).authorization
  const read = () => fetch(new URL('/rest/v1/rpc/st_v6_read_break_glass', supabase), {
    method: 'POST', headers: { apikey: publicKey, Authorization: operatorAuthorization, 'Content-Type': 'application/json' },
    body: JSON.stringify({ p_grant: grant }),
  })
  assert.equal((await read()).status, 403)
  await ops.getByText('Request sent to the workspace owner for review.', { exact: true }).waitFor()
  assert.equal(await ops.getByText(source, { exact: true }).count(), 0)
  const notices = ownerPage.getByRole('region', { name: 'Workspace emergency notices' })
  await notices.getByText('Emergency evidence access was requested.', { exact: true }).waitFor()
  assert.equal(await notices.getByText(source, { exact: true }).count(), 0)
  assert.deepEqual(value(await reporter.client.rpc('st_v6_my_emergency_notices')), [])
  const acknowledged = ownerPage.waitForResponse(response => response.ok() && response.url().endsWith('/rpc/st_v6_read_emergency_notice'))
  await button(notices, 'Mark notice as read').click()
  await acknowledged
  await button(notices, 'Mark notice as read').waitFor({ state: 'hidden' })

  await button(nav(ownerPage), 'Profile').click()
  await button(ownerPage, 'Security').click()
  await enroll(ownerPage, 'Verify authenticator')
  await ownerPage.getByRole('heading', { name: 'Recovery codes', exact: true }).waitFor()
  await button(nav(ownerPage), 'Workspaces').click()
  await button(ownerPage, 'Governance').click()
  const ownerReview = ownerPage.waitForResponse(response => response.url().endsWith('/rpc/st_v6_break_glass_list'))
  await ownerPage.getByText('Emergency access approvals', { exact: true }).click()
  const reviewResponse = await ownerReview
  assert.equal(reviewResponse.status(), 200, 'Workspace owner could not load emergency approvals: ' + await reviewResponse.text())
  assert.ok((await reviewResponse.json()).some(row => row.id === grant), 'Pending request was outside the owner view')
  const review = ownerPage.getByRole('region', { name: 'Emergency access', exact: true })
  await review.locator('select[name="action"]').selectOption('approved')
  await review.getByLabel('Decision reason').fill('Approve one review of the existing reported post.')
  await button(review, 'Record decision').click()
  await review.getByText('Review decision recorded.', { exact: true }).waitFor()
  await button(ops, 'Refresh requests').click()
  await button(ops, 'View approved evidence once').click()
  await ops.getByText(source, { exact: true }).waitFor()
  await ownerPage.getByText('Review the new workspace emergency access notice in Safety.', { exact: true }).waitFor()
  assert.equal((await read()).status, 403)
  await button(ops, 'Close evidence').click()
  assert.equal(await ops.getByText(source, { exact: true }).count(), 0)
  assert.equal(await ops.getByText('Private report notes remain private.', { exact: true }).count(), 0)

  await button(review, 'Refresh requests').click()
  await review.locator('select[name="action"]').selectOption('closed')
  await review.getByLabel('Decision reason').fill('Completed emergency review and confirmed the audit.')
  await button(review, 'Record decision').click()
  await review.getByText('Review decision recorded.', { exact: true }).waitFor()
  await review.getByText('Review history', { exact: true }).click()
  for (const state of ['requested', 'approved', 'accessed', 'closed']) {
    await review.getByRole('listitem').filter({ hasText: new RegExp('^' + state) }).waitFor()
  }
  await button(nav(ownerPage), 'Safety').click()
  await button(ownerPage, 'Account notices').click()
  await notices.getByText('The approved evidence was accessed.', { exact: true }).waitFor()
  await notices.getByText('The emergency access review was closed.', { exact: true }).waitFor()
  console.log('Passed actual operator TOTP, owner approval, one-time evidence, private live customer notices and review audit.')
} finally {
  await browser.close()
  if (workspace) sql(`delete from sectalk_private.st_v6_break_glass_audit where workspace_id='${workspace}';
    delete from public.st_v2_workspaces where id='${workspace}';`)
  if (operatorId) sql(`delete from sectalk_private.st_v6_tenant_access_log where actor='${operatorId}';
    delete from sectalk_private.st_v6_tenant_operators where account_id='${operatorId}';
    delete from sectalk_private.staff where user_id='${operatorId}';`)
  for (const user of users) value(await admin.auth.admin.deleteUser(user))
}
