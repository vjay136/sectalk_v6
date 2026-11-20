// Local QA. Human tenant case reassignment, MFA, decision and reporter status.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHmac, randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const password = randomUUID() + '1!Q'
const suffix = randomUUID().slice(0, 8)

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

async function account(prefix) {
  const handle = prefix + '_' + suffix
  const email = handle + '@example.invalid'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(supabase.origin, publicKey, options)
  const { session } = data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: handle }))
  assert.match(user.id, /^[a-f0-9-]{36}$/)
  return { id: user.id, session, client, email, handle }
}

function sql(statement) {
  return execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-v', 'ON_ERROR_STOP=1',
    '-At', '-U', 'postgres', '-d', 'postgres'], { input: statement, encoding: 'utf8', windowsHide: true }).trim()
}

function totp(secret) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bits = [...secret.toUpperCase().replace(/=+$/, '')].map(character =>
    alphabet.indexOf(character).toString(2).padStart(5, '0')).join('')
  const key = Buffer.from(bits.match(/.{8}/g).map(part => Number.parseInt(part, 2)))
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)))
  const mac = createHmac('sha1', key).update(counter).digest()
  return String((mac.readUInt32BE(mac.at(-1) & 15) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}

assert.equal(app.origin, 'http://127.0.0.1:3523')
const [owner, delegate, reporter, participant] = await Promise.all([
  account('case_owner'), account('case_delegate'), account('case_reporter'), account('case_author'),
])
const workspace = data(await owner.client.rpc('st_v2_create_workspace', { p_name: 'Human room case ' + suffix }))
assert.match(workspace, /^[a-f0-9-]{36}$/)
for (const user of [delegate, reporter, participant]) {
  data(await owner.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: user.handle }))
  const invitation = data(await user.client.from('st_v2_invites').select('id').eq('workspace_id',workspace).single())
  data(await user.client.rpc('st_v2_reply_invite', { p_invite: invitation.id, p_accept: true }))
}
sql("update public.st_v2_members set role='admin' where workspace_id='" + workspace + "' and user_id='" + delegate.id + "';")
const room = randomUUID()
const roomName = 'Case review room ' + suffix
const post = randomUUID()
const body = 'Synthetic reportable room post ' + suffix
const privateNote = 'Private reporter note retained by Platform ' + suffix
data(await owner.client.rpc('st_v6_room_create', { p_id:room,p_workspace:workspace,p_name:roomName,p_kind:'public',p_template:'blank' }))
for (const user of [delegate, reporter, participant]) data(await user.client.rpc('st_v6_room_membership', { p_room:room,p_action:'join' }))
data(await participant.client.rpc('st_v6_room_post', { p_room:room,p_id:post,p_body:body,p_kind:'message' }))
assert.equal((await owner.client.rpc('st_v7_workspace_room_review_queue')).error?.code, '42501')

const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
try {
  const nav = page => page.getByRole('navigation', { name: 'SecTalk features' })
  async function open(user) {
    const page = await browser.newPage({ locale: 'en-US' })
    await page.goto(app.href)
    await page.getByLabel('Email address', { exact: true }).fill(user.email)
    await page.getByLabel('Password', { exact: true }).fill(password)
    await page.locator('button.submit-auth').click()
    await nav(page).waitFor()
    return page
  }
  async function unlock(page) {
    await nav(page).getByRole('button', { name: 'Safety', exact: true }).click()
    await page.getByRole('button', { name: 'Workspace report review', exact: true }).click()
    await page.getByRole('button', { name: 'Set up authenticator', exact: true }).click()
    const secret = (await page.locator('.mfa-setup code').textContent()).trim()
    await page.getByLabel('Authenticator code', { exact: true }).fill(totp(secret))
    await page.getByRole('button', { name: 'Verify access', exact: true }).click()
    const region = page.getByRole('region', { name: 'Workspace room reports', exact: true })
    await region.getByText('No room reports to review.', { exact: true }).waitFor()
    return region
  }
  const [ownerPage, delegatePage, reportPage] = await Promise.all([open(owner), open(delegate), open(reporter)])
  const [firstQueue, secondQueue] = await Promise.all([unlock(ownerPage), unlock(delegatePage)])

  await nav(reportPage).getByRole('button', { name: 'Rooms', exact: true }).click()
  await reportPage.getByRole('region', { name: 'Room directory', exact: true }).getByRole('button', { name: new RegExp(roomName) }).click()
  const postRow = reportPage.locator('[data-room-post]').filter({ hasText: body })
  await postRow.getByText('Room message actions', { exact: true }).click()
  await postRow.getByRole('button', { name: 'Report room message', exact: true }).click()
  const form = reportPage.getByRole('region', { name: 'Report room message', exact: true })
  await form.getByRole('combobox', { name: 'Category', exact: true }).selectOption('spam')
  await form.getByLabel('Private details for platform staff').fill(privateNote)
  await form.getByRole('checkbox', { name: /Allow platform staff/ }).check()
  await form.getByRole('button', { name: 'Submit room report', exact: true }).click()
  await form.getByText(/Report submitted/).waitFor()
  const [record] = data(await reporter.client.rpc('st_v7_my_room_report_status'))
  assert.match(record.id, /^[a-f0-9-]{36}$/)
  assert.equal(record.status, 'open')
  // Seed the approved stage-3 handoff. The existing SOC browser suite exercises preceding Platform stages.
  sql("update sectalk_private.st_v6_room_reports set status='reviewing',handed_off_at=now() where id='" + record.id + "';"
    + "insert into sectalk_private.st_v6_room_report_stages(report_id,stage,assignee,assigned_at,acknowledge_by,action_by)"
    + " values('" + record.id + "',3,'" + owner.id + "',now(),now()+interval '2 hours',now()+interval '1 day');")
  await nav(reportPage).getByRole('button', { name: 'Safety', exact: true }).click()
  const mine = reportPage.getByRole('region', { name: 'My room reports', exact: true })
  await mine.getByText('In review', { exact: true }).waitFor()

  async function refresh(queue) {
    await queue.getByRole('button', { name: 'Refresh room reports', exact: true }).click()
  }
  const row = queue => queue.getByRole('button', { name: new RegExp(roomName) })
  async function action(queue, value, reason, target) {
    await queue.getByRole('combobox', { name: 'Review action', exact: true }).selectOption(value)
    if (target) await queue.getByRole('combobox', { name: 'Workspace reviewer', exact: true }).selectOption(target)
    await queue.getByLabel('Review reason', { exact: true }).fill(reason)
    await queue.getByRole('button', { name: 'Update room report', exact: true }).click()
    await queue.getByText('Room report updated.', { exact: true }).waitFor()
  }
  await refresh(firstQueue)
  await refresh(secondQueue)
  assert.equal(await row(secondQueue).count(), 0)
  await row(firstQueue).click()
  await firstQueue.getByText(body, { exact: true }).waitFor()
  assert.equal(await firstQueue.getByText(privateNote, { exact: true }).count(), 0)
  assert.equal(await firstQueue.locator('option[value="resolved"]').count(), 0)
  await action(firstQueue, 'acknowledge', 'Accept tenant review assignment')
  await action(firstQueue, 'delegate', 'Assign a second workspace reviewer', delegate.id)
  await firstQueue.getByText('No room reports to review.', { exact: true }).waitFor()

  await refresh(secondQueue)
  await row(secondQueue).click()
  await secondQueue.getByText('Assigned to you', { exact: true }).waitFor()
  await action(secondQueue, 'acknowledge', 'Accept reassignment and review case')
  await action(secondQueue, 'resolved', 'Reviewed as an ordinary workspace case')
  await secondQueue.getByText(/^Resolved/).waitFor()
  await mine.getByText(/Decided by your workspace reviewer/).waitFor()
  await mine.getByText('Resolved', { exact: true }).waitFor()
  assert.equal(await mine.getByText('Reviewed as an ordinary workspace case', { exact: true }).count(), 0)
  assert.equal(await mine.getByText(delegate.handle, { exact: true }).count(), 0)
  assert.equal(sql("select count(*) from sectalk_private.st_v7_room_review_assignments where report_id='" + record.id
    + "' and previous='" + owner.id + "' and assigned='" + delegate.id + "';"), '1')
  assert.equal(sql("select count(*) from sectalk_private.st_v6_room_report_audit where report_id='" + record.id
    + "' and action='resolved' and source='workspace' and actor='" + delegate.id + "';"), '1')
  assert.equal(sql("select count(*) from public.st_v6_room_posts where id='" + post + "' and removed_at is null;"), '1')
  console.log('PASS: opt-in report, MFA-only assignment, transfer, reasoned tenant decision, reporter closure, and unchanged post')
} finally {
  await browser.close()
}
