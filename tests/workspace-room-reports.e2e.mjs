// Local QA only. Uses genuine browser TOTP and scoped workspace room reports.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHmac, randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = {auth: {persistSession: false, autoRefreshToken: false}}
const admin = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const password = randomUUID() + '1!Q'
const suffix = randomUUID().slice(0, 8)
assert.match(suffix, /^[a-f0-9]{8}$/)

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}
async function account(role) {
  const handle = 'room_' + role + '_' + suffix
  const email = handle + '@example.invalid'
  const {user} = data(await admin.auth.admin.createUser({email, password, email_confirm: true}))
  const client = createClient(supabase.origin, publicKey, options)
  data(await client.auth.signInWithPassword({email, password}))
  data(await client.rpc('st_save_profile', {p_handle: handle, p_name: 'Private fixture profile'}))
  assert.match(user.id, /^[a-f0-9-]{36}$/)
  return {id: user.id, email, handle, client}
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

const [owner, reporter, author, outsider, l1, l2, platformStaff] = await Promise.all([
  account('owner'), account('reporter'), account('author'), account('outsider'),
  account('l1'), account('l2'), account('platform'),
])
execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-v', 'ON_ERROR_STOP=1',
  '-U', 'postgres', '-d', 'postgres'], {input: `
    insert into sectalk_private.staff values ('${l1.id}'),('${l2.id}'),('${platformStaff.id}');
    insert into sectalk_private.st_v6_case_on_call values
      ('${l1.id}',1,now(),now()+interval '1 hour'),
      ('${l2.id}',2,now(),now()+interval '1 hour'),
      ('${platformStaff.id}',3,now(),now()+interval '1 hour');
  `})
const workspace = data(await owner.client.rpc('st_v2_create_workspace', {p_name: 'Report workspace ' + suffix}))
await outsider.client.rpc('st_v2_create_workspace', {p_name: 'Other report workspace ' + suffix}).then(data)
for (const person of [reporter, author]) {
  data(await owner.client.rpc('st_v2_invite', {p_workspace: workspace, p_handle: person.handle}))
  const invite = data(await person.client.from('st_v2_invites').select('id').eq('workspace_id', workspace).single())
  data(await person.client.rpc('st_v2_reply_invite', {p_invite: invite.id, p_accept: true}))
}
const room = randomUUID()
const roomName = 'Report room ' + suffix
data(await owner.client.rpc('st_v6_room_create', {
  p_id: room, p_workspace: workspace, p_name: roomName, p_kind: 'public', p_template: 'blank',
}))
data(await author.client.rpc('st_v6_room_membership', {p_room: room, p_action: 'join'}))
const post = randomUUID()
const privatePost = randomUUID()
const body = 'Visible room evidence ' + suffix
const privateBody = 'Platform only evidence ' + suffix
data(await author.client.rpc('st_v6_room_post', {p_room: room, p_id: post, p_body: body}))
data(await author.client.rpc('st_v6_room_post', {p_room: room, p_id: privatePost, p_body: privateBody}))
assert.equal((await reporter.client.rpc('st_v6_submit_room_report', {
  p_room: room,p_post: post,p_category: 'threat',p_details: '',p_share: true,
})).error?.code,'42501')
assert.equal((await owner.client.rpc('st_v6_room_report_queue', {p_scope: 'workspace'})).error?.code,'42501')

const browser = await chromium.launch({executablePath: process.env.SECTALK_TEST_BROWSER})
try {
  const nav = page => page.getByRole('navigation', {name: 'SecTalk features'})
  async function open(person) {
    const page = await browser.newPage()
    await page.goto(new URL('/#account', app).href)
    await page.getByLabel('Email address', {exact: true}).fill(person.email)
    await page.getByLabel('Password', {exact: true}).fill(password)
    await page.locator('button.submit-auth').click()
    await nav(page).waitFor()
    return page
  }
  async function safety(page) {
    await nav(page).getByRole('button', {name: 'Safety', exact: true}).click()
  }
  async function verify(page, section) {
    await safety(page)
    await page.getByRole('button', {name: section, exact: true}).click()
    await page.getByRole('button', {name: 'Set up authenticator', exact: true}).click()
    const secret = (await page.locator('.mfa-setup code').textContent()).trim()
    await page.getByLabel('Authenticator code', {exact: true}).fill(totp(secret))
    const response = page.waitForResponse(result => result.url().includes('/auth/v1/factors/') && result.url().endsWith('/verify'))
    await page.getByRole('button', {name: 'Verify access', exact: true}).click()
    assert.ok((await response).ok())
  }

  const [member, l1Page, l2Page, platform, workspaceAdmin, foreignAdmin] = await Promise.all([
    open(reporter),open(l1),open(l2),open(platformStaff),open(owner),open(outsider),
  ])
  await Promise.all([
    verify(l1Page, 'Staff console'),
    verify(l2Page, 'Staff console'),
    verify(platform, 'Staff console'),
    verify(workspaceAdmin, 'Workspace report review'),
    verify(foreignAdmin, 'Workspace report review'),
  ])
  const workspaceQueue = workspaceAdmin.getByRole('region', {name: 'Workspace room reports'})
  await workspaceQueue.getByText('No room reports to review.', {exact: true}).waitFor()
  await nav(member).getByRole('button', {name: 'Rooms', exact: true}).click()
  await member.getByRole('region', {name: 'Room directory', exact: true}).getByRole('button', {name: new RegExp(roomName)}).click()
  const panel = member.getByRole('region', {name: roomName, exact: true})
  await panel.getByRole('button', {name: 'Join room', exact: true}).click()
  const privateDetails = 'Sensitive notes ' + suffix
  async function report(message, category, allowed) {
    const card = panel.getByRole('article').filter({hasText: message})
    await card.getByText('Room message actions', {exact: true}).click()
    await card.getByRole('button', {name: 'Report room message', exact: true}).click()
    const form = card.getByRole('region', {name: 'Report room message', exact: true})
    await form.getByRole('combobox', {name: 'Category', exact: true}).selectOption(category)
    await form.getByLabel('Private details for platform staff', {exact: true}).fill(privateDetails)
    const checkbox = form.getByRole('checkbox')
    assert.equal(await checkbox.isChecked(), false)
    if (allowed) await checkbox.check()
    await form.getByRole('button', {name: 'Submit room report', exact: true}).click()
    const receipt=form.getByRole('status').filter({hasText:'Report submitted.'})
    await receipt.waitFor()
    const ticket=await receipt.locator('code').textContent()
    assert.match(ticket,/^[a-f0-9-]{36}$/)
    await form.getByRole('button', {name: 'Done', exact: true}).click()
    return ticket
  }
  const roomTicket=await report(body, 'threat', true)
  await report(privateBody, 'spam', false)
  await safety(member)
  const mine = member.getByRole('region', {name: 'My room reports'})
  await mine.getByText(roomTicket,{exact:true}).waitFor()
  const ticketHistory=mine.getByRole('article').filter({hasText:roomTicket})
  await ticketHistory.getByText('Action history',{exact:true}).click()
  await ticketHistory.getByText('Report received',{exact:true}).waitFor()
  await mine.getByText('Platform review only', {exact: true}).waitFor()
  await mine.getByText('You allowed workspace sharing', {exact: true}).waitFor()
  assert.equal(await member.getByRole('button', {name: 'Workspace report review', exact: true}).count(), 0)

  const queue = l1Page.getByRole('region', {name: 'Platform room reports'})
  await queue.getByRole('button', {name: 'Refresh room reports', exact: true}).click()
  await queue.getByRole('button', {name: new RegExp('Spam.*' + roomName)}).click()
  assert.equal(await queue.getByRole('option', {name: /^Route to/}).count(), 0)
  await queue.getByRole('button', {name: 'Back to room reports', exact: true}).click()
  await queue.getByRole('button', {name: new RegExp('Threat.*' + roomName)}).click()
  await queue.getByText(privateDetails, {exact: true}).waitFor()

  async function review(view, action) {
    await view.getByRole('combobox', {name: 'Review action', exact: true}).selectOption(action)
    await view.getByLabel('Review reason', {exact: true}).fill('Scoped review ' + suffix)
    await view.getByRole('button', {name: 'Update room report', exact: true}).click()
    await view.getByText('Room report updated.', {exact: true}).waitFor()
  }
  await review(queue, 'route')
  await queue.getByText('Acknowledge by', {exact: true}).waitFor()
  await queue.getByText('Action due', {exact: true}).waitFor()
  assert.equal(await queue.getByRole('option', {name: 'Route to L2', exact: true}).count(), 0)
  assert.equal(await queue.getByRole('option', {name: 'Resolve', exact: true}).count(), 0)
  await review(queue, 'acknowledge')
  await review(queue, 'route')
  await l2Page.getByText('You have a new on-call room report assignment.', {exact: true}).waitFor()
  const l2Queue = l2Page.getByRole('region', {name: 'Platform room reports'})
  await l2Queue.getByRole('button', {name: 'Refresh room reports', exact: true}).click()
  await l2Queue.getByRole('button', {name: new RegExp('Threat.*' + roomName)}).click()
  await l2Queue.getByText('Assigned to you', {exact: true}).waitFor()
  await review(l2Queue, 'acknowledge')
  await review(l2Queue, 'route')
  await workspaceAdmin.getByText('You have a new workspace room report to review.', {exact: true}).waitFor()
  await workspaceQueue.getByRole('button', {name: 'Refresh room reports', exact: true}).click()
  await workspaceQueue.getByRole('button', {name: new RegExp('Threat.*' + roomName)}).click()
  await workspaceQueue.getByText(body, {exact: true}).waitFor()
  assert.equal(await workspaceQueue.getByText(privateDetails, {exact: true}).count(), 0)
  assert.equal(await workspaceQueue.getByText(privateBody, {exact: true}).count(), 0)
  assert.equal(await workspaceQueue.getByRole('option', {name: 'Resolve', exact: true}).count(), 0)

  const foreignQueue = foreignAdmin.getByRole('region', {name: 'Workspace room reports'})
  await foreignQueue.getByRole('button', {name: 'Refresh room reports', exact: true}).click()
  await foreignQueue.getByText('No room reports to review.', {exact: true}).waitFor()
  assert.equal(await foreignAdmin.getByText('You have a new workspace room report to review.', {exact: true}).count(), 0)
  await review(workspaceQueue, 'acknowledge')
  await review(workspaceQueue, 'route')
  await workspaceQueue.getByText('No room reports to review.', {exact: true}).waitFor()
  await platform.getByText('You have a new on-call room report assignment.', {exact: true}).waitFor()
  const platformQueue = platform.getByRole('region', {name: 'Platform room reports'})
  await platformQueue.getByRole('button', {name: 'Refresh room reports', exact: true}).click()
  await platformQueue.getByRole('button', {name: new RegExp('Threat.*' + roomName)}).click()
  await platformQueue.getByText('Assigned to you', {exact: true}).waitFor()
  assert.equal(await platformQueue.getByRole('option', {name: 'Resolve', exact: true}).count(), 0)
  await review(platformQueue, 'acknowledge')
  await review(platformQueue, 'resolved')
  await member.getByRole('button', {name: 'Refresh', exact: true}).click()
  await mine.getByText('Shared with authorized workspace admins', {exact: true}).waitFor()
  await ticketHistory.getByText('Resolved', {exact: true}).first().waitFor()
  for(const action of ['Sent to workspace review','Returned to Platform Safety','Resolved'])
    await ticketHistory.locator('ol').getByText(action,{exact:true}).waitFor()
  assert.equal(await ticketHistory.getByText(privateDetails,{exact:true}).count(),0)
  console.log('Passed real TOTP, private handoffs, tenant isolation, matching room ticket, and reporter action history.')
} finally {
  await browser.close()
}
