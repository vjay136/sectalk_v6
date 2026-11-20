import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const service = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const run = randomUUID().slice(0, 8)
const password = randomUUID() + '1!Q'
const room = randomUUID()
const sibling = randomUUID()
const root = randomUUID()
const memberPost = randomUUID()
const topic = 'Ordinary parent post for permissions'
const name = 'Permissions room ' + run
const accounts = []
let workspace
let browser
let stored

function data(result) {
  if (result.error) throw result.error
  return result.data
}
function sql(statement) {
  return execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-At', '-v', 'ON_ERROR_STOP=1',
    '-U', 'postgres', '-d', 'postgres'], { input: statement, encoding: 'utf8', windowsHide: true }).trim()
}
async function account(role) {
  const handle = 'rperm_' + role + '_' + run
  const email = handle + '@example.invalid'
  const { user } = data(await service.auth.admin.createUser({ email, password, email_confirm: true }))
  accounts.push(user.id)
  const client = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY, options)
  const { session } = data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: 'Room role QA ' + role }))
  return { id: user.id, handle, email, token: session.access_token, client }
}
const rpc = (actor, action, input) => actor.client.rpc(action, input)
const setRule = (actor, role, rules) => rpc(actor, 'st_v6_set_room_role_overrides', { p_room: room, p_role: role, p_rules: rules })
const post = (actor, id, body, parent = null, target = room) => rpc(actor, 'st_v6_room_post',
  { p_room: target, p_id: id, p_body: body, p_kind: 'message', p_parent: parent })
const react = (actor, enabled, emoji = '👍') => rpc(actor, 'st_v6_react_room_post',
  { p_room: room, p_post: root, p_emoji: emoji, p_enabled: enabled })
const start = actor => rpc(actor, 'st_v6_start_room_call', { p_room: room, p_id: randomUUID(), p_title: 'Room call' })
async function upload(actor, target, file = randomUUID()) {
  const query = new URLSearchParams({ room: target, file })
  return fetch(new URL('/api/room-files?' + query, app), {
    method: 'POST', headers: { Authorization: 'Bearer ' + actor.token, 'X-SecTalk-File-Name': 'permissions.txt',
      'Content-Type': 'text/plain' }, body: 'Benign role fixture upload.',
  })
}
const tabs = page => page.getByRole('group', { name: 'Room tabs' })
const tab = (page, title) => tabs(page).getByRole('button', { name: title, exact: true })
async function open(actor, selected) {
  const page = await browser.newPage()
  await page.goto(app.href)
  await page.getByLabel('Email address', { exact: true }).fill(actor.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation', { name: 'SecTalk features' }).getByRole('button', { name: 'Rooms', exact: true }).click()
  await page.getByRole('button', { name: new RegExp(name) }).click()
  await tab(page, selected).click()
  return page
}
const settings = page => page.getByRole('region', { name: 'Room role permissions' })
async function save(panel, role, values) {
  await panel.getByLabel('Room role').selectOption(role.toLowerCase())
  for (const [label, value] of Object.entries(values)) await panel.getByLabel(label, { exact: true }).selectOption(value)
  await panel.getByRole('button', { name: 'Save room permissions' }).click()
  await panel.getByText(role + ' permissions saved.', { exact: true }).waitFor()
}

try {
  const owner = await account('owner')
  const moderator = await account('mod')
  const member = await account('member')
  workspace = data(await rpc(owner, 'st_v2_create_workspace', { p_name: 'Room policies ' + run }))
  for (const actor of [moderator, member]) {
    data(await rpc(owner, 'st_v2_invite', { p_workspace: workspace, p_handle: actor.handle }))
    const invite = data(await actor.client.from('st_v2_invites').select('id').eq('workspace_id', workspace).single())
    data(await rpc(actor, 'st_v2_reply_invite', { p_invite: invite.id, p_accept: true }))
  }
  for (const [id, title] of [[room, name], [sibling, 'Sibling room ' + run]]) {
    data(await rpc(owner, 'st_v6_room_create', { p_workspace: workspace, p_id: id, p_name: title, p_kind: 'private', p_template: 'blank' }))
  }
  sql(`insert into public.st_v6_room_members(room_id,user_id,role)
    values('${room}','${moderator.id}','moderator'),('${room}','${member.id}','member'),('${sibling}','${member.id}','member');`)
  data(await post(owner, root, topic))
  data(await post(member, memberPost, 'Member default post with @channel'))
  assert.equal(sql(`select count(*) from public.st_v3_notifications where room_post_id='${memberPost}' and kind='mention.channel';`), '0')
  data(await react(member, true))
  assert.ok((await start(member)).error)
  assert.ok((await setRule(member, 'member', { post: 'deny' })).error)
  assert.ok((await setRule(moderator, 'owner', { react: 'deny' })).error)
  assert.ok((await setRule(moderator, 'moderator', { react: 'deny' })).error)
  assert.ok((await setRule(owner, 'member', { phantom: 'allow' })).error)

  browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
  const memberPage = await open(member, 'Messages')
  await memberPage.getByLabel('Write a room message').waitFor()
  assert.equal(await tab(memberPage, 'Settings').count(), 0)
  const modPage = await open(moderator, 'Settings')
  const mod = settings(modPage)
  await mod.getByLabel('Room role').waitFor()
  assert.deepEqual(await mod.getByLabel('Room role').locator('option').allTextContents(), ['Member'])
  await save(mod, 'Member', {
    'Post messages and replies': 'deny', 'Add reactions': 'deny', 'Upload files': 'deny', 'Start a room call': 'deny',
  })
  await memberPage.getByLabel('Write a room message').waitFor({ state: 'detached', timeout: 10000 })
  await memberPage.locator('[data-room-post]').filter({ hasText: topic }).getByRole('button', { name: /Open thread/ }).click()
  assert.equal(await memberPage.getByLabel('Write a reply').count(), 0)
  assert.equal(await memberPage.getByRole('button', { name: /Add reaction/ }).count(), 0)
  assert.ok((await post(member, randomUUID(), 'New root must be blocked')).error)
  assert.ok((await post(member, randomUUID(), 'Reply must be blocked', root)).error)
  assert.ok((await rpc(member, 'st_v6_room_post_action', { p_room: room, p_post: memberPost, p_action: 'edit', p_body: 'Edit blocked' })).error)
  assert.ok((await react(member, true, '❤️')).error)
  data(await react(member, false))
  await tab(memberPage, 'Files').click()
  await memberPage.getByText('No room files yet.', { exact: true }).waitFor()
  assert.equal(await memberPage.getByRole('button', { name: 'Upload room file' }).count(), 0)
  assert.equal((await upload(member, room)).status, 404)
  assert.ok((await start(member)).error)
  data(await post(member, randomUUID(), 'Sibling permissions remain unchanged', null, sibling))
  const siblingUpload = await upload(member, sibling)
  assert.equal(siblingUpload.status, 200)
  stored = (await siblingUpload.json()).id

  const ownerPage = await open(owner, 'Settings')
  const panel = settings(ownerPage)
  await panel.getByLabel('Room role').waitFor()
  assert.deepEqual(await panel.getByLabel('Room role').locator('option').allTextContents(), ['Owner', 'Moderator', 'Member'])
  await save(panel, 'Member', {
    'Post messages and replies': 'inherit', 'Add reactions': 'allow', 'Upload files': 'inherit',
    'Mention the room or online members': 'allow', 'Start a room call': 'allow',
  })
  await save(panel, 'Moderator', { 'Mention the room or online members': 'deny' })
  await tab(memberPage, 'Messages').click()
  await memberPage.getByLabel('Write a room message').waitFor()
  await memberPage.getByText('@channel', { exact: true }).waitFor()
  const broadcast = randomUUID()
  data(await post(member, broadcast, 'Permitted thread broadcast @channel', root))
  assert.ok(Number(sql(`select count(*) from public.st_v3_notifications where room_post_id='${broadcast}' and kind='mention.channel';`)) >= 1)
  const quiet = randomUUID()
  data(await post(moderator, quiet, 'Moderator broadcast blocked @channel', root))
  assert.equal(sql(`select count(*) from public.st_v3_notifications where room_post_id='${quiet}' and kind='mention.channel';`), '0')
  data(await react(member, true, '❤️'))
  data(await rpc(owner, 'st_v6_set_workspace_reactions', { p_workspace: workspace, p_set: 'off', p_limit: 8 }))
  assert.ok((await react(member, true, '✅')).error)
  await tab(memberPage, 'Calls').click()
  const calls = memberPage.getByRole('region', { name: 'Room calls' })
  await calls.getByLabel('Room call title').fill('Member-scoped room call')
  await calls.getByRole('button', { name: 'Start room call' }).click()
  await calls.getByRole('heading', { name: 'Member-scoped room call' }).waitFor()
  const href = await calls.getByRole('link', { name: 'Open room call' }).getAttribute('href')
  const meeting = new URL(href).searchParams.get('meeting')
  assert.equal(data(await rpc(member, 'st_v3_media_access', { p_meeting: meeting })), true)
  await calls.getByRole('link', { name: 'Open room call' }).click()
  await memberPage.getByRole('button', { name: 'End meeting', exact: true }).waitFor()
  assert.ok((await rpc(member, 'st_v6_start_instant_meeting', {
    p_id: randomUUID(), p_workspace: workspace, p_title: 'Outside permitted room', p_minutes: 30,
  })).error)
  sql(`update public.st_v6_room_members set role='read_only' where room_id='${room}' and user_id='${member.id}';`)
  assert.equal(data(await rpc(member, 'st_v3_media_access', { p_meeting: meeting })), false)
  assert.ok((await post(member, randomUUID(), 'Read-only remains blocked')).error)
  assert.equal(sql(`select count(*) from public.st_v6_room_audit where room_id='${room}' and action='room.role_permissions';`), '3')
  assert.deepEqual(data(await member.client.from('st_v6_room_audit').select('id').eq('room_id', room)), [])
  console.log('Room role overrides passed in Edge and SQL for post, replies, reactions, upload, broadcast mentions and scoped call hosting.')
} finally {
  await browser?.close()
  if (workspace) {
    if (stored) data(await service.storage.from('sectalk-workspace-files').remove([workspace + '/rooms/' + sibling + '/' + stored]))
    sql(`delete from sectalk_private.st_v6_room_files where workspace='${workspace}'; delete from public.st_v2_workspaces where id='${workspace}';`)
  }
  for (const actor of accounts) data(await service.auth.admin.deleteUser(actor))
}
