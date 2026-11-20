import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { setTimeout } from 'node:timers/promises'
import { createClient } from '@supabase/supabase-js'
import { RoomServiceClient } from 'livekit-server-sdk'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const livekit = new RoomServiceClient('http://127.0.0.1:7880', 'devkey', 'secret')
const bucket = 'sectalk-workspace-files'
const run = randomUUID().slice(0, 8)
const password = randomUUID() + '1!Q'
const rooms = [randomUUID(), randomUUID()]
const bytes = Buffer.from('Benign bytes for a private same-room file ' + run)
const filename = 'room-file-' + run + '.txt'
const title = 'Room Alpha call ' + run
const siblingTitle = 'Room Beta call ' + run
const accounts = []
let workspace
let browser
let file

function data(result) {
  if (result.error) throw result.error
  return result.data
}
function sql(statement) {
  return execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-At', '-v', 'ON_ERROR_STOP=1',
    '-U', 'postgres', '-d', 'postgres'], { input: statement, encoding: 'utf8', windowsHide: true }).trim()
}
async function account(role) {
  const handle = 'rtab_' + role + '_' + run
  const name = 'Room Tabs ' + role
  const email = handle + '@example.invalid'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  accounts.push(user.id)
  const client = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY, options)
  const { session } = data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: name }))
  return { id: user.id, name, handle, email, client, token: session.access_token }
}
const auth = actor => ({ Authorization: 'Bearer ' + actor.token })
const request = (url, init) => fetch(new URL(url, app), init)
const roomFile = (actor, room, id, method = 'GET') =>
  request('/api/room-files?' + new URLSearchParams({ room, ...(id ? { file: id } : {}) }), { method, headers: auth(actor) })
const token = (actor, meetingId) => request('/api/meetings/token', { method: 'POST',
  headers: { ...auth(actor), 'Content-Type': 'application/json' }, body: JSON.stringify({ meetingId }) })
const nav = page => page.getByRole('navigation', { name: 'SecTalk features' })
const tabs = page => page.getByRole('group', { name: 'Room tabs' })

async function login(actor) {
  const page = await browser.newPage({ acceptDownloads: true, permissions: ['camera', 'microphone'] })
  await page.goto(app.href)
  await page.getByLabel('Email address', { exact: true }).fill(actor.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await nav(page).getByRole('button', { name: 'Rooms', exact: true }).waitFor()
  return page
}
async function openRoom(page, name, tab) {
  await nav(page).getByRole('button', { name: 'Rooms', exact: true }).click()
  await page.getByRole('button', { name: new RegExp(name) }).click()
  await tabs(page).getByRole('button', { name: tab, exact: true }).click()
}
async function waitParticipants(room, members) {
  for (let attempt = 0; attempt < 30; attempt++) {
    const people = await livekit.listParticipants(room).catch(() => [])
    if (members.every(id => people.some(person => person.identity === id))) return
    await setTimeout(500)
  }
  assert.fail('Authorized room call attendees did not connect to local LiveKit')
}
async function waitDisconnected(room, actor) {
  for (let attempt = 0; attempt < 32; attempt++) {
    const people = await livekit.listParticipants(room).catch(() => null)
    if (people && !people.some(person => person.identity === actor)) return
    await setTimeout(500)
  }
  assert.fail('The browser did not leave the call after losing room access')
}

try {
  const owner = await account('owner')
  const member = await account('member')
  const sibling = await account('sibling')
  const outside = await account('outside')
  workspace = data(await owner.client.rpc('st_v2_create_workspace', { p_name: 'Rooms test ' + run }))
  for (const actor of [member, sibling]) {
    data(await owner.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: actor.handle }))
    const invitation = data(await actor.client.from('st_v2_invites').select('id').eq('workspace_id', workspace).single())
    data(await actor.client.rpc('st_v2_reply_invite', { p_invite: invitation.id, p_accept: true }))
  }
  const nameA = 'Alpha room ' + run
  const nameB = 'Beta room ' + run
  for (const [id, name] of [[rooms[0], nameA], [rooms[1], nameB]]) {
    data(await owner.client.rpc('st_v6_room_create', {
      p_workspace: workspace, p_id: id, p_name: name, p_kind: 'private', p_template: 'blank',
    }))
  }
  sql(`insert into public.st_v6_room_members(room_id,user_id,role)
    values('${rooms[0]}','${member.id}','member'),('${rooms[1]}','${sibling.id}','member');`)
  browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER,
    args: ['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream'] })
  const ownerPage = await login(owner)
  await openRoom(ownerPage, nameA, 'Files')
  const ownerFiles = ownerPage.getByRole('region', { name: 'Room files' })
  const uploaded = ownerPage.waitForResponse(response => response.url().includes('/api/room-files?') && response.request().method() === 'POST')
  await ownerFiles.getByLabel('Choose room file').setInputFiles({ name: filename, mimeType: 'text/plain', buffer: bytes })
  await ownerFiles.getByRole('button', { name: 'Upload room file' }).click()
  const completed = await uploaded
  assert.equal(completed.status(), 200, await completed.text())
  file = (await completed.json()).id
  const object = workspace + '/rooms/' + rooms[0] + '/' + file
  assert.deepEqual(Buffer.from(await data(await admin.storage.from(bucket).download(object)).arrayBuffer()), bytes)
  assert.equal((await roomFile(sibling, rooms[0], file)).status, 404)
  assert.equal((await roomFile(sibling, rooms[1], file)).status, 404)
  assert.equal((await roomFile(outside, rooms[0])).status, 404)
  assert.ok((await member.client.storage.from(bucket).download(object)).error)
  assert.equal((await request('/api/workspace-files?' + new URLSearchParams({ workspace, file }), { headers: auth(member) })).status, 404)
  const memberPage = await login(member)
  await openRoom(memberPage, nameA, 'Files')
  const memberFiles = memberPage.getByRole('region', { name: 'Room files' })
  await memberFiles.getByRole('heading', { name: filename }).waitFor()
  const download = memberPage.waitForEvent('download')
  await memberFiles.getByRole('button', { name: 'Download file' }).click()
  assert.deepEqual(await readFile(await (await download).path()), bytes)
  assert.equal(await tabs(memberPage).getByRole('button', { name: 'Audit', exact: true }).count(), 0)
  assert.ok((await member.client.rpc('st_v6_start_room_call', { p_room: rooms[0], p_id: randomUUID(), p_title: 'Unauthorized host' })).error)

  await tabs(ownerPage).getByRole('button', { name: 'Calls', exact: true }).click()
  const calls = ownerPage.getByRole('region', { name: 'Room calls' })
  await calls.getByLabel('Room call title').fill(title)
  await calls.getByRole('button', { name: 'Start room call' }).click()
  await calls.getByRole('heading', { name: title }).waitFor()
  await calls.getByText('Admitted: ' + owner.name, { exact: true }).waitFor()
  const link = await calls.getByRole('link', { name: 'Open room call' }).getAttribute('href')
  const meeting = new URL(link).searchParams.get('meeting')
  const siblingMeeting = data(await owner.client.rpc('st_v6_start_room_call', { p_room: rooms[1], p_id: randomUUID(), p_title: siblingTitle }))
  await tabs(memberPage).getByRole('button', { name: 'Calls', exact: true }).click()
  const memberCalls = memberPage.getByRole('region', { name: 'Room calls' })
  await memberCalls.getByRole('heading', { name: title }).waitFor()
  assert.equal(await memberCalls.getByRole('heading', { name: siblingTitle }).count(), 0)
  assert.equal(data(await sibling.client.rpc('st_v6_room_calls', { p_room: rooms[0] })), null)
  assert.equal(data(await outsiderSafe(outside, meeting)), null)
  assert.equal(data(await outsiderSafe(sibling, meeting)), null)
  assert.equal(data(await outsiderSafe(member, siblingMeeting)), null)
  assert.ok((await sibling.client.rpc('st_v3_request_admission', { p_meeting: meeting })).error)
  assert.equal((await token(sibling, meeting)).status, 403)
  assert.equal((await token(outside, meeting)).status, 403)
  assert.equal(sql(`select count(*) from public.st_v3_notifications where meeting_id='${meeting}';`), '0')
  assert.equal(sql(`select count(*) from public.st_v2_workspace_audit where target='${meeting}';`), '0')
  assert.equal(sql(`select count(*) from public.st_v6_room_audit where room_id='${rooms[0]}' and target='${meeting}' and action='meeting.live';`), '1')
  sql(`do $$ begin
    begin
      insert into sectalk_private.st_v6_guest_policy(meeting,enabled) values('${meeting}',true);
      raise exception 'A room call allowed external guests';
    exception when insufficient_privilege then null; end;
    begin
      update public.st_v3_meetings set media_protection=1 where id='${meeting}';
      raise exception 'Room calls accepted the separate protected roster mode';
    exception when check_violation then null; end;
  end $$;`)

  await memberCalls.getByRole('link', { name: 'Open room call' }).click()
  await memberPage.getByRole('button', { name: 'Request admission' }).click()
  await memberPage.getByText('Waiting for the host to admit you', { exact: true }).waitFor()
  data(await owner.client.rpc('st_v3_admit', { p_meeting: meeting, p_user: member.id, p_allow: true }))
  await calls.getByText('Admitted: ' + owner.name + ', ' + member.name, { exact: true }).waitFor()
  await calls.getByRole('link', { name: 'Open room call' }).click()
  await memberPage.getByRole('button', { name: 'Join audio and video' }).click()
  await ownerPage.getByRole('button', { name: 'Join audio and video' }).click()
  await waitParticipants('sectalk-v3-' + meeting, [owner.id, member.id])
  assert.equal((await token(member, meeting)).status, 200)

  sql(`delete from public.st_v6_room_members where room_id='${rooms[0]}' and user_id='${member.id}';`)
  assert.equal((await token(member, meeting)).status, 403)
  assert.equal((await roomFile(member, rooms[0], file)).status, 404)
  assert.equal(sql(`select status from public.st_v3_attendance where meeting_id='${meeting}' and user_id='${member.id}';`), 'left')
  await waitDisconnected('sectalk-v3-' + meeting, member.id)
  const refreshed = data(await owner.client.rpc('st_v6_room_calls', { p_room: rooms[0] }))
  assert.deepEqual(refreshed.calls[0].roster, [owner.name])
  assert.equal((await roomFile(owner, rooms[0], file, 'DELETE')).status, 204)
  const maintenance = await request('/api/workspace-files/maintenance', {
    method: 'POST', headers: { Authorization: 'Bearer ' + process.env.SECTALK_FILE_PURGE_SECRET },
  })
  assert.equal(maintenance.status, 200)
  assert.ok((await admin.storage.from(bucket).download(object)).error)
  sql(`update public.st_v6_room_members set role='member' where room_id='${rooms[0]}' and user_id='${owner.id}';`)
  assert.equal(data(await owner.client.rpc('st_v6_room_calls', { p_room: rooms[0] })).calls[0].live, false)
  assert.equal((await token(owner, meeting)).status, 403)
  console.log('Room Files and Calls passed with private Storage, real Edge, local LiveKit, room ACL, retained tabs and scoped audit.')
} finally {
  await browser?.close()
  if (workspace) {
    if (file) data(await admin.storage.from(bucket).remove([workspace + '/rooms/' + rooms[0] + '/' + file]))
    sql(`delete from sectalk_private.st_v6_room_files where workspace='${workspace}';
      delete from public.st_v2_workspaces where id='${workspace}';`)
  }
  for (const id of accounts) data(await admin.auth.admin.deleteUser(id))
}

function outsiderSafe(actor, meeting) {
  return actor.client.from('st_v3_meetings').select('id').eq('id', meeting).maybeSingle()
}
