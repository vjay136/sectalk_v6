import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { createClient } from '@supabase/supabase-js'
import { verifyStaffPanel } from './workspace-admin-fixture.mjs'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const opts = { auth: { persistSession: false, autoRefreshToken: false } }
const key = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const service = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, opts)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const suffix = randomUUID().slice(0, 8)
const password = randomUUID() + '!2W'
const bytes = Buffer.from('Workspace policy test ' + suffix)
const digest = createHash('sha256').update(bytes).digest('hex')
const file = randomUUID()
const roomFile = randomUUID()
const room = randomUUID()
const filename = 'egress-' + suffix + '.txt'
const actors = []
const spaces = []
let browser

function data(result) {
  if (result.error) throw result.error
  return result.data
}
function sql(statement) {
  return execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-At',
    '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres'], { input: statement, encoding: 'utf8', windowsHide: true }).trim()
}
async function account(role) {
  const handle = 'egress_' + role + '_' + suffix
  const email = handle + '@example.invalid'
  const { user } = data(await service.auth.admin.createUser({ email, password, email_confirm: true }))
  actors.push(user.id)
  const client = createClient(supabase.origin, key, opts)
  const { session } = data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: 'File Egress ' + role }))
  return { id: user.id, email, handle, token: session.access_token, client }
}
const nav = page => page.getByRole('navigation', { name: 'SecTalk features' })
const tabs = page => page.getByRole('group', { name: 'Workspace sections' })
async function signIn(account) {
  const page = await browser.newPage({ acceptDownloads: true })
  await page.goto(app.href)
  await page.getByLabel('Email address', { exact: true }).fill(account.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await nav(page).getByRole('button', { name: 'Workspaces', exact: true }).click()
  return page
}
async function request(actor, path, method = 'GET', headers = {}) {
  return fetch(new URL(path, app), { method, headers: { Authorization: 'Bearer ' + actor.token, ...headers } })
}

try {
  const owner = await account('owner')
  const member = await account('member')
  const outsider = await account('other')
  const workspace = data(await owner.client.rpc('st_v2_create_workspace', { p_name: 'Egress QA ' + suffix }))
  spaces.push(workspace)
  const otherSpace = data(await outsider.client.rpc('st_v2_create_workspace', { p_name: 'Other QA ' + suffix }))
  spaces.push(otherSpace)
  data(await owner.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: member.handle }))
  const invite = data(await member.client.from('st_v2_invites').select('id').eq('workspace_id', workspace).single())
  data(await member.client.rpc('st_v2_reply_invite', { p_invite: invite.id, p_accept: true }))
  sql(`insert into sectalk_private.st_v6_workspace_files(workspace,id,uploader,filename,size_bytes,published_at)
    values('${workspace}','${file}','${owner.id}','${filename}',${bytes.length},now()),
      ('${otherSpace}','${file}','${outsider.id}','${filename}',${bytes.length},now());
    insert into public.st_v6_rooms(id,workspace_id,name,kind,template,creator,classification)
      values('${room}','${workspace}','Egress confidential room','private','blank','${owner.id}','confidential');
    insert into public.st_v6_room_members(room_id,user_id,role)
      values('${room}','${owner.id}','owner'),('${room}','${member.id}','member');
    insert into sectalk_private.st_v6_room_files(room,workspace,id,uploader,filename,size_bytes,sha256,published_at)
      values('${room}','${workspace}','${roomFile}','${owner.id}','${filename}',${bytes.length},'${digest}',now());`)
  const storage = service.storage.from('sectalk-workspace-files')
  const object = workspace + '/' + file
  const roomObject = workspace + '/rooms/' + room + '/' + roomFile
  for (const path of [object, roomObject, otherSpace + '/' + file]) {
    data(await storage.upload(path, bytes, { contentType: 'application/octet-stream' }))
  }
  const workspaceUrl = '/api/workspace-files?workspace=' + workspace + '&file=' + file
  const otherUrl = '/api/workspace-files?workspace=' + otherSpace + '&file=' + file
  const roomUrl = '/api/room-files?room=' + room + '&file=' + roomFile
  const share = workspaceUrl + '&action=share'
  const explain = (actor, scope = workspace, p_file = file) => actor.client.rpc('st_v7_explain_file_egress', {
    p_scope_type: 'workspace', p_scope: scope, p_file, p_operation: 'download',
  })
  assert.deepEqual(Buffer.from(await (await request(member, roomUrl)).arrayBuffer()), bytes)
  const originalLink = await request(member, share, 'POST')
  assert.equal(originalLink.status, 200)
  assert.equal((await originalLink.json()).path, '/workspace-file/' + object)
  assert.equal((await request(outsider, workspaceUrl)).status, 404)
  assert.deepEqual(data(await explain(outsider)), { allowed: false, reasons: ['access_unavailable'] })
  assert.deepEqual(data(await outsider.client.rpc('st_v7_file_egress_policy', { p_workspace: workspace })), { access: 'none' })
  assert.equal((await owner.client.rpc('st_v7_save_file_egress_policy', {
    p_workspace: workspace, p_revision: 0, p_policy: { mode: 'block' },
  })).error?.code, '42501')

  browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
  const ownerPage = await signIn(owner)
  await tabs(ownerPage).getByRole('button', { name: 'File policy', exact: true }).click()
  const policy = ownerPage.getByRole('region', { name: 'Workspace file policy' })
  await verifyStaffPanel(policy)
  const mode = policy.getByRole('combobox').first()
  await mode.waitFor({timeout:15000}).catch(async error => { console.error(await policy.innerText()); throw error })
  await mode.selectOption('block')
  await policy.getByRole('button', { name: 'Save file policy' }).click()
  await policy.getByText('File policy saved.', { exact: true }).waitFor()
  assert.equal((await request(member, roomUrl)).status, 403)
  assert.equal((await request(member, share, 'POST')).status, 403)
  assert.equal((await request(member, workspaceUrl, 'GET', { 'X-Forwarded-For': '127.0.0.1' })).status, 403)
  assert.deepEqual(Buffer.from(await (await request(outsider, otherUrl)).arrayBuffer()), bytes)
  assert.ok((await member.client.storage.from('sectalk-workspace-files').download(object)).error)

  const memberPage = await signIn(member)
  await tabs(memberPage).getByRole('button', { name: 'Files', exact: true }).click()
  assert.equal(await tabs(memberPage).getByRole('button', { name: 'File policy', exact: true }).count(), 0)
  await memberPage.getByRole('article').filter({ hasText: filename }).getByRole('button', { name: 'View file details' }).click()
  const details = memberPage.getByRole('region', { name: 'Workspace file details' })
  await details.getByRole('button', { name: 'Check download access' }).click()
  await details.getByText('The workspace blocks file sharing and downloads.', { exact: true }).waitFor()
  await details.getByRole('button', { name: 'Copy workspace link' }).click()
  await details.getByRole('alert').getByText('Workspace file policy blocked this action.', { exact: true }).waitFor()
  assert.equal(await details.getByRole('textbox', { name: 'Workspace file link' }).count(), 0)

  await mode.selectOption('require')
  await policy.getByLabel('Highest allowed classification').selectOption('internal')
  await policy.getByRole('button', { name: 'Save file policy' }).click()
  await policy.getByText('File policy saved.', { exact: true }).waitFor()
  assert.equal((await request(member, roomUrl)).status, 403)
  await details.getByRole('button', { name: 'Check download access' }).click()
  await details.getByText('Your session and this file meet the workspace policy.', { exact: true }).waitFor()
  await details.getByRole('button', { name: 'Copy workspace link' }).click()
  await details.getByRole('textbox', { name: 'Workspace file link' }).waitFor()
  const receiving = memberPage.waitForEvent('download')
  await details.getByRole('button', { name: 'Download workspace file' }).click()
  assert.deepEqual(await readFile(await (await receiving).path()), bytes)
  assert.equal(sql(`select count(*) from public.st_v2_workspace_audit where workspace_id='${workspace}'
    and event in ('workspace.file_egress_block','workspace.file_egress_require');`), '2')

  await nav(memberPage).getByRole('button', { name: 'Rooms', exact: true }).click()
  await memberPage.getByRole('button', { name: /Egress confidential room/ }).click()
  await memberPage.getByRole('group', { name: 'Room tabs' }).getByRole('button', { name: 'Files', exact: true }).click()
  const roomFiles = memberPage.getByRole('region', { name: 'Room files' })
  await roomFiles.getByRole('button', { name: 'Check download access' }).click()
  await roomFiles.getByText('The file exceeds the allowed classification.', { exact: true }).waitFor()
  await roomFiles.getByRole('button', { name: 'Download file', exact: true }).click()
  await roomFiles.getByRole('alert').getByText('Workspace file policy blocked this action.', { exact: true }).waitFor()

  await mode.selectOption('inherit')
  await policy.getByRole('button', { name: 'Save file policy' }).click()
  await policy.getByText('File policy saved.', { exact: true }).waitFor()
  assert.deepEqual(Buffer.from(await (await request(member, roomUrl)).arrayBuffer()), bytes)
  const receivingRoom = memberPage.waitForEvent('download')
  await roomFiles.getByRole('button', { name: 'Download file', exact: true }).click()
  assert.deepEqual(await readFile(await (await receivingRoom).path()), bytes)
} finally {
  await browser?.close()
  for (const workspace of spaces) {
    data(await service.storage.from('sectalk-workspace-files').remove([workspace + '/' + file, workspace + '/rooms/' + room + '/' + roomFile]))
    sql(`delete from sectalk_private.st_v6_room_files where workspace='${workspace}';
      delete from sectalk_private.st_v6_workspace_files where workspace='${workspace}';
      delete from sectalk_private.st_v6_workspace_file_history_subjects where workspace='${workspace}';
      delete from public.st_v2_workspaces where id='${workspace}';`)
  }
  for (const actor of actors) data(await service.auth.admin.deleteUser(actor))
}
console.log('Passed real browser policy changes, scoped explanations, workspace and room Storage byte access, and tenant isolation.')
