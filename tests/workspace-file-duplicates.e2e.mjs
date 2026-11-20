import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const password = randomUUID() + '1!Q'
const run = randomUUID().slice(0, 8)
const bucket = 'sectalk-workspace-files'
const same = Buffer.from('Same harmless data shared independently in two workspaces ' + run)
const legacy = Buffer.from('Previously published workspace Storage bytes ' + run)
const accounts = []
const spaces = []
const objects = []
const directFiles = []
let browser
let directChat

function data(result) {
  if (result.error) throw result.error
  return result.data
}
function sql(statement) {
  return execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-At', '-v', 'ON_ERROR_STOP=1',
    '-U', 'postgres', '-d', 'postgres'], { input: statement, encoding: 'utf8', windowsHide: true }).trim()
}
async function account(role) {
  const handle = 'wsfile_' + role + '_' + run
  const email = handle + '@example.invalid'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  accounts.push(user.id)
  const client = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY, options)
  const { session } = data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: 'Workspace Files ' + role }))
  return { id: user.id, client, handle, email, token: session.access_token }
}
const auth = actor => actor ? { Authorization: 'Bearer ' + actor.token } : {}
const workspacePath = (workspace, file) => '/api/workspace-files?' + new URLSearchParams({ workspace, ...(file ? { file } : {}) })
const objectPath = (workspace, file) => workspace + '/' + file
const request = (path, init) => fetch(new URL(path, app), init)
const list = (actor, workspace) => request(workspacePath(workspace), { headers: auth(actor) })
const get = (actor, workspace, file) => request(workspacePath(workspace, file), { headers: auth(actor) })
function upload(actor, workspace, filename, bytes, mime = 'text/plain', id = randomUUID()) {
  objects.push(objectPath(workspace, id))
  return request(workspacePath(workspace, id), {
    method: 'POST', headers: { ...auth(actor), 'X-SecTalk-File-Name': encodeURIComponent(filename), 'Content-Type': mime },
    body: bytes,
  })
}
const maintain = token => request('/api/workspace-files/maintenance', {
  method: 'POST', headers: { Authorization: 'Bearer ' + token },
})

async function filesPanel(actor) {
  const page = await browser.newPage({ acceptDownloads: true })
  await page.goto(app.href)
  await page.getByLabel('Email address', { exact: true }).fill(actor.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation', { name: 'SecTalk features' }).getByRole('button', { name: 'Workspaces', exact: true }).click()
  await page.getByRole('group', { name: 'Workspace sections' }).getByRole('button', { name: 'Files', exact: true }).click()
  const panel = page.getByRole('region', { name: 'Workspace files', exact: true })
  await panel.waitFor()
  return { page, panel }
}
async function submit(view, workspace, filename, bytes, duplicate) {
  const response = view.page.waitForResponse(candidate => candidate.url().includes('/api/workspace-files?') &&
    candidate.request().method() === 'POST')
  await view.panel.getByLabel('Choose workspace file').setInputFiles({ name: filename, mimeType: 'text/plain', buffer: bytes })
  await view.panel.getByRole('button', { name: 'Upload workspace file' }).click()
  const completed = await response
  assert.equal(completed.status(), 200, await completed.text())
  const result = await completed.json()
  objects.push(objectPath(workspace, result.id))
  assert.deepEqual(Object.keys(result).sort(), ['duplicate', 'id'])
  assert.equal(result.duplicate, duplicate)
  await view.panel.getByRole('status').getByText(duplicate
    ? 'Uploaded. An identical file already exists in this workspace.' : 'Workspace file uploaded.').waitFor()
  await view.panel.getByRole('heading', { name: filename, exact: true }).waitFor()
  return result.id
}
async function directUpload(actor, filename, bytes, expectedDuplicate) {
  const id = randomUUID()
  directFiles.push(id)
  data(await actor.client.rpc('st_v5_stage_file', { p_chat: directChat, p_id: id, p_filename: filename, p_bytes: bytes.length }))
  assert.equal((await request('/api/files/upload?file=' + id, {
    method: 'POST', headers: { ...auth(actor), 'Content-Type': 'text/plain' }, body: bytes,
  })).status, 200)
  const publish = await request('/api/files/publish', {
    method: 'POST', headers: { ...auth(actor), 'Content-Type': 'application/json' },
    body: JSON.stringify({ file: id, mime: 'text/plain', caption: '' }),
  })
  assert.equal(publish.status, 200)
  assert.equal((await publish.json()).duplicate, expectedDuplicate)
}

try {
  const alpha = await account('alpha')
  const teammate = await account('member')
  const beta = await account('beta')
  const a = data(await alpha.client.rpc('st_v2_create_workspace', { p_name: 'Alpha Files ' + run }))
  spaces.push(a)
  const b = data(await beta.client.rpc('st_v2_create_workspace', { p_name: 'Beta Files ' + run }))
  spaces.push(b)
  data(await alpha.client.rpc('st_v2_invite', { p_workspace: a, p_handle: teammate.handle }))
  const invite = data(await teammate.client.from('st_v2_invites').select('id').eq('workspace_id', a).single())
  data(await teammate.client.rpc('st_v2_reply_invite', { p_invite: invite.id, p_accept: true }))
  assert.equal((await list(null, a)).status, 401)
  assert.equal((await list(beta, a)).status, 404)
  assert.equal((await upload(beta, a, 'out-of-scope.txt', same)).status, 404)
  assert.equal((await upload(alpha, a, 'mislabelled.png', same, 'image/png')).status, 415)
  assert.equal((await upload(alpha, a, 'marker.txt', Buffer.from('Harmless documentation about the <script> element.'))).status, 422)
  assert.ok((await alpha.client.rpc('st_v6_workspace_file_command', {
    p_workspace: a, p_actor: alpha.id, p_action: 'list', p_id: null, p_filename: null, p_bytes: null, p_hash: null,
  })).error)

  browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
  const ownerView = await filesPanel(alpha)
  const betaView = await filesPanel(beta)
  const teamView = await filesPanel(teammate)
  const aFile = await submit(ownerView, a, 'first-alpha.txt', same, false)
  const bFile = await submit(betaView, b, 'first-beta.txt', same, false)
  const repeat = await submit(teamView, a, 'same-tenant-member.txt', same, true)
  directChat = data(await alpha.client.rpc('st_request', { p_handle: teammate.handle }))
  data(await teammate.client.rpc('st_respond', { p_chat: directChat, p_accept: true }))
  await directUpload(alpha, 'first-direct.txt', same, false)
  await directUpload(alpha, 'repeat-direct.txt', same, true)
  const directOnly = Buffer.from('Matching bytes initially uploaded only in a direct chat ' + run)
  await directUpload(alpha, 'direct-before-workspace.txt', directOnly, false)
  await submit(ownerView, a, 'direct-source-cannot-match.txt', directOnly, false)
  for (const [space, id] of [[a, aFile], [a, repeat], [b, bFile]]) {
    const object = data(await admin.storage.from(bucket).download(objectPath(space, id)))
    assert.deepEqual(Buffer.from(await object.arrayBuffer()), same)
  }
  const fpA = sql(`select encode(fingerprint,'hex') from sectalk_private.st_v6_workspace_files where workspace='${a}' and id='${aFile}';`)
  const fpB = sql(`select encode(fingerprint,'hex') from sectalk_private.st_v6_workspace_files where workspace='${b}' and id='${bFile}';`)
  assert.match(fpA, /^[0-9a-f]{64}$/)
  assert.match(fpB, /^[0-9a-f]{64}$/)
  assert.notEqual(fpA, fpB)
  assert.equal((await get(beta, a, aFile)).status, 404)
  assert.equal((await get(beta, b, aFile)).status, 404)
  assert.ok((await teammate.client.storage.from(bucket).download(objectPath(a, aFile))).error)
  const publicObject = new URL('/storage/v1/object/public/' + bucket + '/' + objectPath(a, aFile), supabase)
  assert.ok(!(await fetch(publicObject)).ok)
  const rows = await (await list(teammate, a)).json()
  assert.deepEqual(Object.keys(rows[0]).sort(), ['can_remove', 'filename', 'id', 'size_bytes'])
  const saved = teamView.page.waitForEvent('download')
  await teamView.panel.getByRole('article').filter({ hasText: 'first-alpha.txt' }).getByRole('button', { name: 'Download file' }).click()
  assert.deepEqual(await readFile(await (await saved).path()), same)
  assert.equal((await request(workspacePath(a, aFile), { method: 'DELETE', headers: auth(teammate) })).status, 404)

  const old = randomUUID()
  objects.push(objectPath(a, old))
  data(await admin.storage.from(bucket).upload(objectPath(a, old), legacy, { contentType: 'application/octet-stream' }))
  sql(`insert into sectalk_private.st_v6_workspace_files(workspace,id,uploader,filename,size_bytes,created_at,published_at)
    values('${a}','${old}','${alpha.id}','stored-before-index.txt',${legacy.length},now()-interval '2 days',now()-interval '2 days');`)
  assert.deepEqual(Buffer.from(await (await get(teammate, a, old)).arrayBuffer()), legacy)
  assert.equal((await maintain(alpha.token)).status, 401)
  const indexed = await maintain(process.env.SECTALK_FILE_PURGE_SECRET)
  assert.equal(indexed.status, 200)
  assert.ok((await indexed.json()).indexed >= 1)
  const scoped = createHash('sha256').update('workspace-file:' + a + ':' + createHash('sha256').update(legacy).digest('hex')).digest('hex')
  assert.equal(sql(`select encode(fingerprint,'hex') from sectalk_private.st_v6_workspace_files where workspace='${a}' and id='${old}';`), scoped)
  await submit(ownerView, a, 'match-existing.txt', legacy, true)
  await submit(betaView, b, 'same-existing-other-tenant.txt', legacy, false)

  const parallel = Buffer.from('Concurrent clean workspace bytes ' + run)
  const results = await Promise.all([upload(alpha, a, 'concurrent-a.txt', parallel), upload(teammate, a, 'concurrent-b.txt', parallel)])
  assert.deepEqual(results.map(result => result.status), [200, 200])
  const advisories = await Promise.all(results.map(result => result.json()))
  assert.equal(advisories.filter(result => result.duplicate).length, 1)

  ownerView.page.once('dialog', dialog => dialog.accept())
  await ownerView.panel.getByRole('article').filter({ hasText: 'first-alpha.txt' }).getByRole('button', { name: 'Remove file' }).click()
  await ownerView.panel.getByText('Workspace file removed.', { exact: true }).waitFor()
  assert.equal((await get(teammate, a, aFile)).status, 404)
  assert.deepEqual(Buffer.from(await (await get(teammate, a, repeat)).arrayBuffer()), same)
  assert.deepEqual(Buffer.from(await (await get(beta, b, bFile)).arrayBuffer()), same)
  const swept = await maintain(process.env.SECTALK_FILE_PURGE_SECRET)
  assert.equal(swept.status, 200)
  assert.ok((await swept.json()).purged >= 1)
  assert.ok((await admin.storage.from(bucket).download(objectPath(a, aFile))).error)

  sql(`update public.st_v2_members set suspended_at=now() where workspace_id='${a}' and user_id='${teammate.id}';`)
  assert.equal((await list(teammate, a)).status, 404)
  assert.equal((await get(teammate, a, repeat)).status, 404)
  console.log('Workspace duplicate detection passed in Edge for two tenants, separate bytes, existing-file backfill, concurrency and revoked access.')
} finally {
  await browser?.close()
  if (objects.length) data(await admin.storage.from(bucket).remove([...new Set(objects)]))
  if (directFiles.length) {
    data(await admin.storage.from('sectalk-chat-files').remove(directFiles))
    const ids = directFiles.map(id => "'" + id + "'").join(',')
    sql(`delete from public.st_messages where id in (${ids}); delete from public.st_v5_files where id in (${ids});`)
  }
  if (directChat) sql(`delete from public.st_chats where id='${directChat}';`)
  for (const workspace of spaces) {
    sql(`delete from sectalk_private.st_v6_workspace_files where workspace='${workspace}';
      delete from sectalk_private.st_v6_workspace_file_history_subjects where workspace='${workspace}';
      delete from public.st_v2_workspaces where id='${workspace}';`)
  }
  for (const actor of accounts) data(await admin.auth.admin.deleteUser(actor))
}
