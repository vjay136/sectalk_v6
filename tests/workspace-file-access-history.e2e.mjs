import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHmac, randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { setTimeout } from 'node:timers/promises'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const key = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const service = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const suffix = randomUUID().slice(0, 8)
const password = randomUUID() + '!1Q'
const file = randomUUID()
const filename = 'workspace-audit-' + suffix + '.txt'
const bytes = Buffer.from('Benign file access history fixture ' + suffix)
const actors = []
let workspace
let browser

function data(result) {
  if (result.error) throw result.error
  return result.data
}
function sql(statement) {
  return execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-At', '-v', 'ON_ERROR_STOP=1',
    '-U', 'postgres', '-d', 'postgres'], { input: statement, encoding: 'utf8', windowsHide: true }).trim()
}
async function account(role) {
  const handle = 'wsh_' + role + '_' + suffix
  const name = 'History QA ' + role
  const email = handle + '@example.invalid'
  const { user } = data(await service.auth.admin.createUser({ email, password, email_confirm: true }))
  actors.push(user.id)
  const client = createClient(supabase.origin, key, options)
  const { session } = data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: name }))
  return { id: user.id, name, email, handle, token: session.access_token, client }
}
async function totp(secret) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bits = [...secret.replace(/=+$/, '').toUpperCase()].map(character =>
    alphabet.indexOf(character).toString(2).padStart(5, '0')).join('')
  const keyBytes = Buffer.from(bits.match(/.{8}/g).map(part => Number.parseInt(part, 2)))
  const left = 30000 - Date.now() % 30000
  if (left < 3000) await setTimeout(left + 50)
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)))
  const mac = createHmac('sha1', keyBytes).update(counter).digest()
  return String((mac.readUInt32BE(mac.at(-1) & 15) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}
const auth = actor => ({ Authorization: 'Bearer ' + actor.token })
const history = client => client.rpc('st_v6_workspace_file_access_history', { p_workspace: workspace, p_file: file })
const request = (actor, method, action) => {
  const query = new URLSearchParams({ workspace, file, ...(action ? { action } : {}) })
  return fetch(new URL('/api/workspace-files?' + query, app), { method, headers: auth(actor) })
}
const upload = actor => fetch(new URL('/api/workspace-files?' + new URLSearchParams({ workspace, file }), app), {
  method: 'POST', headers: { ...auth(actor), 'Content-Type': 'text/plain', 'X-SecTalk-File-Name': filename }, body: bytes,
})
async function signIn(actor) {
  const page = await browser.newPage({ acceptDownloads: true })
  await page.goto(app.href)
  await page.getByLabel('Email address', { exact: true }).fill(actor.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  return page
}
const nav = page => page.getByRole('navigation', { name: 'SecTalk features' })
async function openFiles(page) {
  await nav(page).getByRole('button', { name: 'Workspaces', exact: true }).click()
  await page.getByRole('group', { name: 'Workspace sections' }).getByRole('button', { name: 'Files', exact: true }).click()
  return page.getByRole('region', { name: 'Workspace files', exact: true })
}
async function verify(page) {
  await nav(page).getByRole('button', { name: 'Profile', exact: true }).click()
  await page.getByRole('button', { name: 'Security', exact: true }).click()
  await page.getByRole('button', { name: 'Set up authenticator', exact: true }).click()
  const secret = (await page.locator('.mfa-setup code').textContent()).trim()
  await page.getByLabel('Authenticator code', { exact: true }).fill(await totp(secret))
  await page.getByRole('button', { name: 'Verify authenticator', exact: true }).click()
  await page.getByRole('heading', { name: 'Recovery codes', exact: true }).waitFor()
  const token = await page.evaluate(() => {
    const sessionKey = Object.keys(localStorage).find(name => /^sb-.+-auth-token$/.test(name))
    return JSON.parse(localStorage.getItem(sessionKey)).access_token
  })
  return createClient(supabase.origin, key, { ...options, global: { headers: { Authorization: 'Bearer ' + token } } })
}
async function openHistory(panel) {
  await panel.getByText('Workspace file access history', { exact: true }).click()
  return panel.getByRole('region', { name: 'Selected file activity' })
}

try {
  const owner = await account('owner')
  const uploader = await account('uploader')
  const reader = await account('reader')
  const admin = await account('admin')
  const outsider = await account('outside')
  workspace = data(await owner.client.rpc('st_v2_create_workspace', { p_name: 'Audit workspace ' + suffix }))
  for (const member of [uploader, reader, admin]) {
    data(await owner.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: member.handle }))
    const invitation = data(await member.client.from('st_v2_invites').select('id').eq('workspace_id', workspace).single())
    data(await member.client.rpc('st_v2_reply_invite', { p_invite: invitation.id, p_accept: true }))
  }
  sql(`update public.st_v2_members set role='admin' where workspace_id='${workspace}' and user_id='${admin.id}';`)
  const first = await upload(uploader)
  assert.equal(first.status, 200, await first.text())
  assert.equal(data(await history(owner.client)), null)
  assert.equal(data(await history(admin.client)), null)
  assert.equal(data(await history(reader.client)), null)
  assert.equal(data(await history(outsider.client)), null)
  assert.equal((await request(outsider, 'POST', 'view')).status, 404)
  assert.equal((await request(outsider, 'POST', 'share')).status, 404)
  assert.equal((await request(outsider, 'GET')).status, 404)
  assert.ok((await reader.client.rpc('st_v6_record_workspace_file_access', {
    p_workspace: workspace, p_file: file, p_actor: owner.id, p_event: 'share',
  })).error)
  assert.ok((await owner.client.rpc('st_v6_set_workspace_file_history_policy', { p_workspace: workspace, p_enabled: true })).error)

  browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
  const readerPage = await signIn(reader)
  const readerPanel = await openFiles(readerPage)
  await readerPanel.getByRole('article').filter({ hasText: filename }).getByRole('button', { name: 'View file details' }).click()
  const details = readerPage.getByRole('region', { name: 'Workspace file details' })
  await details.getByRole('heading', { name: filename, exact: true }).waitFor()
  await details.getByRole('button', { name: 'Copy workspace link' }).click()
  const linkField = details.getByRole('textbox', { name: 'Workspace file link' })
  await linkField.waitFor()
  const link = await linkField.inputValue()
  assert.equal(link, new URL('/workspace-file/' + workspace + '/' + file, app).href)
  assert.equal((await request(reader, 'POST', 'view')).status, 200)
  assert.equal((await request(reader, 'POST', 'share')).status, 200)
  const adminPage = await signIn(admin)
  await nav(adminPage).getByRole('button', { name: 'Profile', exact: true }).waitFor()
  await adminPage.goto(link)
  await adminPage.getByRole('heading', { name: filename, exact: true }).waitFor()
  const saving = adminPage.waitForEvent('download')
  await adminPage.getByRole('button', { name: 'Download workspace file' }).click()
  assert.deepEqual(await readFile(await (await saving).path()), bytes)
  const uploaderHistory = data(await history(uploader.client))
  assert.deepEqual([...new Set(uploaderHistory.events.map(entry => entry.event))].sort(), ['download', 'published', 'share', 'view'])
  const shareEvents = uploaderHistory.events.filter(entry => entry.event === 'share')
  assert.ok(shareEvents.every(entry => entry.actor === reader.name))
  assert.equal(uploaderHistory.events.find(entry => entry.event === 'download').actor, admin.name)
  assert.equal(data(await history(reader.client)), null)

  const ownerPage = await signIn(owner)
  await verify(ownerPage)
  const ownerPanel = await openFiles(ownerPage)
  await openHistory(ownerPanel)
  await ownerPanel.getByText('Administrator access is off.', { exact: true }).waitFor()
  await adminPage.goto(app.href)
  const verifiedAdmin = await verify(adminPage)
  const adminPanel = await openFiles(adminPage)
  const adminHistory = await openHistory(adminPanel)
  await adminPanel.getByText('No file history is available to this account.', { exact: true }).waitFor()
  assert.equal(data(await history(verifiedAdmin)), null)
  assert.ok((await verifiedAdmin.rpc('st_v6_set_workspace_file_history_policy', { p_workspace: workspace, p_enabled: true })).error)

  await ownerPanel.getByRole('button', { name: 'Enable administrator file history' }).click()
  await ownerPanel.getByText('Administrator access is enabled.', { exact: true }).waitFor()
  const adminSubject = adminPanel.getByRole('button', { name: filename, exact: true })
  await adminSubject.click()
  await adminHistory.getByText('Workspace link generated', { exact: true }).first().waitFor()
  await adminHistory.getByText('File downloaded', { exact: true }).waitFor()
  assert.equal(data(await history(admin.client)), null)
  assert.ok(data(await history(verifiedAdmin)).events.length >= 4)
  await ownerPanel.getByRole('button', { name: 'Disable administrator file history' }).click()
  await ownerPanel.getByText('Administrator access is off.', { exact: true }).waitFor()
  await adminPage.bringToFront()
  await adminHistory.waitFor({ state: 'detached', timeout: 12000 })
  assert.equal(data(await history(verifiedAdmin)), null)
  assert.equal(sql(`select count(*) from public.st_v2_workspace_audit where workspace_id='${workspace}'
    and event in ('workspace.file_history_enabled','workspace.file_history_disabled');`), '2')

  sql(`update public.st_v2_members set suspended_at=now() where workspace_id='${workspace}' and user_id='${reader.id}';`)
  assert.equal((await request(reader, 'POST', 'view')).status, 404)
  assert.equal((await request(reader, 'GET')).status, 404)
  await readerPage.goto(link)
  await readerPage.getByRole('alert').filter({ hasText: 'Workspace file access is unavailable.' }).waitFor()
  assert.ok(data(await history(uploader.client)).events.some(entry => entry.actor === reader.name))
  assert.equal((await request(uploader, 'DELETE')).status, 204)
  sql(`update sectalk_private.st_v6_workspace_file_events set occurred_at=now()-interval '91 days'
    where workspace='${workspace}' and file_id='${file}' and event='published';`)
  assert.ok(!data(await history(uploader.client)).events.some(entry => entry.event === 'published'))
  const maintenance = await fetch(new URL('/api/workspace-files/maintenance', app), {
    method: 'POST', headers: { Authorization: 'Bearer ' + process.env.SECTALK_FILE_PURGE_SECRET },
  })
  assert.equal(maintenance.status, 200)
  assert.equal(sql(`select count(*) from sectalk_private.st_v6_workspace_file_events
    where workspace='${workspace}' and file_id='${file}' and event='published';`), '0')
  assert.ok((await service.storage.from('sectalk-workspace-files').download(workspace + '/' + file)).error)
  assert.equal((await upload(uploader)).status, 409)
  assert.equal((await request(uploader, 'POST', 'view')).status, 404)
  const retained = data(await history(uploader.client))
  assert.ok(retained.removed_at)
  assert.ok(retained.events.some(entry => entry.event === 'download'))
  const uploaderPage = await signIn(uploader)
  const uploaderPanel = await openFiles(uploaderPage)
  const retainedPanel = await openHistory(uploaderPanel)
  await uploaderPanel.getByRole('button', { name: filename + ' (removed)', exact: true }).click()
  await retainedPanel.getByText('File downloaded', { exact: true }).waitFor()
  console.log('Workspace file history passed in Edge with real views, share link, byte download, verified policy and durable revocation-safe audit.')
} finally {
  await browser?.close()
  if (workspace) {
    data(await service.storage.from('sectalk-workspace-files').remove([workspace + '/' + file]))
    sql(`delete from sectalk_private.st_v6_workspace_files where workspace='${workspace}';
      delete from sectalk_private.st_v6_workspace_file_history_subjects where workspace='${workspace}';
      delete from public.st_v2_workspaces where id='${workspace}';`)
  }
  for (const id of actors) data(await service.auth.admin.deleteUser(id))
}
