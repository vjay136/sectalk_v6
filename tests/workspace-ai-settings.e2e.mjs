import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const service = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.origin, 'http://127.0.0.1:3510')
assert.equal(service.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(service.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const suffix = randomUUID().slice(0, 8)
const password = randomUUID() + '1!Q'
const participants = []
let workspace
let browser

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}
function sql(statement) {
  return execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-At', '-v', 'ON_ERROR_STOP=1',
    '-U', 'postgres', '-d', 'postgres'], { input: statement, encoding: 'utf8', windowsHide: true }).trim()
}
async function account(stem, name) {
  const handle = stem + '_' + suffix
  const email = handle + '@example.invalid'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  assert.match(user.id, /^[a-f0-9-]{36}$/)
  participants.push(user.id)
  const client = createClient(service.origin, process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY, options)
  const { session } = data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: name }))
  return { id: user.id, name, handle, email, client, token: session.access_token }
}
function post(actor, route, body) {
  return fetch(new URL(route, app), {
    method: 'POST', headers: { Authorization: 'Bearer ' + actor.token, 'Content-Type': 'application/json' },
    ...(body ? { body: JSON.stringify(body) } : {}),
  })
}

try {
  const [owner, manager, member] = await Promise.all([
    account('aipol_owner', 'Avery Birch'),
    account('aipol_admin', '\u0391very Birch'),
    account('aipol_member', 'Ordinary workspace member'),
  ])
  workspace = data(await owner.client.rpc('st_v2_create_workspace', { p_name: 'Workspace AI fixture ' + suffix }))
  assert.match(workspace, /^[a-f0-9-]{36}$/)
  for (const person of [manager, member]) {
    data(await owner.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: person.handle }))
    const invitation = data(await person.client.from('st_v2_invites').select('id').eq('workspace_id', workspace).single())
    data(await person.client.rpc('st_v2_reply_invite', { p_invite: invitation.id, p_accept: true }))
  }
  sql("update public.st_v2_members set role='admin' where workspace_id='" + workspace + "' and user_id='" + manager.id + "';")
  assert.equal((await member.client.rpc('st_v7_workspace_ai_settings', { p_workspace: workspace })).error?.code, '42501')
  assert.equal((await manager.client.rpc('st_v7_workspace_ai_settings', {
    p_workspace: workspace, p_enabled: false, p_processing_consent: false, p_advisory_threshold: 1, p_retention_days: 30,
  })).error?.code, '42501')
  data(await owner.client.rpc('st_v6_set_impersonation_watch', { p_workspace: workspace, p_member: owner.id, p_tier: 'executive' }))
  const room = randomUUID()
  const root = randomUUID()
  const meeting = randomUUID()
  const title = 'AI retention fixture ' + suffix
  const oldText = 'The older travel schedule was confirmed.'
  const recentText = 'The recent engineering schedule is ready.'
  data(await owner.client.rpc('st_v6_room_create', { p_workspace: workspace, p_id: room, p_name: 'Workspace AI room',
    p_kind: 'public', p_template: 'blank' }))
  data(await owner.client.rpc('st_v6_room_post', { p_room: room, p_id: root, p_body: 'The reviewed checklist is ready.',
    p_kind: 'message', p_parent: null }))
  sql(`
    insert into public.st_v3_meetings(id,workspace_id,host_id,title,status,starts_at,ends_at)
      values('${meeting}','${workspace}','${owner.id}','${title}','ended',now()-interval '26 hours',now()-interval '22 hours');
    insert into sectalk_private.st_v6_caption_session(meeting,source_language,expires_at,line_count)
      values('${meeting}','en',now()-interval '22 hours',2);
    insert into sectalk_private.st_v6_caption_consent(meeting,actor,participant_sid)
      values('${meeting}','${owner.id}','PA_fixture_owner'),('${meeting}','${manager.id}','PA_fixture_admin');
    insert into sectalk_private.st_v6_caption_line(meeting,actor,sequence,speaker,line,spoken_at) values
      ('${meeting}','${owner.id}',1,'Avery Birch','${oldText}',now()-interval '25 hours'),
      ('${meeting}','${owner.id}',2,'Avery Birch','${recentText}',now()-interval '23 hours');
  `)
  const meetingCommand = (person, action, fields = {}) => post(person, '/api/meetings/summaries', { meeting, action, ...fields })
  const threadCommand = (person, action, enabled) => {
    const query = new URLSearchParams({ room, thread: root, action })
    if (enabled !== undefined) query.set('enabled', String(enabled))
    return post(person, '/api/rooms/thread-summary?' + query)
  }
  assert.equal((await meetingCommand(owner, 'policy', { enabled: true })).status, 200)
  assert.equal((await meetingCommand(owner, 'opt-in')).status, 200)
  assert.equal((await meetingCommand(manager, 'generate')).status, 403)
  assert.equal((await meetingCommand(manager, 'opt-in')).status, 200)
  assert.equal((await threadCommand(owner, 'policy', true)).status, 200)
  assert.equal((await threadCommand(owner, 'opt-in')).status, 200)
  assert.equal((await threadCommand(owner, 'generate')).status, 200)

  browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
  const nav = page => page.getByRole('navigation', { name: 'SecTalk features' })
  async function open(person) {
    const page = await browser.newPage({ locale: 'en-US' })
    await page.goto(app.href)
    await page.getByLabel('Email address', { exact: true }).fill(person.email)
    await page.getByLabel('Password', { exact: true }).fill(password)
    await page.locator('button.submit-auth').click()
    await nav(page).getByRole('button', { name: 'Workspaces', exact: true }).click()
    await page.getByRole('group', { name: 'Workspace sections', exact: true }).waitFor()
    return page
  }
  const [a, b] = await Promise.all([open(owner), open(manager)])
  const tab = (page, name) => page.getByRole('group', { name: 'Workspace sections', exact: true })
    .getByRole('button', { name, exact: true })
  const policy = page => page.getByRole('region', { name: 'Workspace AI settings', exact: true })
  const openAI = page => tab(page, 'AI settings').click()
  const save = async page => {
    await policy(page).getByRole('button', { name: 'Save AI settings', exact: true }).click()
    await policy(page).getByText('Workspace AI settings saved.', { exact: true }).waitFor()
  }
  await Promise.all([openAI(a), openAI(b)])
  await policy(b).getByText('Only the workspace owner can change these settings.', { exact: true }).waitFor()
  assert.ok(await policy(b).getByLabel('Transcript retention in days').isDisabled())
  assert.equal(await policy(b).getByRole('button', { name: 'Save AI settings', exact: true }).count(), 0)
  await tab(a, 'Impersonation watch').click()
  const watch = a.getByRole('region', { name: 'Impersonation watch', exact: true })
  await watch.getByText('Similar-looking display name', { exact: true }).waitFor()
  await openAI(a)
  await policy(a).getByLabel('Impersonation advisory sensitivity').selectOption('3')
  await save(a)
  await tab(a, 'Impersonation watch').click()
  await watch.getByText('No similar profiles found in the active workspace roster.', { exact: true }).waitFor()

  const meetingURL = new URL(app)
  meetingURL.searchParams.set('meeting', meeting)
  await b.goto(meetingURL.href)
  await b.getByRole('heading', { name: title, exact: true }).waitFor()
  const transcript = b.getByRole('region', { name: 'Meeting transcript', exact: true })
  await transcript.getByRole('listitem').filter({ hasText: oldText }).waitFor()
  await transcript.getByRole('listitem').filter({ hasText: recentText }).waitFor()
  const summary = b.getByRole('region', { name: 'Meeting summary', exact: true })
  await summary.getByRole('button', { name: 'Generate summary draft', exact: true }).click()
  await summary.getByLabel('Summary text').waitFor()

  await openAI(a)
  await policy(a).getByLabel('Allow processing of opted-in content').uncheck()
  await policy(a).getByLabel('Transcript retention in days').fill('1')
  await save(a)
  await b.getByText('Captions and saved transcripts are unavailable under workspace AI settings.', { exact: true }).waitFor()
  await summary.getByText('Meeting summaries are unavailable under workspace AI settings.', { exact: true }).waitFor()
  assert.equal(await summary.getByLabel('Summary text').count(), 0)
  assert.equal((await threadCommand(owner, 'generate')).status, 403)
  assert.equal((await meetingCommand(manager, 'generate')).status, 403)

  await policy(a).getByLabel('Enable managed AI features').uncheck()
  await policy(a).getByLabel('Allow processing of opted-in content').check()
  await save(a)
  assert.equal((await threadCommand(owner, 'generate')).status, 403)
  await tab(a, 'Impersonation watch').click()
  await watch.getByText('Impersonation advisories are disabled in workspace AI settings.', { exact: true }).waitFor()

  await openAI(a)
  await policy(a).getByLabel('Enable managed AI features').check()
  await policy(a).getByLabel('Transcript retention in days').fill('90')
  await save(a)
  await transcript.getByRole('listitem').filter({ hasText: recentText }).waitFor()
  assert.equal(await transcript.getByRole('listitem').filter({ hasText: oldText }).count(), 0)
  const regenerated = await meetingCommand(manager, 'generate')
  assert.equal(regenerated.status, 200)
  const generated = await regenerated.json()
  assert.ok(generated.draft.summary.includes(recentText))
  assert.ok(!generated.draft.summary.includes(oldText))
  assert.equal((await threadCommand(owner, 'generate')).status, 200)
  console.log('PASS: two actual Edge sessions, owner/admin controls, advisory threshold, managed processing denial, editor invalidation and nonresurrecting retention')
} finally {
  await browser?.close()
  if (workspace) sql("delete from public.st_v2_workspaces where id='" + workspace + "';")
  await Promise.allSettled(participants.map(id => admin.auth.admin.deleteUser(id)))
}
