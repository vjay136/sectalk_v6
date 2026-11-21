// Use only the disposable local Auth QA database and a separate operator origin.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { createClient } from '@supabase/supabase-js'
import { fixtureAuthenticator, totpCode } from './workspace-admin-fixture.mjs'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = {auth: {persistSession: false, autoRefreshToken: false}}
const admin = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const {chromium} = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const password = randomUUID() + '1!Q'
const accounts = []
let chat
let secondChat
let report
let attachment

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

function sql(statement) {
  return execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-v', 'ON_ERROR_STOP=1',
    '-At', '-U', 'postgres', '-d', 'postgres'], {input: statement, encoding: 'utf8', windowsHide: true})
}

async function account(role) {
  const handle = 'soc_' + role + '_' + randomUUID().slice(0, 8)
  const email = handle + '@example.invalid'
  const {user} = data(await admin.auth.admin.createUser({email, password, email_confirm: true}))
  assert.match(user.id, /^[a-f0-9-]{36}$/)
  accounts.push(user.id)
  const client = createClient(supabase.origin, publicKey, options)
  data(await client.auth.signInWithPassword({email, password}))
  data(await client.rpc('st_save_profile', {p_handle: handle, p_name: handle}))
  return {user, email, handle, client, factor: await fixtureAuthenticator(client)}
}

function access(token) {
  return fetch(new URL('/api/operator/access', app), {headers: token ? {Authorization: 'Bearer ' + token} : {}})
}

async function login(page, email) {
  const admission = page.waitForResponse(response => response.url().endsWith('/api/operator/access') && response.request().method() === 'GET')
  await page.goto(app.href)
  await page.getByLabel('Email', {exact: true}).fill(email)
  await page.getByLabel('Password', {exact: true}).fill(password)
  await page.getByRole('button', {name: 'Sign in', exact: true}).click()
  return (await admission).json()
}

let browser
try {
  const [operator, ordinary, subject, contact] = await Promise.all([
    account('operator'), account('ordinary'), account('subject'), account('contact'),
  ])
  assert.equal((await access()).status, 401)
  assert.equal((await access('invalid.token.value')).status, 401)
  assert.equal((await access(ordinary.factor.session.access_token)).status, 403)
  const evidence = await fetch(new URL('/api/files/download', app), {method: 'POST',
    headers: {Authorization: 'Bearer ' + ordinary.factor.session.access_token, 'Content-Type': 'application/json'},
    body: JSON.stringify({file: randomUUID()})})
  assert.equal(evidence.status, 403)
  const crossOrigin = await fetch(new URL('/api/auth/sign-in', app), {method: 'POST',
    headers: {Origin: 'https://example.invalid', 'Content-Type': 'application/json'}})
  assert.equal(crossOrigin.status, 403)
  sql(`insert into sectalk_private.staff(user_id) values ('${operator.user.id}');`)
  chat = data(await ordinary.client.rpc('st_request', {p_handle: subject.handle}))
  assert.match(chat, /^[a-f0-9-]{36}$/)
  data(await subject.client.rpc('st_respond', {p_chat: chat, p_accept: true}))
  secondChat = data(await contact.client.rpc('st_request', {p_handle: subject.handle}))
  assert.match(secondChat, /^[a-f0-9-]{36}$/)
  data(await subject.client.rpc('st_respond', {p_chat: secondChat, p_accept: true}))
  attachment = randomUUID()
  const filename = 'synthetic-admin-evidence.txt'
  const bytes = Buffer.from('Synthetic case attachment ' + randomUUID())
  const excerpt = 'Synthetic moderation evidence ' + randomUUID()
  data(await subject.client.rpc('st_v5_stage_file', {p_chat: chat, p_id: attachment, p_filename: filename, p_bytes: bytes.length}))
  data(await admin.storage.from('sectalk-chat-files').upload(attachment, bytes, {contentType: 'application/octet-stream'}))
  const publication = data(await admin.rpc('st_v7_publish_hashed_file', {p_file: attachment, p_actor: subject.user.id,
    p_caption: excerpt, p_hash: createHash('sha256').update(bytes).digest('hex')}))
  report = data(await ordinary.client.rpc('st_v5_report', {p_chat: chat, p_message: publication.id, p_category: 'harassment',
    p_details: 'Standalone moderation test report.', p_share_file: true}))
  assert.match(report, /^[a-f0-9-]{36}$/)
  assert.equal(Boolean((await ordinary.client.rpc('st_v5_case', {p_report: report})).error), true)

  browser = await chromium.launch({executablePath: process.env.SECTALK_TEST_BROWSER})
  const ordinaryPage = await browser.newPage()
  // Sign-in assurance is required before the database allows role checks.
  assert.deepEqual(await login(ordinaryPage, ordinary.email), {access: 'mfa'})
  await ordinaryPage.getByLabel('Authenticator code', {exact: true}).fill(await totpCode(ordinary.factor.secret))
  await ordinaryPage.getByRole('button', {name: 'Verify code', exact: true}).click()
  await ordinaryPage.getByRole('heading', {name: 'Access unavailable'}).waitFor()
  assert.equal(await ordinaryPage.getByRole('heading', {name: 'Moderation queue', exact: true}).count(), 0)
  assert.equal(await ordinaryPage.getByRole('region', {name: 'Queue operations', exact: true}).count(), 0)
  await ordinaryPage.close()

  const page = await browser.newPage({acceptDownloads: true})
  assert.deepEqual(await login(page, operator.email), {access: 'mfa'})
  const mfa = page.getByRole('heading', {name: 'Verify your authenticator'})
  await mfa.waitFor()
  const tabs = page.getByRole('group', {name: 'Operator sections'})
  const queueTab = tabs.getByRole('button', {name: 'Queue operations', exact: true})
  const queue = page.getByRole('region', {name: 'Queue operations', exact: true})
  assert.equal(await queue.count(), 0)
  await page.getByLabel('Authenticator code', {exact: true}).fill(await totpCode(operator.factor.secret))
  await page.getByRole('button', {name: 'Verify code', exact: true}).click()
  await page.getByRole('heading', {name: 'Moderation queue', exact: true}).waitFor()
  assert.equal(await queueTab.count(), 0)
  await page.getByLabel('Report category', {exact: true}).selectOption('harassment')
  await page.getByRole('button', {name: new RegExp('@' + subject.handle)}).click()
  await page.getByText(excerpt, {exact: true}).waitFor()
  const download = page.waitForEvent('download')
  await page.getByRole('button', {name: 'Download shared file', exact: true}).click()
  const downloaded = await download
  assert.equal(downloaded.suggestedFilename(), filename)
  assert.deepEqual(await readFile(await downloaded.path()), bytes)
  await page.getByLabel('Action', {exact: true}).selectOption('warn')
  const decision = 'Synthetic staff warning from standalone console.'
  await page.getByLabel('Reason', {exact: true}).fill(decision)
  await page.getByRole('button', {name: 'Record decision', exact: true}).click()
  await page.getByText('Account warning issued', {exact: true}).waitFor()
  await page.getByText(decision, {exact: true}).waitFor()
  const timeline = data(await ordinary.client.rpc('st_v5_report_timeline', {p_report: report}))
  assert.ok(timeline.some(item => item.action === 'warn'))
  const notices = data(await subject.client.from('st_v5_account_notices').select('action'))
  assert.ok(notices.some(item => item.action === 'warn'))

  const outgoing = (video=false) => subject.client.rpc('st_v6_start_call', {
    p_chat: secondChat, p_video: video, p_device: randomUUID(),
  })
  const send = () => subject.client.rpc('st_send', {p_chat: secondChat, p_id: randomUUID(), p_body: 'Synthetic continuity message'})
  const ringing = data(await outgoing())
  assert.match(ringing, /^[a-f0-9-]{36}$/)
  assert.equal(data(await contact.client.from('st_calls').select('status').eq('id',ringing).single()).status,'ringing')
  assert.equal((await contact.client.rpc('st_v5_moderate',{p_report:report,p_action:'suspend',p_note:'Forbidden change'})).error!==null,true)
  await page.getByLabel('Action',{exact:true}).selectOption('suspend')
  const suspendReason='Synthetic repeated unwanted contact, with case evidence.'
  await page.getByLabel('Reason',{exact:true}).fill(suspendReason)
  await page.getByRole('button',{name:'Record decision',exact:true}).click()
  await page.getByText('24-hour suspension',{exact:true}).waitFor()
  await page.getByText(suspendReason,{exact:true}).waitFor()
  assert.equal(data(await contact.client.from('st_calls').select('status').eq('id',ringing).single()).status,'ended')
  assert.ok((await send()).error)
  assert.ok((await outgoing()).error)
  assert.ok((await outgoing(true)).error)
  assert.ok(data(await ordinary.client.rpc('st_v5_report_timeline',{p_report:report})).some(item=>item.action==='suspend'))
  await page.getByLabel('Action',{exact:true}).selectOption('restore')
  const restoreReason='Synthetic independent review completed and restriction lifted.'
  await page.getByLabel('Reason',{exact:true}).fill(restoreReason)
  await page.getByRole('button',{name:'Record decision',exact:true}).click()
  await page.getByText('Restriction lifted',{exact:true}).waitFor()
  await page.getByText(restoreReason,{exact:true}).waitFor()
  data(await send())
  const restoredCall=data(await outgoing(true))
  assert.match(restoredCall,/^[a-f0-9-]{36}$/)
  assert.equal(data(await contact.client.from('st_calls').select('status').eq('id',restoredCall).single()).status,'ringing')
  assert.ok(data(await ordinary.client.rpc('st_v5_report_timeline',{p_report:report})).some(item=>item.action==='restore'))

  const staffReason='Synthetic private case notes remain in the operator audit.'
  const reporterSummary='We reviewed the report and closed this case after taking appropriate action.'
  await page.getByLabel('Action',{exact:true}).selectOption('resolved')
  await page.getByLabel('Reason',{exact:true}).fill(staffReason)
  const summaryField=page.getByLabel('Summary for reporter',{exact:true})
  assert.equal(await summaryField.getAttribute('required'),'')
  await summaryField.fill(reporterSummary)
  await page.getByRole('button',{name:'Record decision',exact:true}).click()
  await page.getByText(staffReason,{exact:true}).waitFor()
  const resolution=data(await ordinary.client.rpc('st_v8_my_message_report_timeline',{p_report:report}))
  assert.deepEqual(resolution.filter(item=>item.summary).map(item=>[item.action,item.summary]),[['resolved',reporterSummary]])
  assert.ok(!JSON.stringify(resolution).includes(staffReason))
  for(const actor of [subject,contact]) {
    assert.deepEqual(data(await actor.client.rpc('st_v8_my_message_report_timeline',{p_report:report})),[])
  }

  sql(`insert into sectalk_private.st_v6_queue_operators(account_id) values ('${operator.user.id}');`)
  await queueTab.click({timeout: 20000})
  await queue.waitFor()
  await queue.getByRole('button', {name: 'Service health and SLOs', exact: true}).click()
  await queue.getByText('API and database readiness ready.', {exact: true}).waitFor()
  await queue.getByRole('table', {name: 'Service objectives', exact: true}).waitFor()

  sql(`update auth.mfa_amr_claims set updated_at=now()-interval '11 minutes'
    where session_id in (select id from auth.sessions where user_id='${operator.user.id}') and authentication_method='totp';`)
  await mfa.waitFor({timeout: 20000})
  assert.equal(await queue.count(), 0)
  await page.getByLabel('Authenticator code', {exact: true}).fill(await totpCode(operator.factor.secret))
  await page.getByRole('button', {name: 'Verify code', exact: true}).click()
  await queue.waitFor()

  sql(`delete from sectalk_private.st_v6_queue_operators where account_id='${operator.user.id}';`)
  await queueTab.waitFor({state: 'hidden', timeout: 20000})
  await page.getByRole('heading', {name: 'Moderation queue', exact: true}).waitFor()
  sql(`delete from sectalk_private.staff where user_id='${operator.user.id}';`)
  await page.getByRole('heading', {name: 'Access unavailable'}).waitFor({timeout: 20000})
  assert.equal(await page.getByRole('heading', {name: 'Moderation queue', exact: true}).count(), 0)
  assert.equal(await queue.count(), 0)
  await page.getByRole('button', {name: 'Sign out', exact: true}).click()
  await page.getByRole('heading', {name: 'Operator sign-in'}).waitFor()
  console.log('PASS operator authentication, consented evidence, reporter-only resolution and private audit, warning and cross-chat call/message restriction and restoration, queue health, TOTP expiry and role revocation')
} finally {
  await browser?.close()
  if (report) sql(`delete from sectalk_private.audit where report_id='${report}';
    delete from public.st_reports where id='${report}';`)
  if (attachment) {
    data(await admin.storage.from('sectalk-chat-files').remove([attachment]))
    sql(`delete from sectalk_private.st_v6_file_downloads where file_id='${attachment}';
      delete from public.st_v5_files where id='${attachment}';`)
  }
  for(const id of [chat,secondChat].filter(Boolean)) sql(`delete from public.st_messages where chat_id='${id}';
    delete from public.st_calls where chat_id='${id}'; delete from public.st_chats where id='${id}';`)
  for (const id of accounts) {
    sql(`delete from sectalk_private.st_v6_queue_operators where account_id='${id}';
      delete from sectalk_private.staff where user_id='${id}';`)
    data(await admin.auth.admin.deleteUser(id))
  }
}
