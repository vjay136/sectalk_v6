import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { verifyStaffPanel } from './workspace-admin-fixture.mjs'

const origin = new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
const app = new URL(process.env.SECTALK_STORAGE_TEST_APP).origin
assert.equal(origin,'http://127.0.0.1:55321')
assert.equal(new URL(app).hostname,'127.0.0.1')
const key = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const options = { auth:{persistSession:false,autoRefreshToken:false} }
const service = createClient(origin,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const run = randomUUID().slice(0,8)
const password = randomUUID() + '!1A'
const users = []
let browser,chat,workspace,reportId
function data(result) {
  if (result.error) throw result.error
  return result.data
}
function sql(statement) {
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true}).trim()
}
async function account(role) {
  const handle = 'sr_' + role + '_' + run
  const email = handle + '@example.invalid'
  const { user } = data(await service.auth.admin.createUser({email,password,email_confirm:true}))
  users.push(user.id)
  const client = createClient(origin,key,options)
  const { session } = data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:'Threat QA ' + role}))
  return {id:user.id,email,handle,client,headers:{Authorization:'Bearer ' + session.access_token}}
}
const file = randomUUID()
const room = randomUUID()
const quarantinedPost = randomUUID()
const filename = 'soc-quarantine-' + run + '.txt'
const bytes = Buffer.from('Harmless reported attachment for ' + run)
const domain = 'soc-' + run + '.example.invalid'
const exactHost = 'edge-' + run + '.example.invalid'
const exactUrl = 'https://' + exactHost + '/Specific'
const sharePassword = randomUUID()
const rationale = 'Verified synthetic evidence in the scoped case.'
const nav = page => page.getByRole('navigation',{name:'SecTalk features'})
const tabs = page => page.getByRole('group',{name:'Safety center sections'})
const responsePanel = page => page.getByRole('region',{name:'SOC response requests',exact:true})
const post = (path,headers,value) => fetch(new URL(path,app),{
  method:'POST', headers:{...headers,'Content-Type':'application/json'},body:JSON.stringify(value),
})

async function open(page,actor) {
  await page.goto(app)
  await page.getByLabel('Email address',{exact:true}).fill(actor.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await nav(page).getByRole('button',{name:'Safety',exact:true}).click()
  await tabs(page).getByRole('button',{name:'Threat triage',exact:true}).click()
  await verifyStaffPanel(page)
  await page.getByRole('region',{name:'Threat triage',exact:true}).waitFor()
  const token = await page.evaluate(() => {
    const entry = Object.keys(localStorage).find(name => /^sb-.+-auth-token$/.test(name))
    return JSON.parse(localStorage.getItem(entry)).access_token
  })
  return createClient(origin,key,{...options,global:{headers:{Authorization:'Bearer '+token}}})
}
async function propose(panel,actionKey) {
  await panel.getByLabel('Response action',{exact:true}).selectOption(actionKey)
}
async function send(panel) {
  await panel.getByLabel('Request reason',{exact:true}).fill(rationale)
  const submitted=panel.page().waitForResponse(response =>
    response.url().endsWith('/rpc/st_v7_request_soc_response'),{timeout:12000})
  await panel.getByRole('button',{name:'Request SOC response',exact:true}).click()
  const response=await submitted
  assert.equal(response.status(),200,await response.text())
  await panel.getByText('Response sent for separate approval.',{exact:true}).waitFor()
}
async function approve(panel,requestId) {
  await panel.getByRole('button',{name:'Refresh response requests',exact:true}).click()
  const row = panel.locator('[data-soc-response="' + requestId + '"]')
  await row.getByLabel('Response decision',{exact:true}).selectOption('approve')
  await row.getByLabel('Decision reason',{exact:true}).fill(rationale)
  await row.getByRole('button',{name:'Apply response decision',exact:true}).click()
  await row.getByText(/Executed/).waitFor()
}
try {
  const [author,approver,outside,owner,reporter] = await Promise.all(['ask','approve','outside','owner','reporter'].map(account))
  sql(`insert into sectalk_private.staff values('${author.id}'),('${approver.id}');
    insert into sectalk_private.st_v7_threat_reviewers values
      ('${author.id}','detection'),('${approver.id}','detection'),('${outside.id}','attachment_inspection');
    insert into sectalk_private.st_v7_abuse_blocklist_operators values('${author.id}'),('${approver.id}');
    insert into sectalk_private.st_v7_soc_response_grants(actor,action,role) values
      ('${author.id}','quarantine_file','requester'),('${author.id}','quarantine_file','approver'),
      ('${approver.id}','quarantine_file','approver'),('${author.id}','block_domain','requester'),
      ('${approver.id}','block_domain','approver'),('${author.id}','block_url','requester'),
      ('${approver.id}','block_url','approver');`)
  workspace = data(await author.client.rpc('st_v2_create_workspace',{p_name:'Response workspace ' + run}))
  sql(`insert into public.st_v2_members(workspace_id,user_id,role) values
      ('${workspace}','${approver.id}','admin'),('${workspace}','${owner.id}','member'),('${workspace}','${reporter.id}','member');
    insert into public.st_v6_rooms(id,workspace_id,name,kind,template,creator)
      values('${room}','${workspace}','Response test room','private','blank','${author.id}');
    insert into public.st_v6_room_members(room_id,user_id,role)
      values('${room}','${author.id}','owner'),('${room}','${approver.id}','moderator'),
        ('${room}','${owner.id}','member'),('${room}','${reporter.id}','member');
    insert into sectalk_private.st_v7_soc_response_grants(actor,action,workspace,role) values
      ('${author.id}','lock_room','${workspace}','requester'),('${approver.id}','lock_room','${workspace}','approver'),
      ('${author.id}','quarantine_room_post','${workspace}','requester'),('${approver.id}','quarantine_room_post','${workspace}','approver');`)
  chat = data(await owner.client.rpc('st_request',{p_handle:reporter.handle}))
  data(await reporter.client.rpc('st_respond',{p_chat:chat,p_accept:true}))
  sql(`insert into public.st_messages(id,chat_id,sender,body) values('${file}','${chat}','${owner.id}','Attachment for SOC review');
    insert into public.st_v5_files(id,chat_id,uploader,filename,size_bytes,message_id)
      values('${file}','${chat}','${owner.id}','${filename}',${bytes.length},'${file}');`)
  data(await service.storage.from('sectalk-chat-files').upload(file,bytes,{contentType:'application/octet-stream'}))
  reportId = data(await reporter.client.rpc('st_v5_report',{
    p_chat:chat,p_message:file,p_category:'other',p_details:'The attachment can be shared with Safety.',p_share_file:true,
  }))
  const shareToken = data(await owner.client.rpc('st_v6_create_file_share',{
    p_file:file,p_password:sharePassword,p_seconds:900,p_downloads:2,
  }))
  const share = () => post('/api/files/share',{}, {token:shareToken,password:sharePassword,action:'view'})
  const download = actor => post('/api/files/download',actor.headers,{file})
  const preview = () => fetch(new URL('/api/files/preview?file='+file,app),{headers:reporter.headers})
  assert.equal((await share()).status,200)
  const original = await download(reporter)
  assert.equal(original.status,200,await original.clone().text())
  assert.equal((await preview()).status,200)

  browser = await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const authorPage = await browser.newPage()
  const approvalPage = await browser.newPage()
  const outsidePage = await browser.newPage()
  const authorApi = await open(authorPage,author)
  await tabs(authorPage).getByRole('button',{name:'Staff console',exact:true}).click()
  await authorPage.getByRole('button',{name:new RegExp('@'+owner.handle)}).click()
  const casePanel = authorPage.getByRole('region',{name:'Reported case response request',exact:true})
  await propose(casePanel,'quarantine_file:')
  await send(casePanel)
  const liveId = action => sql(`select id from sectalk_private.st_v7_soc_responses where requester='${author.id}' and action='${action}';`)
  const fileRequest = liveId('quarantine_file')
  assert.equal((await authorApi.rpc('st_v7_decide_soc_response',{p_id:fileRequest,p_approve:true,p_reason:rationale})).error?.code,'42501')
  assert.equal((await download(reporter)).status,200)

  const approverApi = await open(approvalPage,approver)
  const outsideApi = await open(outsidePage,outside)
  assert.deepEqual(data(await outsideApi.rpc('st_v7_soc_response_queue')),[])
  assert.equal((await outsideApi.rpc('st_v7_decide_soc_response',{p_id:fileRequest,p_approve:true,p_reason:rationale})).error?.code,'42501')
  const ticket = (await (await download(reporter)).json()).url
  assert.ok(ticket)
  const beforeApproval = Date.now()
  await approve(responsePanel(approvalPage),fileRequest)
  assert.equal(data(await approverApi.rpc('st_v7_decide_soc_response',{p_id:fileRequest,p_approve:true,p_reason:rationale})),'executed')
  assert.equal((await download(reporter)).status,404)
  assert.equal((await preview()).status,404)
  assert.equal((await share()).status,404)
  assert.ok(Date.now()-beforeApproval<29000,'Existing ticket must still be within its validity window')
  assert.equal((await fetch(new URL(ticket,app),{headers:reporter.headers})).status,404)
  const evidenceHeaders = {
    Authorization:'Bearer ' + await approvalPage.evaluate(() => JSON.parse(localStorage.getItem(
      Object.keys(localStorage).find(name => /^sb-.+-auth-token$/.test(name)))).access_token),
  }
  const evidenceGrant = await post('/api/files/download',evidenceHeaders,{file})
  assert.equal(evidenceGrant.status,200)
  const evidence = await fetch(new URL((await evidenceGrant.json()).url,app),{headers:evidenceHeaders})
  assert.equal(evidence.status,200)
  assert.deepEqual(Buffer.from(await evidence.arrayBuffer()),bytes)
  assert.deepEqual(Buffer.from(await data(await service.storage.from('sectalk-chat-files').download(file)).arrayBuffer()),bytes)
  assert.equal(sql(`select count(*) from sectalk_private.audit where report_id='${reportId}' and action='attachment_quarantined';`),'1')

  await tabs(authorPage).getByRole('button',{name:'Threat triage',exact:true}).click()
  const requestPanel = responsePanel(authorPage)
  await propose(requestPanel,'block_domain:')
  await requestPanel.getByLabel('Domain to block',{exact:true}).fill(domain)
  await send(requestPanel)
  assert.equal(sql(`select sectalk_private.st_v7_domain_blocked('${domain}');`),'f')
  await approve(responsePanel(approvalPage),liveId('block_domain'))
  assert.equal(sql(`select sectalk_private.st_v7_domain_blocked('${domain}');`),'t')

  await propose(requestPanel,'block_url:')
  await requestPanel.getByLabel('URL path to block',{exact:true}).fill(exactUrl.replace('/Specific','/%53pecific')+'?case=synthetic')
  await send(requestPanel)
  const policy = async url => (await post('/api/safety/url-inspection',reporter.headers,{url,policyOnly:true})).json()
  assert.deepEqual(await policy(exactUrl),{allowed:true,recordedRisk:false})
  await approve(responsePanel(approvalPage),liveId('block_url'))
  assert.deepEqual(await policy(exactUrl+'?different=1'),{allowed:false,recordedRisk:true})
  assert.deepEqual(await policy(exactUrl+'/neighbor'),{allowed:true,recordedRisk:false})
  assert.equal((await policy(exactUrl.replace('Specific','specific'))).allowed,true)
  assert.equal((await (await post('/api/safety/url-inspection',reporter.headers,{url:exactUrl})).json()).outcome,'blocked')

  data(await authorApi.rpc('st_v6_room_post',{
    p_room:room,p_id:randomUUID(),p_kind:'message',p_body:'[Blocked page]('+exactUrl+') [Neighboring page]('+exactUrl+'/neighbor)',
  }))
  await authorPage.context().route('https://'+exactHost+'/**',route => route.fulfill({body:'Simulated neighboring page'}))
  await nav(authorPage).getByRole('button',{name:'Rooms',exact:true}).click()
  await authorPage.getByRole('button',{name:/Response test room/}).click()
  await authorPage.getByRole('button',{name:/Blocked page/}).click()
  await authorPage.getByText('Recorded risk. SecTalk Safety blocked this exact address.',{exact:true}).waitFor()
  const popup = authorPage.waitForEvent('popup')
  await authorPage.getByRole('button',{name:/Neighboring page/}).click()
  const allowedPopup = await popup
  await allowedPopup.getByText('Simulated neighboring page',{exact:true}).waitFor()
  await allowedPopup.close()

  const roomEvidence = 'Benign workspace post shared with its authorized reviewers.'
  data(await owner.client.rpc('st_v6_room_post',{p_room:room,p_id:quarantinedPost,p_kind:'message',p_body:roomEvidence}))
  const roomReport = data(await reporter.client.rpc('st_v6_submit_room_report',{
    p_room:room,p_post:quarantinedPost,p_category:'other',p_details:'Synthetic post report',p_share:true,
  }))
  sql(`update sectalk_private.st_v6_room_reports set handed_off_at=clock_timestamp(),status='reviewing' where id='${roomReport}';
    insert into sectalk_private.st_v6_room_report_stages(report_id,stage,assignee,assigned_at,acknowledge_by,action_by,acknowledged_at)
      values('${roomReport}',3,'${author.id}',now(),now()+interval '1 hour',now()+interval '1 day',now());`)
  await nav(authorPage).getByRole('button',{name:'Safety',exact:true}).click()
  await tabs(authorPage).getByRole('button',{name:'Workspace report review',exact:true}).click()
  await authorPage.getByRole('button',{name:/Other · Response test room/}).click()
  const roomCasePanel = authorPage.getByRole('region',{name:'Reported case response request',exact:true})
  await propose(roomCasePanel,'quarantine_room_post:'+workspace)
  await send(roomCasePanel)
  await approve(responsePanel(approvalPage),liveId('quarantine_room_post'))
  await roomCasePanel.getByRole('button',{name:'View retained room evidence'}).click()
  await roomCasePanel.locator('blockquote[aria-label="Retained room evidence"]').getByText(roomEvidence,{exact:true}).waitFor()
  await nav(authorPage).getByRole('button',{name:'Rooms',exact:true}).click()
  await authorPage.getByRole('button',{name:/Response test room/}).click()
  await authorPage.getByText('Message removed',{exact:true}).waitFor()
  await nav(authorPage).getByRole('button',{name:'Safety',exact:true}).click()
  await tabs(authorPage).getByRole('button',{name:'Threat triage',exact:true}).click()

  await propose(requestPanel,'lock_room:'+workspace)
  await requestPanel.getByRole('button',{name:'Load eligible rooms'}).click()
  await requestPanel.getByLabel('Response target').selectOption(room)
  await send(requestPanel)
  assert.equal(sql(`select locked from public.st_v6_rooms where id='${room}';`),'f')
  await approve(responsePanel(approvalPage),liveId('lock_room'))
  assert.equal(sql(`select locked from public.st_v6_rooms where id='${room}';`),'t')
} finally {
  await browser?.close()
  await service.storage.from('sectalk-chat-files').remove([file])
  const actorList = users.length ? users.map(id => "'" + id + "'").join(',') : 'null'
  sql(`begin; set local session_replication_role=replica;
    delete from sectalk_private.st_v7_soc_url_blocks where url_key='${exactUrl}';
    delete from sectalk_private.st_v7_room_quarantine_evidence where post='${quarantinedPost}';
    delete from sectalk_private.st_v7_soc_responses where requester in (${actorList});
    delete from sectalk_private.st_v7_abuse_blocks where value='${domain}';
    commit;`)
  if (chat) sql(`
    delete from sectalk_private.audit where report_id in (select id from public.st_reports where chat_id='${chat}');
    delete from public.st_reports where chat_id='${chat}';
    delete from public.st_v5_files where id='${file}';
    delete from public.st_messages where chat_id='${chat}';
    delete from public.st_chats where id='${chat}';`)
  if (workspace) sql(`delete from sectalk_private.st_v6_room_reports where workspace_id='${workspace}';
    delete from public.st_v2_workspaces where id='${workspace}';`)
  for (const id of users) sql(`delete from sectalk_private.staff where user_id='${id}'; delete from auth.users where id='${id}';`)
}
console.log('Passed attachment quarantine and retained evidence, exact URL blocking and allowed neighbors, consented room post quarantine, room lock, separate approval, and cross-scope denial in Edge.')
