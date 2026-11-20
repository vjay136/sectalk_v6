import assert from 'node:assert/strict'
import {execFileSync} from 'node:child_process'
import {randomUUID} from 'node:crypto'
import {createClient} from '@supabase/supabase-js'
import {verifyStaffPanel} from './workspace-admin-fixture.mjs'

const app=new URL(process.env.SECTALK_STORAGE_TEST_APP)
const backend=new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname,'127.0.0.1')
assert.equal(backend.origin,'http://127.0.0.1:55321')
const options={auth:{persistSession:false,autoRefreshToken:false}}
const service=createClient(backend.href,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
const password=randomUUID()+'!5a'
const suffix=randomUUID().slice(0,8)
const actors=[]
const reportBody='Synthetic spam for consent review '+suffix
const reporterNote='This note stays within the platform team.'
let workspace
let liveReportUpdates=0

function data(result){if(result.error)throw result.error;return result.data}
function sql(statement){
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-q','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'],{input:statement,windowsHide:true})
}

async function account(label){
  const handle=`ch_${label}_${suffix}`
  const email=handle+'@example.invalid'
  const {user}=data(await service.auth.admin.createUser({email,password,email_confirm:true}))
  actors.push(user.id)
  const client=createClient(backend.href,process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:label+' channel QA'}))
  return {id:user.id,client,handle,email}
}

const navigation=page=>page.getByRole('navigation',{name:'SecTalk features'})
async function login(actor){
  const page=await browser.newPage()
  if(actor.handle.startsWith('ch_reporter_'))page.on('websocket',socket=>socket.on('framereceived',message=>{
    if(message.payload.toString().includes('"channel_report_updated"'))liveReportUpdates++
  }))
  await page.goto(app.href)
  await page.getByLabel('Email address',{exact:true}).fill(actor.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await navigation(page).waitFor()
  return page
}

async function safety(page,tab){
  await navigation(page).getByRole('button',{name:'Safety',exact:true}).click()
  if(tab)await page.getByRole('group',{name:'Safety center sections'}).getByRole('button',{name:tab,exact:true}).click()
}

const quarantineReason='Exact consented channel revision independently reviewed.'
const channelName='soc-'+suffix
const olderPost=randomUUID()
let caseId

async function openFeed(page,channel){
  await navigation(page).getByRole('button',{name:'Workspaces',exact:true}).click()
  await page.getByRole('group',{name:'Workspace sections'}).getByRole('button',{name:'Channels',exact:true}).click()
  await page.getByLabel('Channel',{exact:true}).selectOption(channel)
  return page.getByRole('log',{name:'Channel messages',exact:true})
}
async function requestReview(actor){
  const page=await login(actor)
  await safety(page,'Threat triage')
  await verifyStaffPanel(page)
  return page
}

try{
  const [owner,approver,sender,reporter,platform]=await Promise.all(['owner','approve','sender','reporter','platform'].map(account))
  sql(`insert into sectalk_private.staff values('${platform.id}');
    insert into sectalk_private.st_v7_threat_reviewers values ('${owner.id}','detection'),('${approver.id}','detection');`)
  workspace=data(await owner.client.rpc('st_v2_create_workspace',{p_name:'SOC channel workspace '+suffix}))
  const channel=data(await owner.client.rpc('st_v2_create_channel',{p_workspace:workspace,p_name:channelName}))
  sql(`insert into public.st_v2_members(workspace_id,user_id,role) values
      ('${workspace}','${approver.id}','admin'),('${workspace}','${sender.id}','member'),('${workspace}','${reporter.id}','member');
    insert into sectalk_private.st_v7_soc_response_grants(actor,action,workspace,role) values
      ('${owner.id}','quarantine_channel_post','${workspace}','requester'),
      ('${owner.id}','quarantine_channel_post','${workspace}','approver'),
      ('${approver.id}','quarantine_channel_post','${workspace}','approver');`)
  data(await sender.client.rpc('st_v2_post',{p_channel:channel,p_id:olderPost,p_body:reportBody}))
  sql(`update public.st_v2_posts set created_at=now()-interval '20 minutes' where id='${olderPost}';
    insert into public.st_v2_posts(id,channel_id,sender,body)
      select gen_random_uuid(),'${channel}','${sender.id}','Newer synthetic channel fixture '||n from generate_series(1,51) n;`)
  const viewer=await login(reporter)
  const feed=await openFeed(viewer,channel)
  assert.equal(await feed.getByText(reportBody,{exact:true}).count(),0)
  await feed.getByRole('button',{name:'Earlier messages',exact:true}).click()
  const oldArticle=feed.getByRole('article').filter({hasText:reportBody})
  await oldArticle.getByText('Channel message actions',{exact:true}).click()
  await oldArticle.getByRole('button',{name:'Report message',exact:true}).click()
  const reportDialog=viewer.getByRole('dialog',{name:'Report channel message',exact:true})
  await reportDialog.getByLabel('Report category',{exact:true}).selectOption('spam')
  await reportDialog.getByLabel('Report details (optional)',{exact:true}).fill(reporterNote)
  await reportDialog.getByRole('checkbox',{name:'Share this message and my notes with SecTalk Safety',exact:true}).check()
  await reportDialog.getByRole('checkbox',{name:'Allow Safety to share this message with authorized workspace moderators',exact:true}).check()
  await reportDialog.getByRole('button',{name:'Submit channel report',exact:true}).click()
  await viewer.getByRole('status').filter({hasText:'Channel report submitted.'}).waitFor()
  caseId=sql(`copy (select id from sectalk_private.st_v7_channel_reports where post_id='${olderPost}') to stdout;`).toString().trim()
  assert.match(caseId,/^[a-f0-9-]{36}$/)

  const manager=await login(owner)
  await safety(manager,'Workspace report review')
  await verifyStaffPanel(manager)
  const managerQueue=manager.getByRole('region',{name:'Channel report queue',exact:true})
  await managerQueue.getByText('No channel reports are available.',{exact:true}).waitFor()
  const independent=await requestReview(approver)
  const safetyStaff=await login(platform)
  await safety(safetyStaff,'Staff console')
  await verifyStaffPanel(safetyStaff)
  const staffQueue=safetyStaff.getByRole('region',{name:'Channel report queue',exact:true})
  const staffCase=staffQueue.locator('details').filter({hasText:reportBody})
  await staffCase.locator('summary').click()
  await staffCase.getByLabel('Channel review decision').selectOption('handoff')
  await staffCase.getByLabel('Decision reason',{exact:true}).fill('Refer the exact consented message for workspace review.')
  await staffCase.getByRole('button',{name:'Save channel decision',exact:true}).click()
  await staffQueue.getByText('Channel report decision saved.',{exact:true}).waitFor()

  await managerQueue.locator('details').filter({hasText:reportBody}).locator('summary').click()
  await managerQueue.locator('blockquote[aria-label="Consented channel evidence"]').getByText(reportBody,{exact:true}).waitFor()
  const request=managerQueue.getByRole('region',{name:'Reported case response request',exact:true})
  await request.getByLabel('Request reason',{exact:true}).fill('Keep the consented snapshot and hide the reported message.')
  await request.getByRole('button',{name:'Request SOC response',exact:true}).click()
  await request.getByText('Response sent for separate approval.',{exact:true}).waitFor()
  await oldArticle.getByText(reportBody,{exact:true}).waitFor()

  const review=independent.getByRole('region',{name:'SOC response requests',exact:true})
  await review.getByRole('button',{name:'Refresh response requests',exact:true}).click()
  const card=review.getByRole('article').filter({hasText:caseId})
  await card.getByLabel('Response decision',{exact:true}).selectOption('approve')
  await card.getByLabel('Decision reason',{exact:true}).fill(quarantineReason)
  await card.getByRole('button',{name:'Apply response decision',exact:true}).click()
  await card.getByText(/Executed/).waitFor()

  await feed.getByText('Message quarantined',{exact:true}).waitFor()
  assert.equal(await feed.getByText(reportBody,{exact:true}).count(),0)
  await feed.getByText('Newer synthetic channel fixture 1',{exact:true}).waitFor()
  const ordinary=data(await reporter.client.from('st_v2_posts').select('body,quarantined_at').eq('id',olderPost).single())
  assert.equal(ordinary.body,'Message quarantined')
  assert.ok(ordinary.quarantined_at)
  await managerQueue.getByRole('button',{name:'Request SOC response',exact:true}).waitFor()
  await managerQueue.locator('blockquote[aria-label="Consented channel evidence"]').getByText(reportBody,{exact:true}).waitFor()
  await safety(viewer)
  const summary=viewer.getByRole('region',{name:'My channel reports',exact:true})
  await summary.getByText(/Spam.*In review/i).click()
  await summary.getByText('Channel message quarantined',{exact:false}).waitFor()
  assert.equal(await summary.getByText(quarantineReason,{exact:true}).count(),0)
  assert.equal(await summary.getByText(reportBody,{exact:true}).count(),0)
  console.log('Passed actual reporter consent and handoff, separate approval, loaded older feed tombstone, private retained evidence and safe reporter timeline in Edge.')
}finally{
  await browser.close()
  if(caseId)sql(`begin; set local session_replication_role=replica;
    delete from sectalk_private.st_v7_soc_responses where case_id='${caseId}'; commit;`)
  if(workspace)sql(`delete from sectalk_private.st_v7_channel_reports where workspace_id='${workspace}';
    delete from public.st_v2_workspaces where id='${workspace}';`)
  for(const id of actors)sql(`delete from sectalk_private.staff where user_id='${id}'; delete from auth.users where id='${id}';`)
}
