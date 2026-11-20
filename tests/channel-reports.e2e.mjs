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
const severeBody='Synthetic severe category fixture '+suffix
const reporterNote='This note stays within the platform team.'
let workspace
let platformActor

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
  if(actor.handle.startsWith('ch_reporter_'))await page.addInitScript(()=>{
    window.sectalkTestReportEvents=0
    const dispatch=EventTarget.prototype.dispatchEvent
    EventTarget.prototype.dispatchEvent=function(event){
      if(event.type==='channel_report_updated')window.sectalkTestReportEvents++
      return Reflect.apply(dispatch,this,[event])
    }
  })
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

try{
  const owner=await account('owner')
  const sender=await account('sender')
  const reporter=await account('reporter')
  const staff=await account('reviewer')
  platformActor=staff.id
  sql(`insert into sectalk_private.staff values('${platformActor}');`)
  workspace=data(await owner.client.rpc('st_v2_create_workspace',{p_name:'Report workspace '+suffix}))
  const channelName='review-'+suffix
  const channel=data(await owner.client.rpc('st_v2_create_channel',{p_workspace:workspace,p_name:channelName}))
  for(const actor of [sender,reporter]){
    data(await owner.client.rpc('st_v2_invite',{p_workspace:workspace,p_handle:actor.handle}))
    const invitations=data(await actor.client.from('st_v2_invites').select('id').eq('workspace_id',workspace))
    data(await actor.client.rpc('st_v2_reply_invite',{p_invite:invitations[0].id,p_accept:true}))
  }
  const message=randomUUID()
  data(await sender.client.rpc('st_v2_post',{p_channel:channel,p_id:message,p_body:reportBody}))
  data(await sender.client.rpc('st_v2_post',{p_channel:channel,p_id:randomUUID(),p_body:severeBody}))
  assert.equal((await reporter.client.rpc('st_v7_submit_channel_report',{p_channel:channel,p_post:message,
    p_category:'spam',p_details:'No consent',p_share_with_safety:false,p_share_with_workspace:false})).error?.code,'22023')

  const page=await login(reporter)
  await navigation(page).getByRole('button',{name:'Workspaces',exact:true}).click()
  await page.getByRole('group',{name:'Workspace sections'}).getByRole('button',{name:'Channels',exact:true}).click()
  await page.getByLabel('Channel',{exact:true}).selectOption(channel)
  const feed=page.getByRole('log',{name:'Channel messages',exact:true})
  async function startReport(text){
    const article=feed.getByRole('article').filter({hasText:text})
    await article.getByText('Channel message actions',{exact:true}).click()
    await article.getByRole('button',{name:'Report message',exact:true}).click()
    return page.getByRole('dialog',{name:'Report channel message',exact:true})
  }
  const ordinary=await startReport(reportBody)
  await ordinary.getByLabel('Report category',{exact:true}).selectOption('spam')
  await ordinary.getByLabel('Report details (optional)',{exact:true}).fill(reporterNote)
  await ordinary.getByRole('checkbox',{name:'Share this message and my notes with SecTalk Safety',exact:true}).check()
  await ordinary.getByRole('checkbox',{name:'Allow Safety to share this message with authorized workspace moderators',exact:true}).check()
  await ordinary.getByRole('button',{name:'Submit channel report',exact:true}).click()
  await page.getByRole('status').filter({hasText:'Channel report submitted.'}).waitFor()
  const severe=await startReport(severeBody)
  await severe.getByLabel('Report category',{exact:true}).selectOption('sexual_content')
  assert.equal(await severe.getByRole('checkbox').count(),1)
  await severe.getByRole('checkbox').check()
  await severe.getByRole('button',{name:'Submit channel report',exact:true}).click()
  await page.getByRole('status').filter({hasText:'Channel report submitted.'}).waitFor()
  await safety(page)
  const status=page.getByRole('region',{name:'My channel reports'})
  await status.getByText(/Spam.*Open/i).waitFor()

  const manager=await login(owner)
  await safety(manager,'Workspace report review')
  await verifyStaffPanel(manager)
  const tenantQueue=manager.getByRole('region',{name:'Channel report queue'})
  await tenantQueue.getByText('No channel reports are available.',{exact:true}).waitFor()

  const review=await login(staff)
  await safety(review,'Staff console')
  await verifyStaffPanel(review)
  const platform=review.getByRole('region',{name:'Channel report queue'})
  const card=platform.locator('details').filter({hasText:reportBody})
  await card.locator('summary').click()
  await card.getByText(reporterNote,{exact:true}).waitFor()
  const privateCase=platform.locator('details').filter({hasText:severeBody})
  await privateCase.locator('summary').click()
  assert.equal(await privateCase.getByRole('option',{name:'Refer to workspace review',exact:true}).count(),0)
  await card.getByLabel('Channel review decision',{exact:true}).selectOption('handoff')
  await card.getByLabel('Decision reason',{exact:true}).fill('Forward the consented synthetic spam message.')
  await card.getByRole('button',{name:'Save channel decision',exact:true}).click()
  await status.getByText(/Spam.*In review/i).waitFor()

  const local=tenantQueue.locator('details').filter({hasText:reportBody})
  await local.locator('summary').click()
  assert.equal(await local.getByText(reporterNote,{exact:true}).count(),0)
  assert.equal(await tenantQueue.getByText(severeBody,{exact:true}).count(),0)
  await local.getByLabel('Channel review decision',{exact:true}).selectOption('resolved')
  await local.getByLabel('Decision reason',{exact:true}).fill('Private workspace decision for fixture.')
  await local.getByRole('button',{name:'Save channel decision',exact:true}).click()
  await status.getByText(/Spam.*Resolved/i).waitFor()
  await status.getByText(/Spam.*Resolved/i).click()
  await status.getByText('Sent to workspace review',{exact:false}).waitFor()
  assert.ok(await page.evaluate(()=>window.sectalkTestReportEvents)>=2,'Both review changes must arrive over the private account stream')
  assert.equal(await status.getByText('Private workspace decision for fixture.',{exact:true}).count(),0)
  assert.equal(data(await reporter.client.from('st_v2_posts').select('body').eq('id',message).single()).body,reportBody)
  console.log('Passed actual channel consent, separate review, private notes, platform-only severity and live reporter timeline.')
} finally {
  await browser.close()
  if(workspace)sql(`delete from sectalk_private.st_v7_channel_reports where workspace_id='${workspace}';
    delete from public.st_v2_workspaces where id='${workspace}';`)
  if(platformActor)sql(`delete from sectalk_private.staff where user_id='${platformActor}';`)
  for(const actor of actors)data(await service.auth.admin.deleteUser(actor))
}
