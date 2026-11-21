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
let workspace
let artifact
let hold
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
async function login(actor,channels=true) {
  const page=await browser.newPage()
  page.setDefaultTimeout(25000)
  await page.goto(app.href)
  await page.getByLabel('Email address',{exact:true}).fill(actor.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await navigation(page).waitFor()
  if(channels) {
    await navigation(page).getByRole('button',{name:'Workspaces',exact:true}).click()
    await page.getByRole('group',{name:'Workspace sections'}).getByRole('button',{name:'Channels',exact:true}).click()
  }
  return page
}

async function safety(page,tab) {
  await navigation(page).getByRole('button',{name:'Safety',exact:true}).click()
  await page.getByRole('group',{name:'Safety center sections'}).getByRole('button',{name:tab,exact:true}).click()
}
const token=page=>page.evaluate(()=>{
  const key=Object.keys(localStorage).find(key=>/^sb-.+-auth-token$/.test(key))
  return JSON.parse(localStorage.getItem(key)).access_token
})
const scoped=bearer=>createClient(backend.href,process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY,
  {...options,global:{headers:{Authorization:'Bearer '+bearer}}})
const call=(path,bearer,method='GET',body)=>fetch(new URL(path,app),{
  method,headers:{Authorization:'Bearer '+bearer,'Content-Type':'application/json'},body:body&&JSON.stringify(body),
})
const section=(page,name)=>page.getByRole('group',{name:'Workspace sections'}).getByRole('button',{name,exact:true})

try {
  const [owner,admin,sender,reporter,staff,outsider]=await Promise.all(['owner','admin','sender','reporter','staff','outside'].map(account))
  platformActor=staff.id
  workspace=data(await owner.client.rpc('st_v2_create_workspace',{p_name:'Managed evidence '+suffix}))
  sql(`insert into public.st_v2_members(workspace_id,user_id,role) values
    ('${workspace}','${admin.id}','admin'),('${workspace}','${sender.id}','member'),('${workspace}','${reporter.id}','member');
    insert into sectalk_private.staff values('${staff.id}');`)
  const ownerPage=await login(owner)
  await ownerPage.getByText('New channel encryption policy',{exact:true}).click()
  const policy=ownerPage.getByRole('region',{name:'New channel encryption policy',exact:true})
  await verifyStaffPanel(policy)
  await policy.getByRole('button',{name:'Enable managed encryption for new channels',exact:true}).click()
  await policy.getByText('New channels use managed encryption.',{exact:true}).waitFor()
  await ownerPage.getByText('New channel',{exact:true}).click()
  const name='managed-evidence-'+suffix
  await ownerPage.getByLabel('Channel name',{exact:true}).fill(name)
  await ownerPage.getByRole('button',{name:'Create channel',exact:true}).click()
  await ownerPage.getByRole('heading',{name:'Managed encryption',exact:true}).waitFor()
  const channel=await ownerPage.getByLabel('Channel',{exact:true}).inputValue()
  const senderToken=data(await sender.client.auth.getSession()).session.access_token
  const outsiderToken=data(await outsider.client.auth.getSession()).session.access_token
  const post=randomUUID()
  const body='Explicitly consented managed evidence '+suffix
  const path='/api/managed-channel/'+channel
  const sent=await call(path,senderToken,'POST',{id:post,body})
  assert.equal(sent.status,204,sent.ok?'':await sent.text())
  const reporterToken=data(await reporter.client.auth.getSession()).session.access_token
  const reportArgs={post,category:'spam',details:'reporter-only notes',shareWithSafety:true,shareWithWorkspace:true}
  assert.equal((await call(path+'/report',outsiderToken,'POST',reportArgs)).status,404)
  assert.equal((await call(path+'/report',reporterToken,'POST',{...reportArgs,shareWithSafety:false})).status,400)
  assert.ok((await reporter.client.rpc('st_v7_submit_channel_report',{p_channel:channel,p_post:post,p_category:'spam',
    p_details:'Attempt ordinary path.',p_share_with_safety:true,p_share_with_workspace:true})).error)
  assert.equal((await reporter.client.rpc('st_v8_finish_managed_channel_report',{
    p_ticket:randomUUID(),p_actor:reporter.id,p_evidence:'Caller-supplied text',
  })).error?.code,'42501')
  const reporterPage=await login(reporter)
  await reporterPage.getByLabel('Channel',{exact:true}).selectOption(channel)
  const message=reporterPage.getByRole('log',{name:'Channel messages'}).locator('article').filter({hasText:body})
  await message.getByText('Channel message actions',{exact:true}).click()
  await message.getByRole('button',{name:'Report message',exact:true}).click()
  const dialog=reporterPage.getByRole('dialog')
  await dialog.getByLabel('Report category',{exact:true}).selectOption('spam')
  await dialog.getByLabel('Report details (optional)',{exact:true}).fill(reportArgs.details)
  for(const checkbox of await dialog.getByRole('checkbox').all())await checkbox.check()
  const [response]=await Promise.all([
    reporterPage.waitForResponse(response=>response.url().endsWith(path+'/report')),
    dialog.getByRole('button',{name:'Submit channel report',exact:true}).click(),
  ])
  assert.equal(response.status(),201,response.ok()?'':await response.text())
  await reporterPage.getByText(/Channel report submitted/).waitFor()
  const [report,revision]=sql(`copy (select id,managed_revision from sectalk_private.st_v7_channel_reports
    where post_id='${post}' and reporter='${reporter.id}') to stdout;`).toString().trim().split('\t')
  await reporterPage.getByRole('status').filter({hasText:`Ticket ${report}.`}).waitFor()
  await safety(reporterPage,'My reports')
  const reported=reporterPage.getByRole('region',{name:'My channel reports',exact:true})
  await reported.getByText(report,{exact:true}).waitFor()
  await reported.locator('details').filter({hasText:report}).locator('summary').click()
  await reported.getByText(/Report received/).waitFor()
  assert.match(revision,/^[0-9a-f]{64}$/)
  sql(`begin; do $qa$ begin
    update sectalk_private.st_v7_channel_reports set evidence='Changed synthetic snapshot' where id='${report}';
    raise exception 'Managed snapshot could be edited';
    exception when insufficient_privilege then null;
    end $qa$; rollback;`)
  console.log('Managed reporter UI captured and pinned exact ciphertext; absent consent, outsider and legacy bypass denied.')

  const [adminPage,staffPage]=await Promise.all([login(admin,false),login(staff,false)])
  await safety(adminPage,'Workspace report review')
  await verifyStaffPanel(adminPage)
  await adminPage.getByRole('region',{name:'Channel report queue'}).waitFor()
  await safety(staffPage,'Staff console')
  await verifyStaffPanel(staffPage)
  await staffPage.getByRole('region',{name:'Channel report queue'}).waitFor()
  console.log('Independent platform and workspace native TOTP sessions verified.')
  const adminToken=await token(adminPage)
  const staffClient=scoped(await token(staffPage)), adminClient=scoped(adminToken)
  const view={p_report:report,p_scope:'workspace'}
  assert.equal((await adminClient.rpc('st_v8_view_managed_channel_report',view)).error?.code,'42501')
  const rows=data(await staffClient.rpc('st_v7_channel_report_queue',{p_scope:'platform'}))
  assert.equal(rows.find(row=>row.id===report).evidence,null)
  const queue=page=>page.getByRole('region',{name:'Channel report queue'}).locator('details').filter({hasText:name})
  const platform=queue(staffPage)
  await platform.locator('summary').click()
  await platform.getByRole('button',{name:'View consented managed evidence'}).click()
  await platform.getByText(body,{exact:true}).waitFor()
  await platform.getByLabel('Channel review decision',{exact:true}).selectOption('handoff')
  await platform.getByLabel('Decision reason',{exact:true}).fill('Hand off exact consented evidence for synthetic case.')
  const saving=staffPage.waitForResponse(response=>response.url().endsWith('/rpc/st_v7_review_channel_report'))
  await platform.getByRole('button',{name:'Save channel decision',exact:true}).click()
  assert.ok((await saving).ok())
  assert.equal(data(await adminClient.rpc('st_v8_view_managed_channel_report',view)),body)
  const reads=sql(`copy (select string_agg(review_scope,',' order by review_scope) from sectalk_private.st_v8_managed_evidence_views where report='${report}') to stdout;`).toString().trim()
  assert.equal(reads,'platform,workspace')
  console.log('Platform handoff and audited scoped evidence reads passed.')
  const sources=async()=>data(await adminClient.rpc('st_v7_compliance_sources',{p_workspace:workspace})).filter(row=>row.id===report)
  assert.deepEqual(await sources(),[])
  hold=randomUUID()
  const ownerClient=scoped(await token(ownerPage))
  assert.equal(data(await ownerClient.rpc('st_v6_place_workspace_hold',{p_workspace:workspace,p_id:hold,p_room:null,
    p_member:sender.id,p_from:null,p_until:null,p_reason:'Retain the exact synthetic case evidence'})),hold)
  assert.equal((await sources())[0].kind,'managed_channel_report')
  console.log('Consent alone excluded the source, and an active matching member hold made it eligible.')
  await navigation(adminPage).getByRole('button',{name:'Workspaces',exact:true}).click()
  await section(adminPage,'Compliance exports').click()
  const panel=page=>page.getByRole('region',{name:'Compliance exports',exact:true})
  const reference='Managed evidence case '+suffix
  await panel(adminPage).getByText('Request an export',{exact:true}).click()
  await panel(adminPage).getByLabel('Case reference',{exact:true}).fill(reference)
  await panel(adminPage).getByLabel('Case purpose',{exact:true}).fill('Retain exactly the approved held channel report.')
  await panel(adminPage).getByRole('checkbox',{name:new RegExp(report)}).check()
  await panel(adminPage).getByRole('button',{name:'Submit export request',exact:true}).click()
  const card=page=>panel(page).getByRole('article').filter({has:page.getByRole('heading',{name:reference,exact:true})})
  await card(adminPage).getByText('pending',{exact:true}).waitFor()
  const [created]=data(await adminClient.rpc('st_v7_compliance_cases',{p_workspace:workspace}))
  const exportPath='/api/compliance-exports/'+created.id
  assert.equal((await call(exportPath,adminToken,'POST')).status,404)
  await section(ownerPage,'Compliance exports').click()
  const approval=card(ownerPage)
  await approval.getByRole('button',{name:'Approve exact records',exact:true}).click()
  await approval.getByLabel('Decision reason',{exact:true}).fill('Confirm active hold and independently approve exact report.')
  await approval.getByRole('button',{name:'Confirm approve exact records',exact:true}).click()
  await approval.getByText('approved',{exact:true}).waitFor()
  await panel(adminPage).getByRole('button',{name:'Refresh export cases',exact:true}).click()
  const building=adminPage.waitForResponse(r=>r.url().endsWith(exportPath)&&r.request().method()==='POST')
  await card(adminPage).getByRole('button',{name:'Build private bundle',exact:true}).click()
  const built=await building
  assert.equal(built.status(),200,built.ok()?'':await built.text())
  artifact=sql(`copy (select artifact from sectalk_private.st_v7_compliance_cases where id='${created.id}') to stdout;`).toString().trim()
  const download=await call(exportPath,adminToken)
  assert.equal(download.status,200)
  const bundle=await download.text()
  for(const value of [body,report,post,revision,hold])assert.ok(bundle.includes(value),value)
  assert.ok(!bundle.includes(reportArgs.details))
  assert.ok((await adminClient.storage.from('sectalk-exports').download(artifact)).error)
  const physical=data(await service.storage.from('sectalk-exports').download(artifact))
  assert.ok(!(await physical.text()).includes(body))
  assert.equal((await call(exportPath,outsiderToken)).status,404)
  data(await ownerClient.rpc('st_v6_release_workspace_hold',{p_workspace:workspace,p_id:hold,p_reason:'Synthetic evidence check complete'}))
  assert.equal((await call(exportPath,adminToken)).status,404)
  console.log('Fresh native-TOTP case review, audited consent handoff, exact held export, encrypted Storage and release revocation passed.')
} finally {
  await browser.close()
  if(artifact)await service.storage.from('sectalk-exports').remove([artifact])
  if(workspace)sql(`begin; set local session_replication_role=replica;
    delete from sectalk_private.st_v8_managed_evidence_views where workspace='${workspace}';
    delete from sectalk_private.st_v7_tenant_key_audit where workspace='${workspace}'; commit;
    ${hold?`delete from sectalk_private.st_v6_workspace_holds where id='${hold}';`:''}
    delete from public.st_v2_workspaces where id='${workspace}';
    delete from sectalk_private.st_v7_tenant_key_versions where workspace='${workspace}';
    delete from sectalk_private.st_v7_tenant_key_state where workspace='${workspace}';`)
  if(platformActor)sql(`delete from sectalk_private.staff where user_id='${platformActor}';`)
  for(const id of actors)sql(`delete from auth.users where id='${id}';`)
}
