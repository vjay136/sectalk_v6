import assert from 'node:assert/strict'
import {execFileSync} from 'node:child_process'
import {randomUUID} from 'node:crypto'
import {createClient} from '@supabase/supabase-js'
import {fixtureAuthenticator} from './workspace-admin-fixture.mjs'

const app=new URL(process.env.SECTALK_STORAGE_TEST_APP)
const backend=new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.origin,'http://127.0.0.1:3673')
assert.equal(backend.origin,'http://127.0.0.1:56801')
const publicKey=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const serviceKey=process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
assert.ok(publicKey&&serviceKey,'Use only the disposable loopback project credentials')
const options={auth:{persistSession:false,autoRefreshToken:false}}
const service=createClient(backend.href,serviceKey,options)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
const actors=[]
const requestId=randomUUID()
let workspace,inventory
let primaryFailure=false

function sql(input){
  return execFileSync('docker',['exec','-i','supabase_db_v6-bundle243-qa','psql','-XqtA','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'],{input,encoding:'utf8',windowsHide:true}).trim()
}
function data(result){if(result.error)throw new Error(result.error.message);return result.data}
async function actor(label){
  const handle='root_'+label+'_'+randomUUID().slice(0,8)
  const email=handle+'@example.invalid',password=randomUUID()+'!q7'
  const {user}=data(await service.auth.admin.createUser({email,password,email_confirm:true}))
  actors.push(user.id)
  const client=createClient(backend.href,publicKey,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:'Synthetic offboarding '+label}))
  await fixtureAuthenticator(client)
  return {id:user.id,client}
}
const roleButton=(scope,name)=>scope.getByRole('button',{name,exact:true})
async function openReview(who,tab){
  const {session}=data(await who.client.auth.getSession())
  const context=await browser.newContext({storageState:{cookies:[],origins:[{
    origin:app.origin,localStorage:[{name:'sb-127-auth-token',value:JSON.stringify(session)}],
  }]}})
  const page=await context.newPage()
  await page.goto(new URL('/?workspace='+workspace,app).href)
  await roleButton(page,tab).click()
  const offboarding=page.getByRole('region',{name:'Workspace offboarding',exact:true})
  await offboarding.getByText('Source erasure reconciliation',{exact:true}).click()
  const panel=offboarding.getByRole('region',{name:'Source erasure reconciliation',exact:true})
  await panel.getByText('Workspace record removal preflight',{exact:true}).click()
  return panel
}

try{
  assert.equal((await fetch(new URL('/api/health',app))).status,200)
  const owner=await actor('owner'),reviewer=await actor('reviewer')
  workspace=data(await owner.client.rpc('st_v2_create_workspace',{p_name:'Disposable root rehearsal'}))
  sql(`insert into public.st_v2_members(workspace_id,user_id,role) values('${workspace}','${reviewer.id}','admin');
    insert into sectalk_private.st_v8_offboarding_reviewers values('${workspace}','${reviewer.id}');`)
  const scoped={p_workspace:workspace,p_confirmation:workspace}
  const command={...scoped,p_id:requestId}
  const rpc=async(who,name,args)=>data(await who.client.rpc(name,args))
  await rpc(owner,'st_v8_workspace_offboarding_change',{...command,p_action:'requested',p_reason:'Synthetic root rehearsal browser approval.'})
  await rpc(reviewer,'st_v8_workspace_offboarding_change',{...command,p_action:'approved'})
  inventory=(await rpc(owner,'st_v8_workspace_offboarding',{p_workspace:workspace})).request.case
  sql(`insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action)
    values('${inventory}','${workspace}','${owner.id}','downloaded');`)
  await rpc(owner,'st_v8_workspace_offboarding_change',{...command,p_action:'read_only'})
  const capture=async name=>rpc(owner,name,{...scoped,p_action:'capture'})
  const act=async(who,name,action,plan)=>rpc(who,name,{...scoped,p_action:action,p_plan:plan.plan,p_sha256:plan.sha256})
  const audit='st_v8_offboarding_workspace_audit_custody'
  const workflow='st_v8_offboarding_workflow_custody'
  const reconciliation='st_v8_offboarding_reconciliation'
  const auditPlan=await capture(audit)
  await act(reviewer,audit,'approve',auditPlan)
  await act(owner,audit,'detach',auditPlan)
  const sourcePlan=await capture(reconciliation)
  await act(reviewer,reconciliation,'confirm',sourcePlan)
  const workflowPlan=await capture(workflow)
  await act(reviewer,workflow,'approve',workflowPlan)
  await act(owner,workflow,'detach',workflowPlan)
  await capture(reconciliation)

  const ownerPanel=await openReview(owner,'Organization settings')
  const reviewerPanel=await openReview(reviewer,'Compliance exports')
  const rehearsalButton='Run rollback-only removal rehearsal'
  assert.equal(await roleButton(ownerPanel,rehearsalButton).count(),0)
  assert.equal(await roleButton(reviewerPanel,rehearsalButton).count(),0)
  await reviewerPanel.getByLabel('Confirm reconciliation workspace ID',{exact:true}).fill(workspace)
  await roleButton(reviewerPanel,'Confirm exact source reconciliation').click()
  await reviewerPanel.getByText('Current reconciliation independently confirmed.',{exact:true}).waitFor()
  assert.equal(await roleButton(reviewerPanel,rehearsalButton).count(),0)
  await roleButton(ownerPanel,'Refresh source reconciliation').click()
  const confirmation=ownerPanel.getByLabel('Workspace ID for removal rehearsal',{exact:true})
  await confirmation.fill(randomUUID())
  await roleButton(ownerPanel,rehearsalButton).click()
  await ownerPanel.getByRole('alert').getByText('Enter the exact workspace ID.',{exact:true}).waitFor()
  await confirmation.fill(workspace)
  await roleButton(ownerPanel,rehearsalButton).click()
  await ownerPanel.getByText('Workspace record rehearsal passed. All rehearsal changes were rolled back.',{exact:true}).waitFor()
  const reopened=await openReview(reviewer,'Compliance exports')
  await reopened.getByText('Workspace record rehearsal passed. All rehearsal changes were rolled back.',{exact:true}).waitFor()
  assert.equal(await roleButton(reopened,rehearsalButton).count(),0)
  const current=await rpc(owner,reconciliation,{p_workspace:workspace})
  assert.equal(current.current,true)
  assert.equal(current.summary.nativeRows.workspace,1)
  assert.equal(current.summary.nativeRows.members,2)
  assert.equal(current.summary.nativeRows.channels,1)
  console.log('Browser verified independent review, exact owner confirmation, a saved reviewer-visible receipt, and unchanged workspace records after rehearsal.')
}catch(cause){
  primaryFailure=true
  throw cause
}finally{
  await browser.close()
  try{
    if(workspace)sql(`begin;
      set local session_replication_role=replica;
      delete from sectalk_private.st_v8_offboarding_workflow_custody_decisions d using
        sectalk_private.st_v8_offboarding_workflow_custody_plans p where p.id=d.plan and p.workspace='${workspace}';
      delete from sectalk_private.st_v8_offboarding_workflow_custody_plans where workspace='${workspace}';
      delete from sectalk_private.st_v8_offboarding_audit_custody_decisions d using
        sectalk_private.st_v8_offboarding_audit_custody_plans p where p.id=d.plan and p.workspace='${workspace}';
      delete from sectalk_private.st_v8_offboarding_audit_custody_plans where workspace='${workspace}';
      delete from sectalk_private.st_v8_offboarding_root_rehearsal_receipts r using
        sectalk_private.st_v8_offboarding_reconciliations p where r.reconciliation=p.id and p.workspace='${workspace}';
      delete from sectalk_private.st_v8_offboarding_reconciliation_receipts r using
        sectalk_private.st_v8_offboarding_reconciliations p where r.reconciliation=p.id and p.workspace='${workspace}';
      delete from sectalk_private.st_v8_offboarding_reconciliations where workspace='${workspace}';
      delete from sectalk_private.st_v8_offboarding_audit where workspace='${workspace}';
      delete from sectalk_private.st_v7_compliance_audit where workspace_id='${workspace}';
      delete from sectalk_private.st_v8_offboarding_requests where workspace='${workspace}';
      delete from sectalk_private.st_v7_compliance_cases where workspace_id='${workspace}';
      delete from public.st_v2_workspace_audit where workspace_id='${workspace}';
      delete from sectalk_private.st_v8_workspace_audit_custody where workspace='${workspace}';
      set local session_replication_role=origin;
      delete from public.st_v2_workspaces where id='${workspace}';
      commit;`)
    for(const actor of actors)sql(`begin;
      delete from auth.users where id='${actor}';
      set local session_replication_role=replica;
      delete from sectalk_private.st_v8_workspace_audit_actors where actor='${actor}'
        and not exists(select 1 from public.st_v2_workspace_audit where actor='${actor}');
      commit;`)
  }catch(cause){
    if(!primaryFailure)throw cause
    console.error('Disposable rehearsal fixture cleanup failed.')
  }
}
