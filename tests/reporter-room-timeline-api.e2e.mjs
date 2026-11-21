import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { fixtureAuthenticator } from './workspace-admin-fixture.mjs'

const url=new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(url.origin,'http://127.0.0.1:55321')
const key=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const options={auth:{persistSession:false,autoRefreshToken:false}}
const service=createClient(url.origin,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const suffix=randomUUID().slice(0,8), users=[]
let workspace,report,staff

function data(result) {if (result.error) throw result.error; return result.data}
const sql=statement=>execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
  '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true}).trim()

async function actor(name) {
  const handle='rtl_'+name+'_'+suffix, email=handle+'@example.invalid', password=randomUUID()+'!5Qa'
  const {user}=data(await service.auth.admin.createUser({email,password,email_confirm:true}))
  assert.match(user.id,/^[a-f0-9-]{36}$/)
  users.push(user.id)
  const client=createClient(url.origin,key,options)
  const {session}=data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:handle}))
  return {id:user.id,handle,client,token:session.access_token}
}

function timeline(token, id=report) {
  return fetch(new URL('/rest/v1/rpc/st_v8_my_room_report_timeline',url),{method:'POST',
    headers:{apikey:key,'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},
    body:JSON.stringify({p_report:id})})
}

try {
  const [owner,reporter,subject,stranger]=await Promise.all([actor('reviewer'),actor('reporter'),actor('subject'),actor('outsider')])
  staff=owner.id
  sql(`insert into sectalk_private.staff values('${staff}');`)
  const factor=await fixtureAuthenticator(owner.client)
  workspace=data(await owner.client.rpc('st_v2_create_workspace',{p_name:'Disposable timeline API '+suffix}))
  assert.match(workspace,/^[a-f0-9-]{36}$/)
  const room=randomUUID(), post=randomUUID()
  data(await owner.client.rpc('st_v6_room_create',{p_id:room,p_workspace:workspace,p_name:'Disposable room',p_kind:'public',p_template:'blank'}))
  for(const user of [reporter,subject]) {
    data(await owner.client.rpc('st_v2_invite',{p_workspace:workspace,p_handle:user.handle}))
    const invite=data(await user.client.from('st_v2_invites').select('id').eq('workspace_id',workspace).single())
    data(await user.client.rpc('st_v2_reply_invite',{p_invite:invite.id,p_accept:true}))
    data(await user.client.rpc('st_v6_room_membership',{p_room:room,p_action:'join'}))
  }
  const hidden='Private synthetic text '+suffix
  data(await subject.client.rpc('st_v6_room_post',{p_room:room,p_id:post,p_body:hidden}))
  report=data(await reporter.client.rpc('st_v6_submit_room_report',{p_room:room,p_post:post,p_category:'scam',p_details:hidden,p_share:false}))
  assert.match(report,/^[a-f0-9-]{36}$/)
  assert.equal((await timeline()).ok,false)
  const initial=await timeline(reporter.token)
  assert.equal(initial.status,200)
  assert.deepEqual((await initial.json()).map(row=>[row.action,row.scope]),[['submitted',null]])
  for (const token of [subject.token,stranger.token,factor.session.access_token]) {
    const denied=await timeline(token)
    assert.equal(denied.status,200)
    assert.deepEqual(await denied.json(),[])
  }
  assert.deepEqual(await (await timeline(reporter.token,randomUUID())).json(),[])
  for (const action of ['reviewing','resolved']) data(await owner.client.rpc('st_v6_review_room_report',{
    p_report:report,p_scope:'platform',p_action:action,p_reason:hidden,p_expected_stage:0,
  }))
  const complete=await timeline(reporter.token)
  assert.equal(complete.status,200)
  const rows=await complete.json()
  assert.deepEqual(rows.map(row=>[row.action,row.scope]),[['submitted',null],['reviewing','platform'],['resolved','platform']])
  for (let index=0;index<rows.length;index++) {
    assert.deepEqual(Object.keys(rows[index]).sort(),['action','at','scope'])
    assert.ok(Number.isFinite(Date.parse(rows[index].at)))
    if(index>0) assert.ok(Date.parse(rows[index].at)>=Date.parse(rows[index-1].at))
  }
  assert.ok(!JSON.stringify(rows).includes(suffix))
  data(await reporter.client.auth.signOut({scope:'local'}))
  const revoked=await timeline(reporter.token)
  if(revoked.ok) assert.deepEqual(await revoked.json(),[])
  else assert.ok([401,403].includes(revoked.status))
  console.log('PASS room timeline HTTP contract, live progress, reporter-only access and ended session')
} finally {
  if(report)sql(`delete from sectalk_private.st_v6_room_reports where id='${report}';`)
  if(workspace)sql(`delete from public.st_v2_workspaces where id='${workspace}';`)
  if(staff)sql(`delete from sectalk_private.staff where user_id='${staff}';`)
  for(const id of users)data(await service.auth.admin.deleteUser(id))
}
