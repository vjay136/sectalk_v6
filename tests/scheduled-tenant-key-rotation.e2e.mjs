import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { verifyStaffPanel } from './workspace-admin-fixture.mjs'

const backend=new URL(process.env.SECTALK_STORAGE_TEST_URL)
const app=new URL(process.env.SECTALK_STORAGE_TEST_APP)
assert.equal(backend.origin,'http://127.0.0.1:55321')
assert.equal(app.origin,'http://127.0.0.1:3596')
assert.ok(process.env.CRON_SECRET && process.env.CRON_SECRET.length>=32)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const options={auth:{persistSession:false,autoRefreshToken:false}}
const service=createClient(backend.origin,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const client=createClient(backend.origin,process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY,options)
const password=randomUUID()+'!aA1'
const suffix=randomUUID().slice(0,8)
const handle='skey_'+suffix
const email=handle+'@example.invalid'
let owner,workspace,browser,roomMember

function data(result) {
  if(result.error)throw new Error(result.error.message)
  return result.data
}
function sql(input) {
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres'],
    {input,encoding:'utf8',windowsHide:true}).trim()
}
const worker=new URL('/api/tenant-keys/rotate-due',app)
const runWorker=()=>fetch(worker,{headers:{Authorization:'Bearer '+process.env.CRON_SECRET}})
const rewrapWorker=new URL('/api/tenant-keys/rewrap',app)
const rewrapSecret=process.env.SECTALK_DEK_REWRAP_SECRET
const runRewrap=(secret=rewrapSecret,scope=workspace,extra={})=>fetch(rewrapWorker,{method:'POST',
  headers:{'Content-Type':'application/json',...(secret ? {Authorization:'Bearer '+secret} : {})},body:JSON.stringify({workspace:scope,...extra})})

try {
  owner=data(await service.auth.admin.createUser({email,password,email_confirm:true})).user.id
  assert.match(owner,/^[a-f0-9-]{36}$/)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:'Synthetic schedule owner'}))
  sql(`insert into public.st_v2_subscriptions(user_id,plan,status,period_end)
    values('${owner}','enterprise','active',now()+interval '1 day');`)
  workspace=data(await client.rpc('st_v2_create_workspace',{p_name:'Key schedule '+suffix}))
  assert.match(workspace,/^[a-f0-9-]{36}$/)

  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const page=await browser.newPage({locale:'en-US'})
  const button=(scope,name)=>scope.getByRole('button',{name,exact:true})
  await page.goto(app.href)
  await page.getByLabel('Email address',{exact:true}).fill(email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await button(page.getByRole('navigation',{name:'SecTalk features'}),'Workspaces').click()
  const sections=page.getByRole('group',{name:'Workspace sections'})
  await button(sections,'Compliance exports').click()
  await verifyStaffPanel(page)
  const keys=page.getByRole('region',{name:'Managed artifact keys',exact:true})
  await keys.getByLabel('Key rotation reason').fill('Provision synthetic managed workspace key')
  await button(keys,'Create workspace key').click()
  await keys.getByText('Workspace key version 1 is active.',{exact:true}).waitFor()
  await keys.getByText('Automatic managed-key rotation',{exact:true}).click()
  await keys.getByLabel('Rotation interval').selectOption('30')
  await button(keys,'Save rotation schedule').click()
  await keys.getByText('Managed-key rotation schedule saved.',{exact:true}).waitFor()
  await keys.getByText(/Every 30 days · Next due/).waitFor()

  await button(sections,'Channels').click()
  await page.getByText('New channel encryption policy',{exact:true}).click()
  const policy=page.getByRole('region',{name:'New channel encryption policy',exact:true})
  await button(policy,'Enable managed encryption for new channels').click()
  await policy.getByText('New channels use managed encryption.',{exact:true}).waitFor()
  await page.getByText('New channel',{exact:true}).click()
  await page.getByLabel('Channel name',{exact:true}).fill('rotation-'+suffix)
  await button(page,'Create channel').click()
  await page.getByRole('heading',{name:'Managed encryption',exact:true}).waitFor()
  const channel=await page.getByLabel('Channel',{exact:true}).inputValue()
  assert.match(channel,/^[a-f0-9-]{36}$/)
  const before='Synthetic message before the schedule '+suffix
  const after='Synthetic message after the schedule '+suffix
  const send=async text=>{
    await page.getByLabel('Channel message',{exact:true}).fill(text)
    await button(page,'Send message').click()
    await page.getByRole('log',{name:'Channel messages'}).getByText(text,{exact:true}).waitFor()
  }
  await send(before)
  let room,roomRecords,memberClient,roomRequest
  if(rewrapSecret) {
    const roomNavigation=page.getByRole('navigation',{name:'SecTalk features'})
    await button(roomNavigation,'Rooms').click()
    await button(page,'Manage encryption for new private rooms').click()
    await page.getByText('New blank private rooms use server-managed encryption.',{exact:false}).waitFor()
    const ownerToken=await page.evaluate(()=>{
      const key=Object.keys(localStorage).find(name=>/^sb-.+-auth-token$/.test(name))
      return JSON.parse(localStorage.getItem(key)).access_token
    })
    const roomOwner=createClient(backend.origin,process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY,
      {...options,global:{headers:{Authorization:'Bearer '+ownerToken}}})
    room=randomUUID()
    data(await roomOwner.rpc('st_v6_room_create',{p_id:room,p_workspace:workspace,p_name:'Key rotation room '+suffix,
      p_kind:'private',p_template:'blank'}))
    const memberEmail=`keymember_${suffix}@example.invalid`
    roomMember=data(await service.auth.admin.createUser({email:memberEmail,password,email_confirm:true})).user.id
    memberClient=createClient(backend.origin,process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY,options)
    const memberSession=data(await memberClient.auth.signInWithPassword({email:memberEmail,password})).session
    data(await memberClient.rpc('st_save_profile',{p_handle:'keymember_'+suffix,p_name:'Synthetic room member'}))
    sql(`insert into public.st_v2_members(workspace_id,user_id,role) values('${workspace}','${roomMember}','member');
      insert into public.st_v6_room_members(room_id,user_id,role) values('${room}','${roomMember}','member');`)
    roomRequest=(token=memberSession.access_token,body)=>fetch(new URL('/api/managed-room/'+room,app),{
      method:body?'POST':'GET',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},
      body:body&&JSON.stringify(body),
    })
    const eligible='00000000-0000-4000-8000-000000000100'
    const protectedPost='00000000-0000-4000-8000-000000000101'
    assert.equal((await roomRequest(ownerToken,{id:eligible,body:'Rewrap me '+suffix})).status,204)
    assert.equal((await roomRequest(ownerToken,{id:protectedPost,body:'Protect reported '+suffix})).status,204)
    const baseline=await roomRequest()
    assert.equal(baseline.status,200)
    const rows=(await baseline.json()).messages
    roomRecords={eligible:rows.find(row=>row.id===eligible),reported:rows.find(row=>row.id===protectedPost)}
    assert.equal(roomRecords.eligible.body,'Rewrap me '+suffix)
    assert.equal(roomRecords.reported.body,'Protect reported '+suffix)
    roomRecords.reportId=data(await memberClient.rpc('st_v8_submit_managed_room_report',{p_room:room,p_post:protectedPost,
      p_revision:roomRecords.reported.revision,p_category:'spam',p_details:'Synthetic report before rotation',p_consent:true}))
  }
  assert.equal((await fetch(worker)).status,401)
  assert.equal((await fetch(worker,{headers:{Authorization:'Bearer different-worker-secret'}})).status,401)

  sql(`update sectalk_private.st_v8_tenant_rotation_schedules set saved_at=now()-interval '31 days' where workspace='${workspace}';
    update sectalk_private.st_v7_tenant_key_versions set created_at=now()-interval '31 days' where workspace='${workspace}' and version=1;`)
  const outcomes=await Promise.all([runWorker(),runWorker()])
  for(const result of outcomes)assert.equal(result.status,200)
  const totals=await Promise.all(outcomes.map(result=>result.json()))
  assert.ok(totals.every(result=>result.failed===0))
  assert.equal(sql(`select current_version from sectalk_private.st_v7_tenant_key_state where workspace='${workspace}';`),'2')
  assert.equal(sql(`select count(*) from sectalk_private.st_v7_tenant_key_audit where workspace='${workspace}' and event='scheduled_rotation';`),'1')

  if(rewrapSecret) {
    const source=sql(`select e.post,sectalk_private.st_v8_managed_revision(e) from sectalk_private.st_v8_channel_payloads e
      where e.workspace='${workspace}';`)
    const [post,revision]=source.split('|')
    assert.match(post,/^[a-f0-9-]{36}$/)
    assert.match(revision,/^[a-f0-9]{64}$/)
    assert.equal((await runRewrap(null)).status,401)
    assert.equal((await runRewrap('different-worker-secret')).status,401)
    assert.equal((await runRewrap(rewrapSecret,'not-a-workspace')).status,400)
    assert.equal((await runRewrap(rewrapSecret,'x'.repeat(300))).status,413)
    const foreign=await runRewrap(rewrapSecret,randomUUID())
    assert.equal(foreign.status,200)
    assert.deepEqual(await foreign.json(),{processed:0,rewrapped:0,failed:0})
    const blockedRpc=await client.rpc('st_v8_due_managed_channel_rewrap',{p_workspace:workspace})
    assert.equal(blockedRpc.error?.code,'42501')

    const jobs=data(await service.rpc('st_v8_due_managed_channel_rewrap',{p_workspace:workspace}))
    assert.equal(jobs.length,1)
    const job=jobs[0]
    assert.equal(job.post,post)
    const pastChannel=await runRewrap(rewrapSecret,workspace,{after:{post}})
    assert.equal(pastChannel.status,200)
    assert.deepEqual(await pastChannel.json(),{processed:0,rewrapped:0,failed:0})
    const compare={p_workspace:workspace,p_post:post,p_policy_revision:job.policy_revision,p_source_revision:revision,
      p_previous:1,p_target:2,p_wrapped_dek:'A'.repeat(80)}
    assert.equal(data(await service.rpc('st_v8_commit_managed_channel_rewrap',{...compare,p_source_revision:'a'.repeat(64)})),false)
    assert.equal(data(await service.rpc('st_v8_commit_managed_channel_rewrap',{...compare,p_policy_revision:randomUUID()})),false)
    const hold=randomUUID()
    sql(`insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
      values('${hold}','${workspace}','${owner}','Fixture active workspace hold','${owner}');`)
    assert.equal(data(await service.rpc('st_v8_commit_managed_channel_rewrap',compare)),false)
    const held=await runRewrap()
    assert.equal(held.status,200)
    assert.deepEqual(await held.json(),{processed:0,rewrapped:0,failed:0})
    sql(`delete from sectalk_private.st_v6_workspace_holds where id='${hold}';`)
    const ticket=randomUUID()
    sql(`insert into sectalk_private.st_v8_managed_report_tickets(id,channel,post,actor,native_session,revision,category,details,tenant_consent)
      values('${ticket}','${channel}','${post}','${owner}',gen_random_uuid(),'${revision}','spam','',false);`)
    assert.equal(data(await service.rpc('st_v8_commit_managed_channel_rewrap',compare)),false)
    const inReview=await runRewrap()
    assert.equal(inReview.status,200)
    assert.deepEqual(await inReview.json(),{processed:0,rewrapped:0,failed:0})
    sql(`delete from sectalk_private.st_v8_managed_report_tickets where id='${ticket}';`)
    const attempts=await Promise.all([runRewrap(),runRewrap()])
    for(const result of attempts)assert.equal(result.status,200)
    const batches=await Promise.all(attempts.map(result=>result.json()))
    assert.ok(batches.every(batch=>batch.failed===0))
    assert.equal(batches.reduce((sum,batch)=>sum+batch.rewrapped,0),1)
    assert.equal(sql(`select count(*) from sectalk_private.st_v8_managed_channel_rewrap_audit
      where post='${post}' and previous_version=1 and wrapping_version=2 and source_revision='${revision}';`),'1')
    assert.equal(sql(`select w.wrapping_version,w.wrapped_dek<>e.wrapped_dek,sectalk_private.st_v8_managed_revision(e)='${revision}'
      from sectalk_private.st_v8_managed_channel_wraps w join sectalk_private.st_v8_channel_payloads e on e.post=w.post
      where e.post='${post}';`),'2|t|t')
    assert.equal(data(await service.rpc('st_v8_commit_managed_channel_rewrap',compare)),false)
    const repeat=await runRewrap()
    assert.equal(repeat.status,200)
    assert.deepEqual(await repeat.json(),{processed:0,rewrapped:0,failed:0})

    const roomOptions={kind:'room'}
    assert.equal((await runRewrap(rewrapSecret,workspace,{...roomOptions,after:{post}})).status,400)
    const roomJob=(await service.rpc('st_v8_due_managed_room_rewrap',{
      p_workspace:workspace,p_after_room:null,p_after_post:null,
    })).data?.[0]
    assert.equal(roomJob.post,roomRecords.eligible.id)
    assert.equal(roomJob.source_revision,roomRecords.eligible.revision)
    const originalRoomEnvelope=sql(`select to_jsonb(m) from sectalk_private.st_v8_managed_room_posts m
      where room='${room}' and id='${roomJob.post}';`)
    const protectedEnvelope=sql(`select to_jsonb(e) from sectalk_private.st_v8_managed_room_evidence e where report='${roomRecords.reportId}';`)
    const roomCompare={...compare,p_room:room,p_post:roomJob.post,p_source_revision:roomJob.source_revision}
    assert.equal(data(await service.rpc('st_v8_commit_managed_room_rewrap',{...roomCompare,p_room:randomUUID()})),false)
    const deniedRoomRpc=await memberClient.rpc('st_v8_due_managed_room_rewrap',{p_workspace:workspace,p_after_room:null,p_after_post:null})
    assert.equal(deniedRoomRpc.error?.code,'42501')
    const roomHold=randomUUID()
    sql(`insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,room_id,reason,placed_by)
      values('${roomHold}','${workspace}','${room}','Synthetic room rewrap hold','${owner}');`)
    assert.equal(data(await service.rpc('st_v8_commit_managed_room_rewrap',roomCompare)),false)
    assert.deepEqual(await (await runRewrap(rewrapSecret,workspace,roomOptions)).json(),{processed:0,rewrapped:0,failed:0})
    sql(`delete from sectalk_private.st_v6_workspace_holds where id='${roomHold}';`)

    // Each copied capsule is bound to the real post, so the first page contains 16 deterministic failures.
    sql(`insert into sectalk_private.st_v8_managed_room_posts(room,id,workspace,sender,key_version,fingerprint,body,nonce,tag,wrapped_dek)
      select m.room,('00000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,m.workspace,m.sender,m.key_version,
        m.fingerprint,m.body,m.nonce,m.tag,m.wrapped_dek
      from sectalk_private.st_v8_managed_room_posts m cross join generate_series(1,16) n
      where m.room='${room}' and m.id='${roomJob.post}';`)
    const poisoned=await runRewrap(rewrapSecret,workspace,roomOptions)
    assert.equal(poisoned.status,503)
    const firstBatch=await poisoned.json()
    assert.deepEqual(firstBatch,{processed:16,rewrapped:0,failed:16,next:{room,post:'00000000-0000-4000-8000-000000000016'}})
    const afterPoison={...roomOptions,after:firstBatch.next}
    const roomAttempts=await Promise.all([runRewrap(rewrapSecret,workspace,afterPoison),runRewrap(rewrapSecret,workspace,afterPoison)])
    for(const batch of roomAttempts)assert.equal(batch.status,200)
    assert.equal((await Promise.all(roomAttempts.map(batch=>batch.json()))).reduce((sum,batch)=>sum+batch.rewrapped,0),1)
    assert.equal(sql(`select count(*) from sectalk_private.st_v8_managed_room_rewrap_audit
      where (room,post)=('${room}','${roomJob.post}') and previous_version=1 and wrapping_version=2;`),'1')
    assert.equal(sql(`select to_jsonb(m) from sectalk_private.st_v8_managed_room_posts m
      where room='${room}' and id='${roomJob.post}';`),originalRoomEnvelope)
    assert.equal(sql(`select to_jsonb(e) from sectalk_private.st_v8_managed_room_evidence e
       where report='${roomRecords.reportId}';`),protectedEnvelope)
    assert.equal(sql(`select post from sectalk_private.st_v8_managed_room_wraps where room='${room}';`),roomJob.post)
    sql(`delete from sectalk_private.st_v8_managed_room_posts where room='${room}' and id<'${roomJob.post}';`)
    const memberRead=await roomRequest()
    assert.equal(memberRead.status,200)
    const updatedRoom=(await memberRead.json()).messages
    assert.deepEqual(updatedRoom.find(row=>row.id===roomJob.post),roomRecords.eligible)
    const memberSearch=await roomRequest(undefined,{action:'search',query:'rewrap me'})
    assert.equal(memberSearch.status,200)
    assert.deepEqual((await memberSearch.json()).messages,[roomRecords.eligible])
    const reportAfter=data(await memberClient.rpc('st_v8_submit_managed_room_report',{p_room:room,p_post:roomJob.post,
      p_revision:roomRecords.eligible.revision,p_category:'spam',p_details:'Same synthetic revision after rewrap',p_consent:true}))
    assert.equal(sql(`select revision||':'||key_version from sectalk_private.st_v8_managed_room_evidence
      where report='${reportAfter}';`),`${roomRecords.eligible.revision}:1`)
  }

  await page.reload()
  await button(page.getByRole('navigation',{name:'SecTalk features'}),'Workspaces').click()
  await button(sections,'Channels').click()
  await page.getByLabel('Channel',{exact:true}).selectOption(channel)
  await page.getByRole('log',{name:'Channel messages'}).getByText(before,{exact:true}).waitFor()
  await send(after)
  assert.equal(sql(`select string_agg(e.key_version::text,',' order by p.created_at) from sectalk_private.st_v8_channel_payloads e
    join public.st_v2_posts p on p.id=e.post where p.channel_id='${channel}';`),'1,2')
  await button(sections,'Compliance exports').click()
  await keys.getByText(/Version 2 · Managed custody/).waitFor()
  await keys.getByText('Key audit history',{exact:true}).click()
  await keys.getByText(/Scheduled rotation activated/).waitFor()
  console.log('Passed browser owner MFA, automatic policy setup, signed and concurrent worker requests, historical ciphertext, and new key activation.')
  if(rewrapSecret)console.log('Passed signed managed rewrap, stale and concurrent CAS, hold and report ticket exclusion, immutable source revision, and timeline read.')
  if(rewrapSecret)console.log('Passed managed-room composite CAS, report and hold exclusion, bounded cursor past 16 failed capsules, timeline/search revision preservation and report after rewrap.')
} finally {
  await browser?.close()
  if(workspace && /^[a-f0-9-]{36}$/.test(workspace)) {
    sql(`begin; set local session_replication_role=replica;
      delete from sectalk_private.st_v8_tenant_rotation_schedules where workspace='${workspace}';
      delete from sectalk_private.st_v7_tenant_key_audit where workspace='${workspace}';
      ${rewrapSecret?`delete from sectalk_private.st_v8_managed_channel_rewrap_audit where workspace='${workspace}';
        delete from sectalk_private.st_v8_managed_room_rewrap_audit where workspace='${workspace}';`:''}
      commit;`)
    sql(`delete from public.st_v2_workspaces where id='${workspace}';
      delete from sectalk_private.st_v7_tenant_key_versions where workspace='${workspace}';
      delete from sectalk_private.st_v7_tenant_key_state where workspace='${workspace}';`)
  }
  if(roomMember)await service.auth.admin.deleteUser(roomMember)
  if(owner)await service.auth.admin.deleteUser(owner)
}
