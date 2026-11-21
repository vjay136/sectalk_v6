import assert from 'node:assert/strict'
import { execFileSync,spawn } from 'node:child_process'
import { createHash,randomBytes,randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { setTimeout } from 'node:timers/promises'
import { createClient } from '@supabase/supabase-js'
import { readAllowlist } from '../services/tenant-dek-aws/adapter.mjs'
import { awsErasureObserver,createProviderErasureAttestor } from '../services/tenant-dek-aws/erasure-attestor.mjs'
import { fixtureAuthenticator } from './workspace-admin-fixture.mjs'

const db=new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
assert.equal(db,'http://127.0.0.1:55321')
const port=Number(process.env.SECTALK_PROVIDER_ERASURE_TEST_PORT??3596)
assert.ok(Number.isInteger(port)&&port>=1024&&port<=65535)
const app='http://127.0.0.1:'+port
const publicKey=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const serviceKey=process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
const options={auth:{persistSession:false,autoRefreshToken:false}}
const service=createClient(db,serviceKey,options)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const suffix=randomUUID().slice(0,8),password=randomUUID()+'!aA1',users=[]
const awsToken=randomBytes(32).toString('base64url')
const keyId='arn:aws:kms:us-east-1:123456789012:key/'+randomUUID()
const eventId=randomUUID()
const ref='synthetic_custody'
const hold=randomUUID(),requestId=randomUUID(),caseId=randomUUID()
const commandTrace=[]
let workspace,provider,child,browser,mode='pending',providerTime=new Date().toISOString()
let primaryFailure=false
const sql=statement=>execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
  '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true}).trim()
const hashed=(value,kind='hex')=>createHash('sha256').update(JSON.stringify(value)).digest(kind)
function data(result){if(result.error)throw new Error(result.error.message);return result.data}

async function person(label,mfa) {
  const handle=`pr_${label}_${suffix}`,email=handle+'@example.invalid'
  const {user}=data(await service.auth.admin.createUser({email,password,email_confirm:true}))
  users.push(user.id)
  const client=createClient(db,publicKey,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:'Synthetic '+label}))
  if(mfa) await fixtureAuthenticator(client)
  return {id:user.id,client,session:data(await client.auth.getSession()).session}
}

try {
  const [owner,reviewer,outsider]=await Promise.all([person('owner',true),person('reviewer',true),person('outside',false)])
  workspace=data(await owner.client.rpc('st_v2_create_workspace',{p_name:'Provider proof '+suffix}))
  const bindings=readAllowlist(JSON.stringify([{workspace,version:1,reference:ref,keyId}]))
  const observe=awsErasureObserver({},async (binary,args)=>{
    assert.equal(binary,'/usr/local/aws-cli/v2/current/bin/aws')
    assert.ok(args.includes('us-east-1'))
    commandTrace.push(args.slice(0,2).join(' '))
    if(args[1]==='describe-key') {
      assert.deepEqual(args.slice(0,4),['kms','describe-key','--key-id',keyId])
      if(mode==='pending')return {stdout:JSON.stringify({KeyMetadata:{Arn:keyId,AWSAccountId:'123456789012',KeyState:'PendingDeletion'}})}
      const stderr=mode==='denied' ? 'An error occurred (AccessDeniedException) when calling the DescribeKey operation' :
        'An error occurred (NotFoundException) when calling the DescribeKey operation'
      throw Object.assign(new Error('Synthetic provider exception'),{stderr})
    }
    assert.deepEqual(args.slice(0,3),['cloudtrail','lookup-events','--lookup-attributes'])
    assert.ok(args.includes('--page-size')&&args.includes('--max-items'))
    const resource=mode==='foreign' ? keyId.replace('123456789012','000000000000') : keyId
    const eventTime=mode==='prestage' ? new Date(Date.now()-300_000).toISOString() : providerTime
    if(mode==='hold_race')sql(`insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
      values('${hold}','${workspace}','${owner.id}','Synthetic hold activated during provider verification','${owner.id}');`)
    const event={eventID:eventId,eventTime,eventSource:'kms.amazonaws.com',eventName:'DeleteKey',eventType:'AwsServiceEvent',
      awsRegion:'us-east-1',recipientAccountId:'123456789012',readOnly:false,
      managementEvent:true,eventCategory:'Management',userIdentity:{accountId:'123456789012',invokedBy:'AWS Internal'},
      responseElements:mode==='missing_arn'?null:{keyId},
      resources:[{ARN:resource,type:'AWS::KMS::Key',accountId:'123456789012'}]}
    if(mode==='cloudhsm_incomplete'||mode==='deleted') {
      event.additionalEventData={customKeyStoreId:'cks-synthetickms',clusterId:'cluster-synthetic',
        backingKeys:JSON.stringify([{backingKeyId:'synthetic-backing-key'}]),
        backingKeysDeletionStatus:JSON.stringify([{backingKeyId:'synthetic-backing-key',
          deletionStatus:mode==='deleted'?'SUCCESS':'FAILURE'}])}
    }
    return {stdout:JSON.stringify({Events:mode==='missing'?[]:[JSON.stringify(event)],NextToken:null})}
  })
  provider=createProviderErasureAttestor({token:awsToken,bindings,observe})
  provider.listen(0,'127.0.0.1')
  await once(provider,'listening')
  const origin=`http://127.0.0.1:${provider.address().port}`
  const pin=hashed(['sectalk/external-key-pin/v2',origin,keyId],'base64url')
  const marker='external_v2_'+pin+'_'+hashed(['sectalk/external-key/v2',pin,workspace,1,ref],'base64url')
  sql(`insert into public.st_v2_members(workspace_id,user_id,role) values('${workspace}','${reviewer.id}','admin');
    insert into sectalk_private.st_v8_offboarding_reviewers values('${workspace}','${reviewer.id}');
    insert into sectalk_private.st_v7_tenant_destroy_reviewers values('${workspace}','${reviewer.id}');
    insert into sectalk_private.st_v7_compliance_cases(id,workspace_id,requester,reviewer,case_reference,reason,sources,state,approved_at)
    values('${caseId}','${workspace}','${owner.id}','${reviewer.id}','Synthetic staged case','Disposable offboarding evidence fixture',
      '[{"kind":"offboarding_inventory"}]','approved',now()-interval '3 minutes');
    insert into sectalk_private.st_v8_offboarding_requests(id,workspace,requester,reviewer,case_id,reason,state,snapshot,snapshot_sha256,created_at,staged_at,integration_shutdown)
    select '${requestId}','${workspace}','${owner.id}','${reviewer.id}','${caseId}','Disposable metadata evidence fixture','read_only',
      snapshot,encode(sha256(convert_to(snapshot::text,'UTF8')),'hex'),now()-interval '3 minutes',now()-interval '2 minutes','{}'
    from (select sectalk_private.st_v8_offboarding_snapshot('${workspace}') snapshot) seed;
    insert into sectalk_private.st_v7_tenant_key_state(workspace,current_version) values('${workspace}',1);
    insert into sectalk_private.st_v7_tenant_key_versions(workspace,version,custody,provider_ref,wrapped)
      values('${workspace}',1,'byok','${ref}','${marker}');`)
  assert.equal(await fetch(app+'/api/ready',{signal:AbortSignal.timeout(750)}).then(()=>true).catch(()=>false),false,'Rewrap QA origin must be isolated')
  child=spawn(process.execPath,[resolve('node_modules/next/dist/bin/next'),'dev','-H','127.0.0.1','-p',String(port)],{
    cwd:resolve(process.env.SECTALK_PROVIDER_ERASURE_TEST_APP_DIR),stdio:'inherit',
    env:{...process.env,NEXT_PUBLIC_SUPABASE_URL:db,NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:publicKey,
      SECTALK_FILE_STORAGE_KEY:serviceKey,SECTALK_APP_URL:app,SECTALK_EXTERNAL_KMS_URL:origin+'/v1/tenant-dek',
      SECTALK_EXTERNAL_KMS_TOKEN:randomBytes(32).toString('base64url'),
      SECTALK_EXTERNAL_KMS_KEYS:JSON.stringify({[workspace]:{active:ref,keys:{[ref]:keyId}}}),
      SECTALK_PROVIDER_ERASURE_URL:origin+'/v1/provider-key-erasure',SECTALK_PROVIDER_ERASURE_TOKEN:awsToken},
  })
  let ready=false
  for(let attempt=0;attempt<35&&child.exitCode===null;attempt++) {
    ready=await fetch(app+'/api/ready',{signal:AbortSignal.timeout(2000)}).then(r=>r.ok).catch(()=>false)
    if(ready)break
    await setTimeout(350)
  }
  assert.ok(ready)
  const call=(person,confirmation=workspace)=>fetch(app+'/api/tenant-keys/provider-erasure',{method:'POST',
    headers:{'Content-Type':'application/json',...(person?{Authorization:'Bearer '+person.session.access_token}:{})},
    body:JSON.stringify({workspace,version:1,confirmation}),
  })
  assert.equal((await call(null)).status,401)
  assert.equal((await call(owner)).status,403)
  assert.equal((await call(outsider)).status,403)
  assert.equal((await call(reviewer,'unrelated')).status,400)
  sql(`insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values('${hold}','${workspace}','${owner.id}','Synthetic active key preservation hold','${owner.id}');`)
  assert.equal((await call(reviewer)).status,403)
  assert.equal(commandTrace.length,0)
  sql(`delete from sectalk_private.st_v6_workspace_holds where id='${hold}';`)
  const statusBefore=data(await owner.client.rpc('st_v8_tenant_provider_erasure_status',{p_workspace:workspace}))
  assert.equal(statusBefore.canVerify,false)
  assert.deepEqual(statusBefore.versions,[{version:1,eventDigest:null,eventTime:null}])
  assert.equal(data(await outsider.client.rpc('st_v8_tenant_provider_erasure_status',{p_workspace:workspace})),null)
  for(const [state,expected] of [['pending','pending_deletion'],['denied','unavailable'],['missing','unavailable'],['foreign','unavailable'],
    ['prestage','unavailable'],['missing_arn','unavailable'],['cloudhsm_incomplete','unavailable']]) {
    mode=state
    const response=await call(reviewer)
    assert.equal(response.status,200)
    assert.deepEqual(await response.json(),{state:expected})
    assert.equal(sql(`select count(*) from sectalk_private.st_v8_provider_erasure_receipts where workspace='${workspace}';`),'0')
  }
  assert.deepEqual(commandTrace.slice(0,2),['kms describe-key','kms describe-key'])
  mode='hold_race'
  assert.equal((await call(reviewer)).status,409)
  assert.equal(sql(`select count(*) from sectalk_private.st_v8_provider_erasure_receipts where workspace='${workspace}';`),'0')
  sql(`delete from sectalk_private.st_v6_workspace_holds where id='${hold}';`)

  mode='deleted'
  providerTime=new Date().toISOString()
  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const page=await browser.newPage({acceptDownloads:true,storageState:{cookies:[],origins:[{
    origin:app,localStorage:[{name:'sb-127-auth-token',value:JSON.stringify(reviewer.session)}],
  }]}})
  await page.goto(app)
  await page.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Workspaces',exact:true}).click()
  await page.getByRole('group',{name:'Workspace sections'}).getByRole('button',{name:'Compliance exports',exact:true}).click()
  const panel=page.getByRole('region',{name:'Managed artifact keys',exact:true})
  await panel.getByText('Provider key erasure evidence',{exact:true}).click()
  await panel.getByText('Workspace source deletion is unverified. Backup erasure is unverified.',{exact:true}).waitFor()
  await panel.getByLabel('External key version').selectOption('1')
  await panel.getByLabel('Confirm workspace for provider evidence').fill(workspace)
  await panel.getByRole('button',{name:'Verify provider deletion event',exact:true}).click()
  await panel.getByRole('status').filter({hasText:'Provider deletion event verified.'}).waitFor()
  const done=data(await owner.client.rpc('st_v8_tenant_provider_erasure_status',{p_workspace:workspace}))
  assert.equal(done.sourceDeletion,'unverified')
  assert.equal(done.backupErasure,'unverified')
  assert.match(done.versions[0].eventDigest,/^[a-f0-9]{64}$/)
  assert.equal(sql(`select provider_event from sectalk_private.st_v8_provider_erasure_receipts where workspace='${workspace}';`),eventId)
  assert.equal(sql(`select destroyed_at is null from sectalk_private.st_v7_tenant_key_state where workspace='${workspace}';`),'t')
  await panel.getByLabel('Verified external key version').selectOption('1')
  await panel.getByLabel('Confirm workspace for evidence export').fill(workspace)
  const downloadEvent=page.waitForEvent('download')
  await panel.getByRole('button',{name:'Download provider key evidence',exact:true}).click()
  const download=await downloadEvent
  assert.equal(download.suggestedFilename(),'sectalk-provider-key-evidence-v1.json')
  const raw=await readFile(await download.path(),'utf8')
  const exported=JSON.parse(raw)
  const receiptSha256=createHash('sha256').update(raw).digest('hex')
  await panel.getByRole('status').filter({hasText:receiptSha256}).waitFor()
  assert.equal(exported.workspace,workspace)
  assert.equal(exported.version,1)
  assert.equal(exported.eventSha256,done.versions[0].eventDigest)
  assert.equal(exported.pinCommitment,createHash('sha256').update('sectalk-provider-pin-commitment-v1:'+workspace+':1:'+pin).digest('hex'))
  assert.ok(![pin,ref,keyId,marker].some(secret=>raw.includes(secret)))
  assert.equal((await owner.client.rpc('st_v8_export_provider_key_evidence',{
    p_workspace:workspace,p_version:1,p_confirmation:workspace})).error?.code,'42501')
  const count=commandTrace.length
  assert.deepEqual(await (await call(reviewer)).json(),{state:'deleted_event'})
  assert.equal(commandTrace.length,count)
  assert.throws(()=>sql(`delete from sectalk_private.st_v8_provider_erasure_receipts where workspace='${workspace}';`))
  assert.equal((await reviewer.client.rpc('st_v8_commit_tenant_provider_erasure',{p_ticket:randomUUID(),p_actor:reviewer.id,
    p_event:eventId,p_event_time:providerTime,p_sha256:'a'.repeat(64)})).error?.code,'42501')
  console.log('Passed staged workspace provider proof via Edge, native MFA, exact AWS key lifecycle, immutable independent receipt and distinct unverified source/backup state.')
} catch(error) {
  primaryFailure=true
  throw error
} finally {
  await browser?.close()
  if(child&&child.exitCode===null) {
    if(process.platform==='win32')execFileSync('taskkill',['/PID',String(child.pid),'/T','/F'],{windowsHide:true})
    else child.kill('SIGTERM')
  }
  if(provider)await new Promise(resolve=>provider.close(resolve))
  try {
    if(workspace)sql(`begin; set local session_replication_role=replica;
      delete from sectalk_private.st_v8_provider_erasure_receipts where workspace='${workspace}';
      delete from sectalk_private.st_v8_offboarding_requests where workspace='${workspace}';
      delete from sectalk_private.st_v7_compliance_cases where workspace_id='${workspace}';
      delete from public.st_v2_workspace_audit where workspace_id='${workspace}';
      delete from sectalk_private.st_v8_workspace_audit_custody where workspace='${workspace}';
      set local session_replication_role=origin;
      delete from sectalk_private.st_v7_tenant_key_versions where workspace='${workspace}';
      delete from sectalk_private.st_v7_tenant_key_state where workspace='${workspace}';
      delete from public.st_v2_workspaces where id='${workspace}'; commit;`)
    for(const user of users)data(await service.auth.admin.deleteUser(user))
  }catch(error) {
    if(!primaryFailure)throw error
    console.error('Disposable provider-evidence fixture cleanup failed.')
  }
}
