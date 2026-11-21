import assert from 'node:assert/strict'
import {randomBytes,randomUUID} from 'node:crypto'
import {spawn,execFileSync} from 'node:child_process'
import {resolve} from 'node:path'
import {readFile} from 'node:fs/promises'
import {setTimeout} from 'node:timers/promises'
import {createClient} from '@supabase/supabase-js'
import {fixtureAuthenticator} from './workspace-admin-fixture.mjs'

const db=new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
assert.equal(db,'http://127.0.0.1:55321')
const app='http://127.0.0.1:3489'
const service=process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,publicKey=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const options={auth:{persistSession:false,autoRefreshToken:false}}
const admin=createClient(db,service,options)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const suffix=randomUUID().slice(0,8)
const message='Managed synthetic room post '+suffix
const oldest='Ｆｕｌｌｗｉｄｔｈ older room check '+suffix
const wrappingKey=randomBytes(32).toString('base64url')
const users=[]
const duplicateKeyWarnings=[]
let browser,child,workspace,room,report,artifact
const sql=statement=>execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
  '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true}).trim()
function value(result){if(result.error)throw result.error;return result.data}
async function person(label,mfa=false){
  const handle='mroom_'+label+'_'+suffix,email=handle+'@example.invalid',password=randomUUID()+'!4aS'
  const {user}=value(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  users.push(user.id)
  const client=createClient(db,publicKey,options)
  value(await client.auth.signInWithPassword({email,password}))
  value(await client.rpc('st_save_profile',{p_handle:handle,p_name:'Managed room '+label}))
  if(mfa)await fixtureAuthenticator(client)
  return {id:user.id,client,session:value(await client.auth.getSession()).session}
}
async function request(person,room,payload){
  return fetch(app+'/api/managed-room/'+room,{method:payload?'POST':'GET',
    headers:{Authorization:'Bearer '+person.session.access_token,'Content-Type':'application/json'},
    body:payload?JSON.stringify(payload):undefined})
}
async function roomPage(person){
  const page=await accountPage(person)
  await page.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Rooms',exact:true}).click()
  return page
}
async function accountPage(person){
  const page=await browser.newPage()
  page.on('console',message=>{
    if (['error','warning'].includes(message.type())&&/Encountered two children with the same key/.test(message.text())) {
      duplicateKeyWarnings.push(message.text())
    }
  })
  await page.addInitScript(({name,value})=>localStorage.setItem(name,JSON.stringify(value)),
    {name:'sb-'+new URL(db).hostname.split('.')[0]+'-auth-token',value:person.session})
  await page.goto(app)
  return page
}
async function compliancePage(person){
  const page=await accountPage(person)
  await page.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Workspaces',exact:true}).click()
  await page.getByRole('group',{name:'Workspace sections'}).getByRole('button',{name:'Compliance exports',exact:true}).click()
  return page
}
async function seedSealedHistory(owner){
  const key=JSON.parse(sql(`select jsonb_build_object('workspace',workspace,'version',version,'custody',custody,
    'ref',provider_ref,'wrapped',wrapped) from sectalk_private.st_v7_tenant_key_versions
    where workspace='${workspace}' and version=1;`))
  const saved=process.env.SECTALK_KMS_WRAPPING_KEY
  process.env.SECTALK_KMS_WRAPPING_KEY=wrappingKey
  try{
    const {sealTenantRecord}=await import('../apps/web/lib/tenant-artifact-keys.ts')
    const records=await Promise.all(Array.from({length:110},async(_,index)=>{
      const id=randomUUID()
      const plaintext=Buffer.from(index===0?oldest:'Older synthetic note '+index,'utf8')
      try{
        const sealed=await sealTenantRecord(key,'room:'+room,id,owner.id,plaintext)
        return `('${room}','${id}','${workspace}','${owner.id}',1,decode(repeat('0',64),'hex'),
          '${sealed.body}','${sealed.nonce}','${sealed.tag}','${sealed.wrapped_dek}',now()-make_interval(secs=>${110-index}))`
      }finally{plaintext.fill(0)}
    }))
    sql(`insert into sectalk_private.st_v8_managed_room_posts(room,id,workspace,sender,key_version,
      fingerprint,body,nonce,tag,wrapped_dek,created_at) values ${records.join(',')};`)
  }finally{
    if(saved===undefined)delete process.env.SECTALK_KMS_WRAPPING_KEY
    else process.env.SECTALK_KMS_WRAPPING_KEY=saved
  }
}
try{
  const owner=await person('owner',true),member=await person('member'),outsider=await person('outside')
  const staff=await person('staff',true)
  sql(`insert into sectalk_private.staff values('${staff.id}');`)
  workspace=value(await owner.client.rpc('st_v2_create_workspace',{p_name:'Managed room QA '+suffix}))
  sql(`insert into public.st_v2_members(workspace_id,user_id,role) values
    ('${workspace}','${member.id}','member'),('${workspace}','${outsider.id}','member');`)
  const original=randomUUID()
  value(await owner.client.rpc('st_v6_room_create',{p_id:original,p_workspace:workspace,p_name:'Standard room '+suffix,p_kind:'private',p_template:'blank'}))
  const existing=randomUUID()
  value(await owner.client.rpc('st_v6_room_post',{p_room:original,p_id:existing,p_body:'Standard history remains '+suffix}))
  const nextMode=process.env.SECTALK_MANAGED_ROOM_TEST_DEV==='1' ? 'dev' : 'start'
  child=spawn(process.execPath,[resolve('node_modules/next/dist/bin/next'),nextMode,'--hostname','127.0.0.1','--port','3489'],{
    cwd:resolve(process.env.SECTALK_MANAGED_ROOM_TEST_APP_DIR||'apps/web'),stdio:'inherit',env:{...process.env,
      NEXT_PUBLIC_SUPABASE_URL:db,NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:publicKey,
      SECTALK_FILE_STORAGE_KEY:service,SECTALK_KMS_WRAPPING_KEY:wrappingKey},
  })
  let ready=false
  for(let i=0;i<40&&child.exitCode===null;i++){
    ready=await fetch(app+'/api/health',{signal:AbortSignal.timeout(2000)}).then(r=>r.ok).catch(()=>false)
    if(ready)break
    await setTimeout(500)
  }
  assert(ready)
  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const page=await roomPage(owner)
  const policy=page.getByRole('button',{name:'Manage encryption for new private rooms'})
  await policy.click()
  await page.getByText('New blank private rooms use server-managed encryption.',{exact:false}).waitFor()
  room=randomUUID()
  const name='Encrypted QA '+suffix
  value(await owner.client.rpc('st_v6_room_create',{p_id:room,p_workspace:workspace,p_name:name,p_kind:'private',p_template:'blank'}))
  sql(`insert into public.st_v6_room_members(room_id,user_id,role) values('${room}','${member.id}','member');`)
  await page.getByRole('region',{name:'Room directory',exact:true}).getByRole('button',{name:new RegExp(name)}).click()
  await page.getByText('Encryption mode · Server-managed encryption',{exact:true}).waitFor()
  await page.getByLabel('Managed room message',{exact:true}).fill(message)
  const sent=page.waitForResponse(response=>response.url().endsWith('/api/managed-room/'+room)&&response.request().method()==='POST')
  await page.getByRole('button',{name:'Send managed message'}).click()
  const response=await sent
  assert.equal(response.status(),204,await response.text())
  await page.getByText(message,{exact:true}).waitFor()
  assert.equal(await page.getByRole('button',{name:'Threads',exact:true}).count(),0)
  const memberResult=await request(member,room)
  assert.equal(memberResult.status,200)
  const {messages}=await memberResult.json()
  assert.equal(messages[0].body,message)
  const sealed=sql(`select body from sectalk_private.st_v8_managed_room_posts where room='${room}' and id='${messages[0].id}';`)
  assert.ok(sealed.length>0&&!sealed.includes(suffix))
  assert.deepEqual(value(await member.client.from('st_v6_room_posts').select('body').eq('room_id',room)),[])
  assert.equal(sql(`select count(*) from sectalk_private.st_v7_dlp_delivery_receipts where scope_type='room' and scope_id='${room}';`),'0')
  assert.equal((await request(outsider,room)).status,404)
  assert.equal((await request(outsider,room,{id:randomUUID(),body:'Not in this room'})).status,404)
  assert.equal((await request(outsider,room,{action:'search',query:'synthetic'})).status,404)
  assert.equal((await request(owner,original,{action:'search',query:'Standard history'})).status,404)
  assert.equal((await request(owner,room,{action:'search',query:'synthetic',before:new Date().toISOString()})).status,400)
  assert.equal((await member.client.rpc('st_v6_room_post',{p_room:room,p_id:randomUUID(),p_body:'Legacy write probe'})).error?.code,'42501')
  assert.ok((await member.client.rpc('st_v8_managed_room_work',{p_ticket:randomUUID(),p_actor:member.id,p_action:'read'})).error)
  assert.equal((await request(owner,room,{id:messages[0].id,body:message})).status,204)
  assert.equal((await request(owner,room,{id:messages[0].id,body:'Different message'})).status,409)
  await seedSealedHistory(owner)
  await page.getByText('Search room messages',{exact:true}).click()
  await page.getByLabel('Search this managed room',{exact:true}).fill('fullwidth older')
  await page.getByRole('button',{name:'Find messages',exact:true}).click()
  const results=page.getByRole('region',{name:'Managed room search results',exact:true})
  await results.getByText('No matches so far.',{exact:true}).waitFor()
  const olderButton=results.getByRole('button',{name:'Search older messages',exact:true})
  const second=page.waitForResponse(response=>response.url().endsWith('/api/managed-room/'+room)&&
    response.request().postDataJSON()?.action==='search')
  await olderButton.click()
  assert.deepEqual((await (await second).json()).messages,[])
  await olderButton.click()
  await results.getByText(oldest,{exact:true}).waitFor()
  assert.equal(await olderButton.count(),0)
  const recipientPage=await roomPage(member)
  await recipientPage.getByRole('region',{name:'Room directory',exact:true}).getByRole('button',{name:new RegExp(name)}).click()
  await recipientPage.getByText('Search room messages',{exact:true}).click()
  await recipientPage.getByLabel('Search this managed room',{exact:true}).fill('synthetic room post')
  await recipientPage.getByRole('button',{name:'Find messages',exact:true}).click()
  const recipientResults=recipientPage.getByRole('region',{name:'Managed room search results',exact:true})
  await recipientResults.getByText(message,{exact:true}).waitFor()
  const reportInput={p_room:room,p_post:messages[0].id,p_revision:messages[0].revision,
    p_category:'spam',p_details:'Synthetic report fixture',p_consent:true}
  assert.equal((await member.client.rpc('st_v8_submit_managed_room_report',{...reportInput,p_consent:false})).error?.code,'22023')
  assert.equal((await member.client.rpc('st_v8_submit_managed_room_report',{...reportInput,p_revision:'0'.repeat(64)})).error?.code,'PT409')
  for(const actor of [outsider,owner]){
    assert.equal((await actor.client.rpc('st_v8_submit_managed_room_report',reportInput)).error?.code,'42501')
  }
  await recipientResults.getByRole('button',{name:'Report managed message',exact:true}).click()
  const form=recipientPage.getByRole('region',{name:'Report room message',exact:true})
  await form.locator('select[name="category"]').selectOption('spam')
  await form.getByRole('checkbox',{name:'Share this exact message revision with Platform Safety',exact:true}).check()
  await form.getByRole('button',{name:'Submit room report',exact:true}).click()
  const receipt=form.getByRole('status').filter({hasText:'Report submitted.'})
  await receipt.waitFor()
  report=value(await member.client.rpc('st_v8_submit_managed_room_report',reportInput))
  assert.equal(await receipt.locator('code').textContent(),report)
  await recipientPage.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Safety',exact:true}).click()
  const tracked=recipientPage.getByRole('region',{name:'My room reports',exact:true}).getByRole('article').filter({hasText:report})
  await tracked.getByText(report,{exact:true}).waitFor()
  await tracked.getByText('Action history',{exact:true}).click()
  await tracked.getByText('Report received',{exact:true}).waitFor()
  assert.equal((await member.client.rpc('st_v8_submit_consented_managed_room_report',{
    ...reportInput,p_category:'spam',p_workspace_consent:true,
  })).error?.code,'PT409')
  assert.equal(sql(`select body from sectalk_private.st_v8_managed_room_evidence where report='${report}';`),sealed)
  assert.equal(sql(`select share_with_workspace from sectalk_private.st_v6_room_reports where id='${report}';`),'f')
  assert.ok((await member.client.rpc('st_v8_managed_room_evidence_envelope',{p_report:report})).error)
  const evidence=actor=>fetch(app+'/api/managed-room-evidence/'+report,{headers:{Authorization:'Bearer '+actor.session.access_token}})
  for(const actor of [outsider,owner,member])assert.equal((await evidence(actor)).status,404)
  sql(`update sectalk_private.st_v8_managed_room_posts set body='AA' where room='${room}' and id='${messages[0].id}';`)
  const reviewPage=await accountPage(staff)
  await reviewPage.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Safety',exact:true}).click()
  await reviewPage.getByRole('group',{name:'Safety center sections'}).getByRole('button',{name:'Staff console',exact:true}).click()
  const moderation=reviewPage.getByRole('region',{name:'Platform room reports',exact:true})
  await moderation.getByRole('button',{name:new RegExp('Spam · '+name)}).click()
  await moderation.getByRole('button',{name:'Open approved revision',exact:true}).click()
  await moderation.getByText(message,{exact:true}).waitFor()
  assert.equal(sql(`select count(*) from sectalk_private.st_v8_managed_room_evidence_reads where report='${report}' and actor='${staff.id}';`),'1')
  sql(`update sectalk_private.st_v8_managed_room_evidence set body='AA' where report='${report}';`)
  assert.equal((await evidence(staff)).status,404)
  sql(`update sectalk_private.st_v8_managed_room_evidence set body='${sealed}' where report='${report}';
    update sectalk_private.st_v8_managed_room_posts set body='${sealed}' where room='${room}' and id='${messages[0].id}';`)
  const author=await person('author'), requester=await person('requester',true), router=await person('route',true)
  sql(`insert into public.st_v2_members(workspace_id,user_id,role) values
    ('${workspace}','${author.id}','member'),('${workspace}','${requester.id}','admin');
    insert into public.st_v6_room_members(room_id,user_id,role) values
    ('${room}','${author.id}','member'),('${room}','${requester.id}','member');
    insert into sectalk_private.staff values('${router.id}');
    insert into sectalk_private.st_v6_case_on_call(user_id,tier,starts_at,ends_at) values
    ('${router.id}',1,now()-interval '2 seconds',now()+interval '20 minutes'),
    ('${router.id}',2,now()-interval '2 seconds',now()+interval '20 minutes');`)
  const heldPost=randomUUID(),heldBody='Held exact room revision '+suffix
  assert.equal((await request(author,room,{id:heldPost,body:heldBody})).status,204)
  const heldPage=await roomPage(member)
  await heldPage.getByRole('region',{name:'Room directory',exact:true}).getByRole('button',{name:new RegExp(name)}).click()
  await heldPage.getByRole('article').filter({hasText:heldBody}).getByRole('button',{name:'Report managed message',exact:true}).click()
  const heldForm=heldPage.getByRole('region',{name:'Report room message',exact:true})
  await heldForm.locator('select[name="category"]').selectOption('spam')
  await heldForm.locator('input[name="share"]').check()
  await heldForm.locator('input[name="workspace-share"]').check()
  await heldForm.getByRole('button',{name:'Submit room report',exact:true}).click()
  await heldForm.getByRole('status').filter({hasText:'Report submitted.'}).waitFor()
  const heldReport=sql(`select id from sectalk_private.st_v6_room_reports where room_id='${room}' and post_id='${heldPost}';`)
  const source={kind:'managed_room_report',id:heldReport}
  const sourceArgs={p_workspace:workspace,p_reference:'Held exact '+suffix,p_reason:'Review this consented and held room revision.',p_sources:[source]}
  const sources=async()=>value(await requester.client.rpc('st_v7_compliance_sources',{p_workspace:workspace}))
  const hasHeldSource=rows=>rows.some(row=>row.kind===source.kind&&row.id===source.id)
  const hold=randomUUID()
  const roomReview=async(action,stage)=>value(await router.client.rpc('st_v6_review_room_report',{
    p_report:heldReport,p_scope:'platform',p_action:action,p_reason:'Handle consented workspace review',p_expected_stage:stage,
  }))
  assert.equal((await requester.client.rpc('st_v7_request_compliance_export',sourceArgs)).error?.code,'42501')
  value(await owner.client.rpc('st_v6_place_workspace_hold',{p_workspace:workspace,p_id:hold,p_room:room,
    p_member:null,p_from:null,p_until:null,p_reason:'Preserve exact approved test evidence.'}))
  assert.equal(hasHeldSource(await sources()),false)
  await roomReview('route',0)
  await roomReview('acknowledge',1)
  await roomReview('route',1)
  await roomReview('acknowledge',2)
  await roomReview('route',2)
  assert.equal(hasHeldSource(await sources()),true)
  assert.equal((await requester.client.rpc('st_v7_request_compliance_export',{
    ...sourceArgs,p_sources:[{kind:source.kind,id:report}],
  })).error?.code,'42501')
  assert.ok((await requester.client.rpc('st_v8_managed_room_compliance_keys',{p_ticket:randomUUID()})).error)
  const adminPage=await compliancePage(requester),ownerPage=await compliancePage(owner)
  const panel=page=>page.getByRole('region',{name:'Compliance exports',exact:true})
  await panel(adminPage).getByText('Request an export',{exact:true}).click()
  await panel(adminPage).getByLabel('Case reference',{exact:true}).fill(sourceArgs.p_reference)
  await panel(adminPage).getByLabel('Case purpose',{exact:true}).fill(sourceArgs.p_reason)
  await panel(adminPage).getByRole('checkbox',{name:new RegExp(heldReport)}).check()
  await panel(adminPage).getByRole('button',{name:'Submit export request',exact:true}).click()
  const card=page=>panel(page).getByRole('article').filter({has:page.getByRole('heading',{name:sourceArgs.p_reference,exact:true})})
  await card(adminPage).getByText('pending',{exact:true}).waitFor()
  const pending=value(await requester.client.rpc('st_v7_compliance_cases',{p_workspace:workspace}))
    .find(item=>item.reference===sourceArgs.p_reference)
  const exportPath='/api/compliance-exports/'+pending.id
  const exportCall=(actor,method='GET')=>fetch(app+exportPath,{method,headers:{Authorization:'Bearer '+actor.session.access_token}})
  assert.equal((await exportCall(requester,'POST')).status,404)
  await panel(ownerPage).getByRole('button',{name:'Refresh export cases',exact:true}).click()
  await card(ownerPage).getByRole('button',{name:'Approve exact records',exact:true}).click()
  await card(ownerPage).getByLabel('Decision reason',{exact:true}).fill('Approved the held consented room revision.')
  await card(ownerPage).getByRole('button',{name:'Confirm approve exact records',exact:true}).click()
  await card(ownerPage).getByText('approved',{exact:true}).waitFor()
  assert.equal((await exportCall(owner,'POST')).status,404)
  assert.equal((await exportCall(outsider,'POST')).status,404)
  await panel(adminPage).getByRole('button',{name:'Refresh export cases',exact:true}).click()
  await card(adminPage).getByRole('button',{name:'Build private bundle',exact:true}).click()
  const downloadButton=card(adminPage).getByRole('button',{name:'Download approved bundle',exact:true})
  await downloadButton.waitFor()
  artifact=sql(`select artifact from sectalk_private.st_v7_compliance_cases where id='${pending.id}';`)
  assert.ok((await requester.client.storage.from('sectalk-exports').download(artifact)).error)
  const saved=adminPage.waitForEvent('download')
  await downloadButton.click()
  const downloaded=JSON.parse(await readFile(await (await saved).path(),'utf8'))
  assert.equal(downloaded.approved_managed_room_messages[0].body,heldBody)
  assert.equal(downloaded.approved_managed_room_messages[0].id,heldReport)
  assert.equal(downloaded.records[0].kind,source.kind)
  assert.equal(downloaded.records[0].json.includes(heldBody),false)
  assert.equal(downloaded.approved_bundle_sha256,sql(`select bundle_sha256 from sectalk_private.st_v7_compliance_cases where id='${pending.id}';`))
  value(await owner.client.rpc('st_v6_release_workspace_hold',{p_workspace:workspace,p_id:hold,p_reason:'Release this synthetic test preservation hold.'}))
  assert.equal((await exportCall(requester)).status,404)
  assert.equal(sql(`select count(*) from sectalk_private.st_v8_managed_room_evidence_reads where report='${report}';`),'1')
  sql(`update auth.mfa_amr_claims set updated_at=now()-interval '6 minutes'
    where authentication_method='totp' and session_id in(select id from auth.sessions where user_id='${staff.id}');`)
  assert.equal((await evidence(staff)).status,404)
  value(await owner.client.rpc('st_v7_set_workspace_dlp',{p_workspace:workspace,p_revision:0,
    p_rules:{pii:'warn',phi:'redact',payment_card:'block',credential:'redact'}}))
  assert.equal((await request(owner,room,{id:randomUUID(),body:'Dummy test card 4111 1111 1111 1111'})).status,422)
  sql(`insert into public.st_v6_room_bans(room_id,user_id) values('${room}','${member.id}');`)
  assert.equal((await request(member,room)).status,404)
  assert.equal((await request(member,room,{action:'search',query:'synthetic room post'})).status,404)
  assert.equal((await member.client.rpc('st_v8_submit_managed_room_report',reportInput)).error?.code,'42501')
  await policy.click()
  await page.getByText('New blank private rooms can use server-managed encryption.',{exact:false}).waitFor()
  assert.equal(sql(`select encryption_mode from public.st_v6_rooms where id='${room}';`),'managed')
  await page.getByRole('region',{name:'Room directory',exact:true}).getByRole('button',{name:new RegExp('Standard room '+suffix)}).click()
  await page.getByText('Encryption mode · Standard workspace storage',{exact:true}).waitFor()
  await page.getByText('Standard history remains '+suffix,{exact:true}).waitFor()
  assert.deepEqual(duplicateKeyWarnings,[],'Room reporting and moderation must not render duplicate React keys')
  console.log('Managed room mode, encrypted send/read, scoped search past 100 messages, consented evidence, approved private export, and hold revocation passed.')
}finally{
  await browser?.close()
  child?.kill()
  if(artifact)await admin.storage.from('sectalk-exports').remove([artifact])
  if(report)sql(`delete from sectalk_private.st_v8_managed_room_evidence_reads where report='${report}';`)
  if(workspace)sql(`delete from public.st_v2_workspaces where id='${workspace}';`)
  for(const id of users)await admin.auth.admin.deleteUser(id)
}
