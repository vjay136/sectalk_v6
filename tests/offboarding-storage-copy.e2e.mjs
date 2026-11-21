// Local Auth QA only. Synthetic Storage bytes and request-scoped immutable receipts.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { createClient } from '@supabase/supabase-js'
import { verifyStaffPanel } from './workspace-admin-fixture.mjs'

const app=new URL(process.env.SECTALK_STORAGE_TEST_APP)
const backend=new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname,'127.0.0.1')
assert.equal(backend.origin,'http://127.0.0.1:55321')
const options={auth:{persistSession:false,autoRefreshToken:false}}
const publicKey=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const service=createClient(backend.origin,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const bucket=service.storage.from('sectalk-workspace-files')
const roomMode=process.env.SECTALK_OFFBOARDING_ROOM_STORAGE==='1'
const registrationMode=process.env.SECTALK_OFFBOARDING_ROOM_METADATA_CLEANUP==='1'
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
const suffix=randomUUID().slice(0,8), password=randomUUID()+'!5Qa'
let path

function data(result) {if (result.error) throw result.error; return result.data}
const hash=bytes=>createHash('sha256').update(bytes).digest('hex')
const button=(scope,name)=>scope.getByRole('button',{name,exact:true})
const sql=statement=>execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
  '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true}).trim()

async function user(role) {
  const handle='copy_'+role+'_'+suffix, email=handle+'@example.invalid'
  const {user}=data(await service.auth.admin.createUser({email,password,email_confirm:true}))
  assert.match(user.id,/^[a-f0-9-]{36}$/)
  const client=createClient(backend.origin,publicKey,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:'Copy QA '+role}))
  return {id:user.id,email,client}
}

async function open(user,tab) {
  const page=await browser.newPage({acceptDownloads:true})
  await page.goto(app.href)
  await page.getByLabel('Email address',{exact:true}).fill(user.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await button(page.getByRole('navigation',{name:'SecTalk features'}),'Workspaces').click()
  await button(page,tab).click()
  const panel=page.getByRole('region',{name:'Workspace offboarding',exact:true})
  await verifyStaffPanel(panel)
  await button(panel,'Refresh offboarding status').waitFor()
  const token=await page.evaluate(()=>JSON.parse(localStorage.getItem(Object.keys(localStorage).find(k=>/^sb-.+-auth-token$/.test(k)))).access_token)
  const native=createClient(backend.origin,publicKey,{...options,global:{headers:{Authorization:'Bearer '+token}}})
  return {page,panel,token,native,refresh:()=>button(panel,'Refresh offboarding status').click()}
}

async function verifyRegistrationCleanup(requester,judge,{workspace,room,file,copy,bytes,filename,hold,owner}) {
  const scope=roomMode?'room':'workspace'
  const label=scope+' file'
  const title=(roomMode?'Room':'Workspace')+' file registration cleanup'
  const reviewUrl=new URL('/api/workspaces/offboarding/'+scope+'-file-cleanup?'+new URLSearchParams({
    workspace,copy,file,confirmation:workspace,action:'review',
  }),app)
  assert.equal((await fetch(reviewUrl,{method:'POST',headers:{Authorization:'Bearer '+judge.token},body:bytes})).status,409)
  const retainedPath='qa-retained-offboarding-files/'+randomUUID()
  data(await bucket.move(path,retainedPath))
  assert.deepEqual(Buffer.from(await data(await bucket.download(retainedPath)).arrayBuffer()),bytes)
  assert.equal((await bucket.info(path)).error?.code,'NoSuchKey')
  await judge.refresh()
  for(const view of [requester,judge])
    await view.panel.locator('summary').filter({hasText:new RegExp('^'+title+'$')}).click()
  const panel=view=>view.panel.getByRole('region',{name:title,exact:true})
  const ownerPanel=panel(requester), reviewPanel=panel(judge)
  assert.equal(await ownerPanel.getByText('Remove this '+label+' registration',{exact:true}).count(),0)
  await reviewPanel.getByText('Awaiting independent recovery verification',{exact:true}).waitFor()
  const fileInput=reviewPanel.getByLabel('Retained approved file')
  await reviewPanel.getByLabel('Confirm recovery workspace ID').fill(workspace)
  await fileInput.setInputFiles({name:filename,mimeType:'application/octet-stream',buffer:Buffer.from(bytes.map(byte=>byte^1))})
  await button(reviewPanel,'Verify recovered '+label).click()
  await reviewPanel.getByRole('alert').waitFor()
  assert.equal(await reviewPanel.getByText('Recovery copy independently verified',{exact:true}).count(),0)
  await fileInput.setInputFiles({name:filename,mimeType:'application/octet-stream',buffer:bytes})
  await button(reviewPanel,'Verify recovered '+label).click()
  await reviewPanel.getByText('Recovery copy independently verified',{exact:true}).waitFor()
  await ownerPanel.getByRole('button',{name:/^Refresh (room|workspace) file cleanup status$/}).click()
  await ownerPanel.getByText('Recovery copy independently verified',{exact:true}).waitFor()
  sql(`insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values('${hold}','${workspace}','${owner}','Keep disjoint synthetic records available.','${owner}');`)
  await ownerPanel.getByRole('button',{name:/^Refresh (room|workspace) file cleanup status$/}).click()
  await ownerPanel.getByText('Active preservation holds block '+label+' cleanup.',{exact:true}).waitFor()
  assert.equal(await ownerPanel.getByText('Remove this '+label+' registration',{exact:true}).count(),0)
  sql(`update sectalk_private.st_v6_workspace_holds set released_at=now(),released_by='${owner}',
    release_reason='Release the synthetic hold.' where id='${hold}';`)
  await ownerPanel.getByRole('button',{name:/^Refresh (room|workspace) file cleanup status$/}).click()
  await ownerPanel.getByText('Remove this '+label+' registration',{exact:true}).click()
  await ownerPanel.getByLabel('Confirm cleanup workspace ID').fill(workspace)
  await ownerPanel.getByLabel('Confirm exact '+label+' ID').fill(randomUUID())
  await button(ownerPanel,'Remove approved '+label+' registration').click()
  await ownerPanel.getByRole('alert').getByText('Enter the exact '+label+' ID to confirm registration removal.').waitFor()
  await ownerPanel.getByLabel('Confirm exact '+label+' ID').fill(file)
  await button(ownerPanel,'Remove approved '+label+' registration').click()
  await ownerPanel.getByRole('heading',{name:(roomMode?'Room':'Workspace')+' file registration removed',exact:true}).waitFor()
  if(roomMode) {
    assert.equal(sql(`select count(*) from sectalk_private.st_v6_room_files where room='${room}' and id='${file}';`),'0')
    assert.equal(sql(`select count(*) from sectalk_private.st_v8_offboarding_room_file_retirements
      where (room,file,copy_id)=('${room}','${file}','${copy}');`),'1')
  } else {
    assert.equal(sql(`select count(*) from sectalk_private.st_v6_workspace_files where workspace='${workspace}' and id='${file}';`),'0')
    assert.equal(sql(`select count(*) from sectalk_private.st_v8_offboarding_workspace_file_retirements
      where (workspace,file,copy_id)=('${workspace}','${file}','${copy}');`),'1')
    assert.equal(sql(`select count(*) from sectalk_private.st_v6_workspace_retired_file_ids
      where (workspace,id)=('${workspace}','${file}');`),'1')
    assert.equal(sql(`select count(*) from sectalk_private.st_v6_workspace_file_history_subjects
      where (workspace,id)=('${workspace}','${file}') and removed_at is not null;`),'1')
    assert.ok(Number(sql(`select count(*) from sectalk_private.st_v6_workspace_file_events
      where (workspace,file_id)=('${workspace}','${file}') and event='download';`))>0)
  }
  assert.deepEqual(Buffer.from(await data(await bucket.download(retainedPath)).arrayBuffer()),bytes)
  if(process.env.SECTALK_OFFBOARDING_RECONCILE_RECEIPTS==='1') {
    for(const view of [requester,judge])
      await view.panel.locator('summary').filter({hasText:/^Source erasure reconciliation$/}).click()
    const census=view=>view.panel.getByRole('region',{name:'Source erasure reconciliation',exact:true})
    const ownerCensus=census(requester), reviewerCensus=census(judge)
    const count=(scope,label)=>scope.locator('dt').filter({hasText:label}).locator('xpath=following-sibling::dd[1]')
    const removalLabel=(roomMode?'Room':'Workspace')+' file registration removal receipts'
    await count(ownerCensus.getByRole('region',{name:'Verified scoped deletion receipts'}),removalLabel)
      .getByText('1',{exact:true}).waitFor()
    const recovery=ownerCensus.getByRole('region',{name:'Verified copy and recovery evidence'})
    for(const label of ['Verified '+scope+' file copies','Independently verified retained '+scope+' files'])
      await count(recovery,label).getByText('1',{exact:true}).waitFor()
    await ownerCensus.getByLabel('Confirm reconciliation workspace ID').fill(workspace)
    await button(ownerCensus,'Capture current source reconciliation').click()
    await ownerCensus.getByText('Current reconciliation awaits independent review.',{exact:true}).waitFor()
    await button(reviewerCensus,'Refresh source reconciliation').click()
    await reviewerCensus.getByLabel('Confirm reconciliation workspace ID').fill(workspace)
    await button(reviewerCensus,'Confirm exact source reconciliation').click()
    await reviewerCensus.getByText('Current reconciliation independently confirmed.',{exact:true}).waitFor()
    data(await bucket.copy(retainedPath,path))
    await button(ownerCensus,'Refresh source reconciliation').click()
    await ownerCensus.getByText('Reconciliation changed, expired, or is blocked.',{exact:true}).waitFor()
    await ownerCensus.getByText('Previously retired paths are present again in Storage metadata.',{exact:true}).waitFor()
    const storage=ownerCensus.getByRole('region',{name:'Current Storage metadata'})
    await count(storage,'Retired '+scope+' file paths present again').getByText('1',{exact:true}).waitFor()
    await ownerCensus.getByText('Provider bytes, backups, and full tenant erasure are unverified.',{exact:true}).waitFor()
    assert.deepEqual(Buffer.from(await data(await bucket.download(path)).arrayBuffer()),bytes)
    assert.deepEqual(Buffer.from(await data(await bucket.download(retainedPath)).arrayBuffer()),bytes)
  }
  console.log('PASS '+scope+' exact retained bytes, documented absence, registration removal and preserved Storage')
}

try {
  const [owner,reviewer]=await Promise.all([user('owner'),user('reviewer')])
  const workspace=data(await owner.client.rpc('st_v2_create_workspace',{p_name:'Private Storage copy QA '+suffix}))
  assert.match(workspace,/^[a-f0-9-]{36}$/)
  const file=randomUUID(), request=randomUUID(), approval=randomUUID(), hold=randomUUID(), room=randomUUID()
  const filename='offboarding-proof.txt'
  const bytes=Buffer.from('Synthetic archive bytes '+suffix)
  const args={p_actor:owner.id,p_id:file,p_bytes:bytes.length,p_hash:hash(bytes),
    ...(roomMode?{p_room:room,p_name:filename}:{p_workspace:workspace,p_filename:filename})}
  sql(`insert into public.st_v2_members(workspace_id,user_id,role) values('${workspace}','${reviewer.id}','admin');
    insert into sectalk_private.st_v8_offboarding_reviewers values('${workspace}','${reviewer.id}');`)
  if(roomMode) sql(`insert into public.st_v6_rooms(id,workspace_id,name,kind,template,creator)
    values('${room}','${workspace}','Disposable Storage room','public','blank','${owner.id}');
    insert into public.st_v6_room_members(room_id,user_id,role)
      values('${room}','${owner.id}','owner'),('${room}','${reviewer.id}','moderator');`)
  const fileCommand=roomMode?'st_v6_room_file_command':'st_v6_workspace_file_command'
  data(await service.rpc(fileCommand,{...args,p_action:'reserve'}))
  path=workspace+'/'+(roomMode?'rooms/'+room+'/':'')+file
  data(await bucket.upload(path,bytes,{contentType:'application/octet-stream'}))
  data(await service.rpc(fileCommand,{...args,p_action:'publish'}))
  const [requester,judge]=await Promise.all([open(owner,'Organization settings'),open(reviewer,'Compliance exports')])
  const scope={p_workspace:workspace,p_confirmation:workspace}
  data(await requester.native.rpc('st_v8_workspace_offboarding_change',{...scope,p_id:request,p_action:'requested',p_reason:'Prepare disposable exact Storage copy proof.'}))
  data(await judge.native.rpc('st_v8_workspace_offboarding_change',{...scope,p_id:request,p_action:'approved'}))
  data(await requester.native.rpc('st_v8_offboarding_content',{...scope,p_id:approval,
    p_action:roomMode?'export_content_room_files':'export_content_files'}))
  data(await judge.native.rpc('st_v8_offboarding_content',{...scope,p_id:approval,p_action:'approve'}))
  const caseId=data(await requester.native.rpc('st_v8_workspace_offboarding',{p_workspace:workspace})).request.case
  sql(`insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action) values('${caseId}','${workspace}','${owner.id}','downloaded');`)
  data(await requester.native.rpc('st_v8_workspace_offboarding_change',{...scope,p_id:request,p_action:'read_only'}))
  const plan=data(await requester.native.rpc('st_v8_offboarding_storage_plan',{...scope,p_action:'capture'}))
  const proofQuery=new URLSearchParams({...(roomMode?{room}:{workspace}),file,offboarding:approval,'offboarding-storage-plan':plan.plan})
  const proofUrl=new URL((roomMode?'/api/room-files?':'/api/workspace-files?')+proofQuery,app)
  const get=actor=>fetch(proofUrl,{headers:{Authorization:'Bearer '+actor.token}})
  if(roomMode) {
    const mixed=new URL(proofUrl)
    mixed.searchParams.set('residency-verify',randomUUID())
    assert.equal((await fetch(mixed,{headers:{Authorization:'Bearer '+requester.token}})).status,404)
  }
  assert.equal((await get(requester)).status,404)
  data(await judge.native.rpc('st_v8_offboarding_storage_plan',{...scope,p_action:'confirm',p_plan:plan.plan,p_sha256:plan.sha256}))
  assert.equal((await get(judge)).status,404)
  await requester.refresh()
  const storage=requester.panel.getByRole('region',{name:'Offboarding Storage review',exact:true})
  await storage.getByText('Current Storage inventory independently confirmed.',{exact:true}).waitFor()
  const content=requester.panel.getByRole('region',{name:'Workspace content export',exact:true})
  await button(content,'Refresh content approval').click()
  const manifest=requester.page.waitForEvent('download')
  await button(content,'Download next content page').click()
  await manifest
  const proved=requester.page.waitForEvent('download')
  await button(content,'Verify and download '+filename).click()
  assert.deepEqual(await readFile(await (await proved).path()),bytes)
  await content.getByText('Exact Storage copy verified and issued.',{exact:true}).waitFor()
  await storage.locator('dt').filter({hasText:roomMode?'Verified room file copies':'Verified workspace file copies'})
    .locator('xpath=following-sibling::dd[1]').getByText('1',{exact:true}).waitFor()
  const auditScope={p_workspace:workspace,p_plan:plan.plan}
  const receipts=roomMode?'st_v8_offboarding_room_storage_copies':'st_v8_offboarding_storage_copies'
  const copies=data(await judge.native.rpc(receipts,auditScope)).verifiedCopies
  assert.equal(copies.length,1)
  assert.deepEqual([copies[0].file,copies[0].bytes,copies[0].sha256],[file,bytes.length,hash(bytes)])
  if(roomMode) assert.equal(copies[0].room,room)
  assert.deepEqual(Buffer.from(await data(await bucket.download(path)).arrayBuffer()),bytes)
  const replay=await get(requester)
  assert.equal(replay.status,200)
  assert.equal(replay.headers.get('x-sectalk-storage-copy-receipt'),copies[0].id)

  if(registrationMode) await verifyRegistrationCleanup(requester,judge,{workspace,room,file,copy:copies[0].id,bytes,filename,hold,owner:owner.id})
  else {
    sql(`insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
      values('${hold}','${workspace}','${owner.id}','Keep synthetic approved bytes during review.','${owner.id}');`)
    assert.equal((await get(requester)).status,404)
    assert.equal((await judge.native.rpc(receipts,auditScope)).error?.code,'42501')
    sql(`update sectalk_private.st_v6_workspace_holds set released_at=now(),released_by='${owner.id}',
      release_reason='Release the synthetic hold.' where id='${hold}';`)
    const replacement=Buffer.from(bytes.map(byte=>byte^1))
    data(await bucket.update(path,replacement,{contentType:'application/octet-stream'}))
    assert.equal((await get(requester)).status,404)
    assert.equal((await judge.native.rpc(receipts,auditScope)).error?.code,'42501')
    assert.deepEqual(Buffer.from(await data(await bucket.download(path)).arrayBuffer()),replacement)
    console.log('PASS exact '+(roomMode?'room':'workspace')+' file bytes, independent Storage receipt, idempotency, hold and same-size replacement')
  }
} finally {
  await browser.close()
  if(path&&!registrationMode) data(await bucket.remove([path]))
}
