import assert from 'node:assert/strict'
import {execFileSync,spawn} from 'node:child_process'
import {createHash,createHmac,randomBytes,randomUUID} from 'node:crypto'
import {readFile} from 'node:fs/promises'
import {createServer} from 'node:http'
import {setTimeout as delay} from 'node:timers/promises'
import {createClient} from '@supabase/supabase-js'
import {fixtureAuthenticator} from './workspace-admin-fixture.mjs'

const options={auth:{persistSession:false,autoRefreshToken:false}}
const source={
  project:'v6-i232-qa',database:'http://127.0.0.1:56651',app:'http://127.0.0.1:3671',
  publicKey:process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY,serviceKey:process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,
  users:[],
}
const destination={
  project:'v6-bundle243-qa',database:'http://127.0.0.1:56801',app:'http://127.0.0.1:3672',
  publicKey:process.env.SECTALK_RESIDENCY_TARGET_PUBLIC_KEY,serviceKey:process.env.SECTALK_RESIDENCY_TARGET_KEY,
  users:[],
}
const workspace=randomUUID(),room=randomUUID(),anchor=randomUUID(),post=randomUUID(),handoff=randomUUID(),approval=randomUUID()
const reply=randomUUID(),anchorReply=randomUUID(),task=randomUUID()
const attachment=randomUUID(),attachmentName='Reviewed room attachment.txt'
const attachmentBytes=Buffer.from('Synthetic attachment '+attachment+'\n')
const attachmentHash=createHash('sha256').update(attachmentBytes).digest('hex')
const attachmentPath=`${workspace}/rooms/${room}/${attachment}`
const cell=randomUUID(),plan=randomBytes(32).toString('hex'),secret=randomBytes(32).toString('hex')
const roomName='Reviewed project room',body='Recovered owner room message '+post.slice(0,8)
const replyBody='Recovered owner thread reply '+reply.slice(0,8)
const anchorReplyBody='Recovered reply to imported history '+anchorReply.slice(0,8)
const taskTitle='Recovered owner task '+task.slice(0,8)
let browser,scanner,scanCount=0

function sql(site,input){
  return execFileSync('docker',['exec','-i','supabase_db_'+site.project,'psql','-XqtA','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'],{input,encoding:'utf8',windowsHide:true}).trim()
}
function data(result){
  if(result.error)throw new Error(result.error.message)
  return result.data
}
async function actor(site,label,email){
  const handle=label+'_'+randomUUID().slice(0,8)
  const address=email||handle+'@example.invalid'
  const password=randomUUID()+'!aS'
  const api=createClient(site.database,site.publicKey,options)
  const {user}=data(await site.admin.auth.admin.createUser({email:address,password,email_confirm:true}))
  site.users.push(user.id)
  data(await api.auth.signInWithPassword({email:address,password}))
  data(await api.rpc('st_save_profile',{p_handle:handle,p_name:'Synthetic room recovery operator'}))
  await fixtureAuthenticator(api)
  return {id:user.id,api}
}
function hold(side){
  return `insert into sectalk_private.st_v8_residency_rollback_holds(workspace,approval,handoff,side)
    values('${workspace}','${approval}','${handoff}','${side}');`
}
function common(site,owner,reviewer,phase){
  sql(site,`begin;
    insert into public.st_v2_workspaces(id,name,owner) values('${workspace}','Disposable room recovery','${owner.id}');
    insert into public.st_v2_members(workspace_id,user_id,role)
      values('${workspace}','${owner.id}','owner'),('${workspace}','${reviewer.id}','admin');
    insert into sectalk_private.st_v8_offboarding_reviewers values('${workspace}','${reviewer.id}');
    insert into public.st_v6_rooms(id,workspace_id,name,kind,template,creator,classification)
      values('${room}','${workspace}','${roomName}','${phase==='held'?'public':'private'}','blank','${owner.id}',
        '${phase==='held'?'internal':'confidential'}');
    insert into public.st_v6_room_members(room_id,user_id,role) values('${room}','${owner.id}','owner'),('${room}','${reviewer.id}','member');
    insert into public.st_v6_room_posts(room_id,id,sender,body,kind,created_at)
      values('${room}','${anchor}','${reviewer.id}','Previously approved history','message','2025-01-01T00:00:00Z');
    insert into sectalk_private.st_v8_residency_write_handoffs(workspace,approval,handoff,source_project,destination_project,phase,changed_at)
      values('${workspace}','${approval}','${handoff}','${source.project}','${destination.project}','${phase}',now()-interval '1 minute');
    insert into sectalk_private.st_v8_residency_rollback_manifest_admissions
      values('${handoff}',vault.create_secret('${secret}'),'${plan}',now()+interval '1 hour');
    commit;`)
}
async function pageFor(site,who){
  const session=data(await who.api.auth.getSession()).session
  const context=await browser.newContext({acceptDownloads:true,storageState:{cookies:[],origins:[{
    origin:site.app,localStorage:[{name:'sb-127-auth-token',value:JSON.stringify(session)}],
  }]}})
  const page=await context.newPage()
  await page.goto(site.app+'/?workspace='+workspace)
  return page
}
const recovery=page=>page.getByRole('region',{name:'Standard room rollback replay',exact:true})
const taskRecovery=page=>page.getByRole('region',{name:'Room task rollback replay',exact:true})
const review=page=>page.getByRole('region',{name:'Destination rollback change review',exact:true})
const sourceEvidence=page=>page.getByRole('region',{name:'Source rollback verification',exact:true})
async function submit(panel,confirmation,button){
  await panel.getByLabel(confirmation,{exact:true}).fill(workspace)
  await panel.getByRole('button',{name:button,exact:true}).click()
}
async function recoveredRow(who,id=post){
  return data(await who.api.from('st_v6_room_posts').select('room_id,id,sender,body,created_at,parent_id')
    .eq('room_id',room).eq('id',id).single())
}
async function recoveredTask(who){
  return data(await who.api.from('st_v6_tasks').select('*').eq('room_id',room).eq('id',task).single())
}
async function fileRequest(site,who,path,init={}){
  const session=data(await who.api.auth.getSession()).session
  return fetch(site.app+path,{...init,headers:{...init.headers,Authorization:'Bearer '+session.access_token}})
}

async function verifyEvidenceWaitsForRoomRow(startCapture){
  const locker=spawn('docker',['exec','-i','supabase_db_'+source.project,'psql','-XqtA','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'],{windowsHide:true,stdio:['pipe','pipe','inherit']})
  const exited=new Promise(resolve=>locker.once('close',resolve))
  let pending
  try{
    locker.stdin.write(`begin;
      select pg_backend_pid() from public.st_v6_room_posts where (room_id,id)=('${room}','${anchor}') for no key update;
    \n`)
    const [chunk]=await Promise.race([
      new Promise(resolve=>locker.stdout.once('data',data=>resolve([data]))),
      delay(5000,[Buffer.from('')],{ref:false}),
    ])
    const pid=chunk.toString().trim()
    assert.match(pid,/^\d+$/,'The verified preexisting thread root must be locked')
    pending=Promise.resolve(startCapture())
    let blocked=false
    for(let attempt=0;attempt<20&&!blocked;attempt++){
      blocked=sql(source,`select exists(select 1 from pg_stat_activity where ${pid}=any(pg_blocking_pids(pid)));\n`)==='t'
      if(!blocked)await delay(100)
    }
    assert.equal(blocked,true,'Recording evidence must wait for the exact preexisting root')
  }finally{
    locker.stdin.end('rollback;\n')
    assert.equal(await exited,0)
    if(pending)assert.equal((await pending).error?.code,'PT409','The lock probe uses a deliberately stale digest')
  }
}

try{
  const scannerSecret=process.env.SECTALK_RESIDENCY_SCANNER_TEST_SECRET
  assert.ok(scannerSecret&&scannerSecret.length>=32,'Configure both loopback app fixtures with the test scanner secret')
  scanner=createServer(async(request,response)=>{
    const chunks=[]
    for await(const chunk of request)chunks.push(chunk)
    if(request.method!=='POST'||request.url!=='/scan'||request.headers.authorization!=='Bearer '+scannerSecret
      ||!Buffer.concat(chunks).equals(attachmentBytes))return response.writeHead(403).end()
    scanCount++
    response.writeHead(200,{'Content-Type':'application/json'})
      .end(JSON.stringify({verdict:'clean',sha256:attachmentHash}))
  })
  await new Promise((ready,fail)=>scanner.once('error',fail).listen(3605,'127.0.0.1',ready))
  for(const site of [source,destination]){
    assert.ok(site.publicKey&&site.serviceKey,'Use only credentials for the two disposable loopback fixtures')
    const health=await fetch(site.app+'/api/health')
    assert.equal(health.status,200)
    assert.equal((await health.json()).status,'configured')
    site.admin=createClient(site.database,site.serviceKey,options)
  }
  const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const email='rr_owner_'+randomUUID().slice(0,8)+'@example.invalid'
  const rootAuthorEmail='rr_root_'+randomUUID().slice(0,8)+'@example.invalid'
  const [sourceOwner,sourceReviewer,destinationOwner,destinationReviewer]=await Promise.all([
    actor(source,'rr_so',email),actor(source,'rr_sr',rootAuthorEmail),actor(destination,'rr_do',email),
    actor(destination,'rr_dr',rootAuthorEmail),
  ])
  assert.notEqual(sourceOwner.id,destinationOwner.id)
  assert.notEqual(sourceReviewer.id,destinationReviewer.id)
  common(source,sourceOwner,sourceReviewer,'held')
  common(destination,destinationOwner,destinationReviewer,'activated')
  sql(source,`begin;
    insert into sectalk_private.st_v8_content_exports(id,workspace,requester,reviewer,approved_at,expires_at)
      values('${approval}','${workspace}','${sourceOwner.id}','${sourceReviewer.id}',now(),now()+interval '1 hour');
    insert into sectalk_private.st_v8_content_export_entries
      select '${approval}',1,e.kind,e.scope_id,e.record_id,encode(sha256(convert_to(e.item::text,'UTF8')),'hex')
      from sectalk_private.st_v8_content_export_records('${workspace}','${sourceOwner.id}','${sourceReviewer.id}',
        'room_message','${room}','${anchor}') e;
    ${hold('source')} commit;`)
  const approvedRoot=await recoveredRow(sourceOwner,anchor)
  assert.equal(approvedRoot.sender,sourceReviewer.id)
  const approvedRootDigest=sql(source,`select sha256 from sectalk_private.st_v8_content_export_entries
    where (export_id,kind,scope_id,record_id)=('${approval}','room_message','${room}','${anchor}');`)
  assert.match(approvedRootDigest,/^[a-f0-9]{64}$/)
  assert.deepEqual(await recoveredRow(destinationOwner,anchor),{...approvedRoot,sender:destinationReviewer.id})
  sql(destination,`begin;
    insert into sectalk_private.st_v8_residency_cells values('${cell}','eu','rr-${cell}','Disposable room recovery','fixture',null);
    insert into sectalk_private.st_v8_residency_content_admissions values('${cell}','${workspace}','${source.project}',
      '${approval}','${plan}',1,now()+interval '1 hour');
    insert into sectalk_private.st_v8_residency_staged_content(cell,workspace,source_project,approval,records)
      values('${cell}','${workspace}','${source.project}','${approval}','[]');
    insert into sectalk_private.st_v8_residency_room_imports(cell,workspace,source_project,approval,room,room_name,actor,evidence_count,imported_at)
      values('${cell}','${workspace}','${source.project}','${approval}','${room}','${roomName}','${destinationOwner.id}',1,now()-interval '2 minutes');
    insert into sectalk_private.st_v8_residency_room_history(workspace,approval,room,post,actor,record_digest,imported_at)
      values('${workspace}','${approval}','${room}','${anchor}','${destinationReviewer.id}','${approvedRootDigest}',now()-interval '2 minutes');
    insert into sectalk_private.st_v8_residency_rollback_baselines(handoff,snapshot)
      values('${handoff}',sectalk_private.st_v8_residency_rollback_snapshot('${workspace}'));
    commit;`)
  data(await destinationOwner.api.rpc('st_v6_room_post',{p_room:room,p_id:post,p_body:body}))
  data(await destinationOwner.api.rpc('st_v6_room_post',{p_room:room,p_id:reply,p_body:replyBody,p_parent:post}))
  data(await destinationOwner.api.rpc('st_v6_room_post',{p_room:room,p_id:anchorReply,p_body:anchorReplyBody,p_parent:anchor}))
  data(await destinationOwner.api.rpc('st_v6_task_create',{p_id:task,p_room:room,p_chat:null,p_title:taskTitle,
    p_due_at:'2030-01-01T00:00:00Z',p_priority:'high',p_labels:['release']}))
  const roomFileUrl='/api/room-files?'+new URLSearchParams({room,file:attachment})
  const uploaded=await fileRequest(destination,destinationOwner,roomFileUrl,{method:'POST',body:attachmentBytes,
    headers:{'Content-Type':'text/plain','X-SecTalk-File-Name':encodeURIComponent(attachmentName)}})
  assert.equal(uploaded.status,200,await uploaded.text())
  const original=await recoveredRow(destinationOwner)
  const originalReply=await recoveredRow(destinationOwner,reply)
  const originalAnchorReply=await recoveredRow(destinationOwner,anchorReply)
  const originalTask=await recoveredTask(destinationOwner)
  sql(destination,hold('destination'))

  const destinationOwnerPage=await pageFor(destination,destinationOwner)
  await submit(review(destinationOwnerPage),'Confirm change review workspace ID','Capture destination changes')
  await review(destinationOwnerPage).getByText('Awaiting independent review.',{exact:true}).waitFor()
  const destinationReviewerPage=await pageFor(destination,destinationReviewer)
  await submit(review(destinationReviewerPage),'Confirm change review workspace ID','Confirm independent change review')
  await review(destinationReviewerPage).getByText('The independent review is current. Workspace writes remain held.',{exact:true}).waitFor()
  await review(destinationOwnerPage).getByRole('button',{name:'Refresh change review',exact:true}).click()
  await review(destinationOwnerPage).getByText('The independent review is current. Workspace writes remain held.',{exact:true}).waitFor()

  const manifest=(who,action,packet)=>who.api.rpc('st_v8_residency_rollback_manifest',{
    p_workspace:workspace,p_confirmation:workspace,p_action:action,p_packet:packet,
  })
  const issuedManifest=data(await manifest(destinationOwner,'issue')).packet
  assert.equal(data(await manifest(sourceOwner,'receive',issuedManifest)).state,'received')
  const currentReview=data(await destinationOwner.api.rpc('st_v8_residency_rollback_reconcile',{p_workspace:workspace}))
  const destinationFileUrl='/api/workspaces/residency/room-file-copy?'+new URLSearchParams({
    workspace,file:attachment,'residency-rollback':currentReview.id,
  })
  assert.equal((await fileRequest(destination,destinationReviewer,destinationFileUrl)).status,404)
  await review(destinationOwnerPage).getByText('View record revisions',{exact:true}).click()
  const attachmentEvent=destinationOwnerPage.waitForEvent('download')
  await review(destinationOwnerPage).getByRole('listitem').filter({hasText:attachment})
    .getByRole('button',{name:'Download reviewed room file copy',exact:true}).click()
  const attachmentDownload=await attachmentEvent
  const attachmentPackage=await readFile(await attachmentDownload.path())
  const transferFile=JSON.parse(attachmentPackage.toString())
  const fileProof=JSON.parse(transferFile.proof.payload)
  assert.equal(fileProof.format,'sectalk-residency-room-file-copy-v1')
  assert.equal(fileProof.room,room)
  assert.equal(fileProof.sha256,attachmentHash)
  assert.equal(transferFile.proof.signature,createHmac('sha256',Buffer.from(secret,'hex'))
    .update(transferFile.proof.payload).digest('hex'))
  assert.deepEqual(Buffer.from(transferFile.contentBase64,'base64'),attachmentBytes)

  const downloadEvent=destinationOwnerPage.waitForEvent('download')
  await submit(recovery(destinationOwnerPage),'Confirm room message recovery workspace ID','Download room message recovery file')
  const download=await downloadEvent
  assert.equal(download.suggestedFilename(),'sectalk-room-message-recovery-'+workspace+'.json')
  const packetBytes=await readFile(await download.path())
  const wire=JSON.parse(JSON.parse(packetBytes.toString()).payload)
  const replies=[{id:reply,room,body:replyBody,parent:post},{id:anchorReply,room,body:anchorReplyBody,parent:anchor}]
    .sort((left,right)=>left.id.localeCompare(right.id))
  assert.deepEqual(wire.records.map(({id,room,body,parent})=>({id,room,body,parent})),[
    {id:post,room,body,parent:undefined},...replies,
  ])
  const proof=wire.records.find(record=>record.id===anchorReply).existingParent
  assert.equal(proof.approvedDigest,approvedRootDigest)
  assert.equal(proof.destinationAuthor,destinationReviewer.id)
  assert.match(proof.baselineDigest,/^[a-f0-9]{64}$/)
  assert.match(proof.authorTag,/^[a-f0-9]{64}$/)
  const taskDownloadEvent=destinationOwnerPage.waitForEvent('download')
  await submit(taskRecovery(destinationOwnerPage),'Confirm room task recovery workspace ID','Download room task recovery file')
  const taskDownload=await taskDownloadEvent
  const taskPacketBytes=await readFile(await taskDownload.path())
  const taskClaim=JSON.parse(JSON.parse(taskPacketBytes.toString()).payload)
  assert.equal(taskClaim.records.length,1)
  assert.deepEqual({id:taskClaim.records[0].id,room:taskClaim.records[0].room,name:taskClaim.records[0].name,
    priority:taskClaim.records[0].priority,labels:taskClaim.records[0].labels},
    {id:task,room,name:taskTitle,priority:'high',labels:['release']})

  const sourceOwnerPage=await pageFor(source,sourceOwner)
  const manifestPanel=sourceOwnerPage.getByRole('region',{name:'Rollback recovery manifest',exact:true})
  await manifestPanel.getByLabel('Signed recovery file',{exact:true}).setInputFiles({
    name:attachmentDownload.suggestedFilename(),mimeType:'application/json',buffer:attachmentPackage,
  })
  await manifestPanel.getByRole('button',{name:'Stage reviewed file copy',exact:true}).click()
  await manifestPanel.getByText(/was staged in private storage/).waitFor()
  assert.equal((await fileRequest(source,sourceOwner,roomFileUrl)).status,404)
  await recovery(sourceOwnerPage).getByLabel('Signed room message recovery file',{exact:true}).setInputFiles({
    name:download.suggestedFilename(),mimeType:'application/json',buffer:packetBytes,
  })
  await submit(recovery(sourceOwnerPage),'Confirm room message recovery workspace ID','Stage room message recovery file')
  await recovery(sourceOwnerPage).getByText('The original independent source reviewer can apply the staged room messages.',{exact:true}).waitFor()
  assert.equal(await recovery(sourceOwnerPage).getByRole('button',{name:'Apply reviewed room messages',exact:true}).count(),0)
  assert.equal(data(await sourceOwner.api.from('st_v6_room_posts').select('id').eq('room_id',room).in('id',[post,reply,anchorReply])).length,0)
  await taskRecovery(sourceOwnerPage).getByLabel('Signed room task recovery file',{exact:true}).setInputFiles({
    name:taskDownload.suggestedFilename(),mimeType:'application/json',buffer:taskPacketBytes,
  })
  await submit(taskRecovery(sourceOwnerPage),'Confirm room task recovery workspace ID','Stage room task recovery file')
  await taskRecovery(sourceOwnerPage).getByText('The original independent source reviewer can apply the staged room tasks.',{exact:true}).waitFor()
  assert.equal(await taskRecovery(sourceOwnerPage).getByRole('button',{name:'Apply reviewed room tasks',exact:true}).count(),0)
  assert.deepEqual(data(await sourceOwner.api.from('st_v6_tasks').select('id').eq('id',task)),[])

  const sourceReviewerPage=await pageFor(source,sourceReviewer)
  const stagedAttachment=sourceEvidence(sourceReviewerPage).getByRole('listitem').filter({hasText:attachmentName})
  await stagedAttachment.getByText('Awaiting independent approval',{exact:true}).waitFor()
  await submit(stagedAttachment,'Confirm staged file workspace ID','Approve staged file')
  await stagedAttachment.getByText('Approved for restoration',{exact:true}).waitFor()
  await sourceEvidence(sourceOwnerPage).getByRole('button',{name:'Refresh source verification',exact:true}).click()
  const approvedAttachment=sourceEvidence(sourceOwnerPage).getByRole('listitem').filter({hasText:attachmentName})
  await approvedAttachment.getByText('Approved for restoration',{exact:true}).waitFor()
  await submit(approvedAttachment,'Confirm staged file workspace ID','Restore approved file')
  await approvedAttachment.getByText('Restored to room Files',{exact:true}).waitFor()
  const restored=await fileRequest(source,sourceOwner,roomFileUrl)
  assert.equal(restored.status,200)
  assert.deepEqual(Buffer.from(await restored.arrayBuffer()),attachmentBytes)
  assert.equal(sql(source,`select count(*) from sectalk_private.st_v8_residency_source_file_copies
    where handoff='${handoff}' and file='${attachment}' and room='${room}' and reviewer='${sourceReviewer.id}'
      and restored_at is not null and restored_version is not null;`),'1')
  assert.ok(scanCount>=3,'Ordinary upload, private stage and live restoration use the scanner')
  const heldFile=await fileRequest(source,sourceOwner,'/api/room-files?'+new URLSearchParams({room,file:randomUUID()}),
    {method:'POST',body:attachmentBytes,headers:{'Content-Type':'text/plain','X-SecTalk-File-Name':attachmentName}})
  assert.equal(heldFile.status,423,await heldFile.text())
  const reviewerPanel=recovery(sourceReviewerPage)
  await reviewerPanel.getByText('Review the staged room messages',{exact:true}).click()
  await reviewerPanel.getByText(body,{exact:true}).waitFor()
  const stagedReply=reviewerPanel.getByRole('listitem').filter({hasText:replyBody})
  await stagedReply.getByText(roomName,{exact:true}).waitFor()
  assert.match(await stagedReply.textContent(),/Thread reply/)
  await stagedReply.getByText(post,{exact:true}).waitFor()
  const stagedAnchorReply=reviewerPanel.getByRole('listitem').filter({hasText:anchorReplyBody})
  await stagedAnchorReply.getByText(anchor,{exact:true}).waitFor()
  await submit(reviewerPanel,'Confirm room message recovery workspace ID','Apply reviewed room messages')
  await reviewerPanel.getByText('Reviewed room messages were replayed. Workspace writes remain held.',{exact:true}).waitFor()
  assert.deepEqual(await recoveredRow(sourceOwner),{...original,sender:sourceOwner.id})
  assert.deepEqual(await recoveredRow(sourceOwner,reply),{...originalReply,sender:sourceOwner.id,parent_id:post})
  assert.deepEqual(await recoveredRow(sourceOwner,anchorReply),{...originalAnchorReply,sender:sourceOwner.id,parent_id:anchor})
  assert.deepEqual(await recoveredRow(sourceOwner,anchor),approvedRoot)
  const taskReviewerPanel=taskRecovery(sourceReviewerPage)
  await taskReviewerPanel.getByText('Review the staged room tasks',{exact:true}).click()
  const stagedTask=taskReviewerPanel.getByRole('listitem').filter({hasText:taskTitle})
  await stagedTask.getByText(roomName,{exact:true}).waitFor()
  await stagedTask.getByText('To do · high priority',{exact:true}).waitFor()
  await stagedTask.getByText('Labels release',{exact:true}).waitFor()
  await submit(taskReviewerPanel,'Confirm room task recovery workspace ID','Apply reviewed room tasks')
  await taskReviewerPanel.getByText('Reviewed room tasks were replayed. Workspace writes remain held.',{exact:true}).waitFor()
  assert.deepEqual(await recoveredTask(sourceOwner),{...originalTask,author_id:sourceOwner.id})
  for(const owner of [sourceOwner,destinationOwner]){
    assert.equal((await owner.api.rpc('st_v6_task_create',{p_id:randomUUID(),p_room:room,p_chat:null,p_title:'Ordinary held task'})).error?.code,'PT423')
  }
  assert.equal((await sourceOwner.api.rpc('st_v6_room_post',{p_room:room,p_id:randomUUID(),p_body:'Ordinary held write'})).error?.code,'PT423')
  assert.equal((await destinationOwner.api.rpc('st_v6_room_post',{p_room:room,p_id:randomUUID(),p_body:'Ordinary held write'})).error?.code,'PT423')
  await sourceReviewerPage.reload()
  await sourceReviewerPage.getByRole('region',{name:'Source rollback verification',exact:true})
    .getByText('6 of 6 reviewed changes verified at the source. Workspace writes are held.',{exact:true}).waitFor()
  await verifyEvidenceWaitsForRoomRow(()=>sourceOwner.api.rpc('st_v8_residency_source_evidence',{
    p_workspace:workspace,p_action:'capture',p_confirmation:workspace,p_digest:'0'.repeat(64),
  }))
  const retired=data(await destinationOwner.api.rpc('st_v8_residency_retire_destination',{
    p_workspace:workspace,p_action:'issue',p_confirmation:workspace,
  }))
  assert.equal(retired.state,'retired')
  const reopen=(who,action='reopen')=>who.api.rpc('st_v8_residency_reactivate_source',{
    p_workspace:workspace,p_confirmation:workspace,p_action:action,p_packet:retired.packet,
  })
  assert.equal((await reopen(sourceOwner)).error?.code,'PT409')
  await sourceEvidence(sourceOwnerPage).getByRole('button',{name:'Refresh source verification',exact:true}).click()
  await submit(sourceEvidence(sourceOwnerPage),'Confirm source evidence workspace ID','Record source evidence')
  await sourceEvidence(sourceOwnerPage).getByText('Awaiting independent sign-off on the recorded source evidence.',{exact:true}).waitFor()
  await sourceEvidence(sourceReviewerPage).getByRole('button',{name:'Refresh source verification',exact:true}).click()
  await submit(sourceEvidence(sourceReviewerPage),'Confirm source evidence workspace ID','Sign off on source evidence')
  await sourceEvidence(sourceReviewerPage)
    .getByText('The independent reviewer signed off on all changes in this manifest.',{exact:true}).waitFor()
  assert.equal((await reopen(sourceReviewer)).error?.code,'42501')
  assert.equal(data(await reopen(sourceOwner,'status')).state,'ready')
  const reactivation=sourceOwnerPage.getByRole('region',{name:'Source reactivation',exact:true})
  await reactivation.getByRole('button',{name:'Refresh source reactivation status',exact:true}).click()
  await reactivation.getByLabel('Signed destination retirement proof').setInputFiles({
    name:'retired-destination.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(retired.packet)),
  })
  await submit(reactivation,'Confirm source reactivation workspace ID','Reopen source writes')
  await reactivation.getByText(/Source write authority was restored\./).first().waitFor()
  const reopened=data(await reopen(sourceOwner))
  assert.equal(reopened.receipt,retired.receipt)
  assert.equal(reopened.state,'reopened')
  const afterReopen=randomUUID()
  data(await sourceOwner.api.rpc('st_v6_room_post',{p_room:room,p_id:afterReopen,p_body:'Authorized source write after reactivation'}))
  assert.equal((await recoveredRow(sourceOwner,afterReopen)).sender,sourceOwner.id)
  assert.equal((await destinationOwner.api.rpc('st_v6_room_post',{
    p_room:room,p_id:randomUUID(),p_body:'Destination remains held after source reactivation',
  })).error?.code,'PT423')
  console.log('Edge verified all six restored room records, locked evidence, independent sign-off and source-only write reactivation.')
} finally {
  await browser?.close()
  if(scanner?.listening)await new Promise(resolve=>scanner.close(resolve))
  for(const site of [source,destination]){
    if(!site.admin)continue
    await site.admin.storage.from('sectalk-workspace-files').remove([attachmentPath])
    if(site===source)await site.admin.storage.from('sectalk-residency-recovery')
      .remove([`${workspace}/${handoff}/${attachment}/${attachmentHash}`])
    sql(site,`begin;
      with removed as (delete from sectalk_private.st_v8_residency_rollback_manifest_admissions
        where handoff='${handoff}' returning vault_id) delete from vault.secrets s using removed r where s.id=r.vault_id;
      set local session_replication_role=replica;
      delete from sectalk_private.st_v8_content_export_entries where export_id='${approval}';
      set local session_replication_role=origin;
      delete from sectalk_private.st_v6_room_files where workspace='${workspace}' and room='${room}' and id='${attachment}';
      delete from public.st_v2_workspaces where id='${workspace}';
      delete from sectalk_private.st_v8_residency_staged_content where cell='${cell}' and approval='${approval}';
      delete from sectalk_private.st_v8_residency_content_admissions where cell='${cell}' and approval='${approval}';
      delete from sectalk_private.st_v8_residency_cells where id='${cell}'; commit;`)
    for(const id of site.users)sql(site,`delete from auth.users where id='${id}';`)
  }
}
