import assert from 'node:assert/strict'
import {execFileSync} from 'node:child_process'
import {randomBytes,randomUUID} from 'node:crypto'
import {readFile} from 'node:fs/promises'
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
const reply=randomUUID()
const cell=randomUUID(),plan=randomBytes(32).toString('hex'),secret=randomBytes(32).toString('hex')
const roomName='Reviewed project room',body='Recovered owner room message '+post.slice(0,8)
const replyBody='Recovered owner thread reply '+reply.slice(0,8)
let browser

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
    insert into public.st_v6_room_posts(room_id,id,sender,body,kind) values('${room}','${anchor}','${owner.id}','Previously approved history','message');
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
const review=page=>page.getByRole('region',{name:'Destination rollback change review',exact:true})
async function submit(panel,confirmation,button){
  await panel.getByLabel(confirmation,{exact:true}).fill(workspace)
  await panel.getByRole('button',{name:button,exact:true}).click()
}
async function recoveredRow(who,id=post){
  return data(await who.api.from('st_v6_room_posts').select('room_id,id,sender,body,created_at,parent_id')
    .eq('room_id',room).eq('id',id).single())
}

try{
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
  const [sourceOwner,sourceReviewer,destinationOwner,destinationReviewer]=await Promise.all([
    actor(source,'rr_so',email),actor(source,'rr_sr'),actor(destination,'rr_do',email),actor(destination,'rr_dr'),
  ])
  assert.notEqual(sourceOwner.id,destinationOwner.id)
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
  sql(destination,`begin;
    insert into sectalk_private.st_v8_residency_cells values('${cell}','eu','rr-${cell}','Disposable room recovery','fixture',null);
    insert into sectalk_private.st_v8_residency_content_admissions values('${cell}','${workspace}','${source.project}',
      '${approval}','${plan}',1,now()+interval '1 hour');
    insert into sectalk_private.st_v8_residency_staged_content(cell,workspace,source_project,approval,records)
      values('${cell}','${workspace}','${source.project}','${approval}','[]');
    insert into sectalk_private.st_v8_residency_room_imports(cell,workspace,source_project,approval,room,room_name,actor,evidence_count,imported_at)
      values('${cell}','${workspace}','${source.project}','${approval}','${room}','${roomName}','${destinationOwner.id}',1,now()-interval '2 minutes');
    insert into sectalk_private.st_v8_residency_rollback_baselines(handoff,snapshot)
      values('${handoff}',sectalk_private.st_v8_residency_rollback_snapshot('${workspace}'));
    commit;`)
  data(await destinationOwner.api.rpc('st_v6_room_post',{p_room:room,p_id:post,p_body:body}))
  data(await destinationOwner.api.rpc('st_v6_room_post',{p_room:room,p_id:reply,p_body:replyBody,p_parent:post}))
  const original=await recoveredRow(destinationOwner)
  const originalReply=await recoveredRow(destinationOwner,reply)
  sql(destination,hold('destination'))

  const destinationOwnerPage=await pageFor(destination,destinationOwner)
  await submit(review(destinationOwnerPage),'Confirm change review workspace ID','Capture destination changes')
  await review(destinationOwnerPage).getByText('Awaiting independent review.',{exact:true}).waitFor()
  const destinationReviewerPage=await pageFor(destination,destinationReviewer)
  await submit(review(destinationReviewerPage),'Confirm change review workspace ID','Confirm independent change review')
  await review(destinationReviewerPage).getByText('The independent review is current. Workspace writes remain held.',{exact:true}).waitFor()

  const manifest=(who,action,packet)=>who.api.rpc('st_v8_residency_rollback_manifest',{
    p_workspace:workspace,p_confirmation:workspace,p_action:action,p_packet:packet,
  })
  const issuedManifest=data(await manifest(destinationOwner,'issue')).packet
  assert.equal(data(await manifest(sourceOwner,'receive',issuedManifest)).state,'received')

  const downloadEvent=destinationOwnerPage.waitForEvent('download')
  await submit(recovery(destinationOwnerPage),'Confirm room message recovery workspace ID','Download room message recovery file')
  const download=await downloadEvent
  assert.equal(download.suggestedFilename(),'sectalk-room-message-recovery-'+workspace+'.json')
  const packetBytes=await readFile(await download.path())
  const wire=JSON.parse(JSON.parse(packetBytes.toString()).payload)
  assert.deepEqual(wire.records.map(({id,room,body,parent})=>({id,room,body,parent})),[
    {id:post,room,body,parent:undefined},{id:reply,room,body:replyBody,parent:post},
  ])

  const sourceOwnerPage=await pageFor(source,sourceOwner)
  await recovery(sourceOwnerPage).getByLabel('Signed room message recovery file',{exact:true}).setInputFiles({
    name:download.suggestedFilename(),mimeType:'application/json',buffer:packetBytes,
  })
  await submit(recovery(sourceOwnerPage),'Confirm room message recovery workspace ID','Stage room message recovery file')
  await recovery(sourceOwnerPage).getByText('The original independent source reviewer can apply the staged room messages.',{exact:true}).waitFor()
  assert.equal(await recovery(sourceOwnerPage).getByRole('button',{name:'Apply reviewed room messages',exact:true}).count(),0)
  assert.equal(data(await sourceOwner.api.from('st_v6_room_posts').select('id').eq('room_id',room).in('id',[post,reply])).length,0)

  const sourceReviewerPage=await pageFor(source,sourceReviewer)
  const reviewerPanel=recovery(sourceReviewerPage)
  await reviewerPanel.getByText('Review the staged room messages',{exact:true}).click()
  await reviewerPanel.getByText(body,{exact:true}).waitFor()
  const stagedReply=reviewerPanel.getByRole('listitem').filter({hasText:replyBody})
  await stagedReply.getByText(roomName,{exact:true}).waitFor()
  assert.match(await stagedReply.textContent(),/Thread reply/)
  await stagedReply.getByText(post,{exact:true}).waitFor()
  await submit(reviewerPanel,'Confirm room message recovery workspace ID','Apply reviewed room messages')
  await reviewerPanel.getByText('Reviewed room messages were replayed. Workspace writes remain held.',{exact:true}).waitFor()
  assert.deepEqual(await recoveredRow(sourceOwner),{...original,sender:sourceOwner.id})
  assert.deepEqual(await recoveredRow(sourceOwner,reply),{...originalReply,sender:sourceOwner.id,parent_id:post})
  assert.equal((await sourceOwner.api.rpc('st_v6_room_post',{p_room:room,p_id:randomUUID(),p_body:'Ordinary held write'})).error?.code,'PT423')
  assert.equal((await destinationOwner.api.rpc('st_v6_room_post',{p_room:room,p_id:randomUUID(),p_body:'Ordinary held write'})).error?.code,'PT423')
  await sourceReviewerPage.reload()
  await sourceReviewerPage.getByRole('region',{name:'Source rollback verification',exact:true})
    .getByText('2 of 2 reviewed changes verified at the source. Workspace writes are held.',{exact:true}).waitFor()
  console.log('Edge verified signed room thread recovery, the paired reply marker, exact native parent linkage and both write holds.')
} finally {
  await browser?.close()
  for(const site of [source,destination]){
    if(!site.admin)continue
    sql(site,`begin;
      with removed as (delete from sectalk_private.st_v8_residency_rollback_manifest_admissions
        where handoff='${handoff}' returning vault_id) delete from vault.secrets s using removed r where s.id=r.vault_id;
      set local session_replication_role=replica;
      delete from sectalk_private.st_v8_content_export_entries where export_id='${approval}';
      set local session_replication_role=origin;
      delete from public.st_v2_workspaces where id='${workspace}';
      delete from sectalk_private.st_v8_residency_staged_content where cell='${cell}' and approval='${approval}';
      delete from sectalk_private.st_v8_residency_content_admissions where cell='${cell}' and approval='${approval}';
      delete from sectalk_private.st_v8_residency_cells where id='${cell}'; commit;`)
    for(const id of site.users)sql(site,`delete from auth.users where id='${id}';`)
  }
}
