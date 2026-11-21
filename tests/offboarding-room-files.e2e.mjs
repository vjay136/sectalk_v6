import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import {execFileSync} from 'node:child_process'
import {createHash,randomUUID} from 'node:crypto'
import {createClient} from '@supabase/supabase-js'
import {verifyStaffPanel} from './workspace-admin-fixture.mjs'

const app=new URL(process.env.SECTALK_STORAGE_TEST_APP)
const backend=new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname,'127.0.0.1')
assert.equal(backend.origin,'http://127.0.0.1:55321')
const options={auth:{persistSession:false,autoRefreshToken:false}}
const publicKey=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const service=createClient(backend.href,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
const suffix=randomUUID().slice(0,8),password=randomUUID()+'!5a'
const actors=[],workspaces=[]
let primaryFailure=false
const roomFilePaths=[]
const sql=statement=>execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-q','-v','ON_ERROR_STOP=1',
  '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true})
function data(result){if(result.error)throw result.error;return result.data}
async function account(label){
  const handle='wo_'+label+'_'+suffix,email=handle+'@example.invalid'
  const {user}=data(await service.auth.admin.createUser({email,password,email_confirm:true}))
  actors.push(user.id)
  const client=createClient(backend.href,publicKey,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:label+' offboarding QA'}))
  return {id:user.id,email,client}
}
const button=(scope,name)=>scope.getByRole('button',{name,exact:true})
async function open(actor,tab) {
  const page=await browser.newPage()
  await page.goto(app.href)
  await page.getByLabel('Email address',{exact:true}).fill(actor.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await button(page.getByRole('navigation',{name:'SecTalk features'}),'Workspaces').click()
  await button(page,tab).click()
  const panel=page.getByRole('region',{name:'Workspace offboarding',exact:true})
  await verifyStaffPanel(panel)
  await button(panel,'Refresh offboarding status').waitFor()
  return {page,panel,refresh:()=>button(panel,'Refresh offboarding status').click()}
}
async function browserScope(page) {
  const token=await page.evaluate(()=>{
    const key=Object.keys(localStorage).find(key=>/^sb-.+-auth-token$/.test(key))
    return JSON.parse(localStorage.getItem(key)).access_token
  })
  return {token,client:createClient(backend.href,publicKey,{...options,global:{headers:{Authorization:'Bearer '+token}}})}
}
const digest=value=>createHash('sha256').update(value).digest('hex')

try {
  const [owner,reviewer,outsider]=await Promise.all(['owner','reviewer','outside'].map(account))
  const workspace=data(await owner.client.rpc('st_v2_create_workspace',{p_name:'Room archive synthetic '+suffix}))
  workspaces.push(workspace)
  sql(`insert into public.st_v2_members(workspace_id,user_id,role) values('${workspace}','${reviewer.id}','admin');
    insert into sectalk_private.st_v8_offboarding_reviewers values('${workspace}','${reviewer.id}');`)
  const ownerPage=await open(owner,'Organization settings')
  const current=await browserScope(ownerPage.page)
  const judge=await open(reviewer,'Compliance exports')
  const reviewerScope=await browserScope(judge.page)
  const scope={p_workspace:workspace}
  const content=ownerPage.panel.getByRole('region',{name:'Workspace content export',exact:true})
  const contentReview=judge.panel.getByRole('region',{name:'Workspace content export',exact:true})
  const pageButton=button(content,'Download next content page')
  const privateRoom=randomUUID(),differentRoom=randomUUID()
  const roomName='Scoped private files '+suffix
  const roomInput={p_workspace:workspace,p_kind:'private',p_template:'blank'}
  data(await current.client.rpc('st_v6_room_create',{...roomInput,p_id:privateRoom,p_name:roomName}))
  data(await current.client.rpc('st_v6_room_create',{...roomInput,p_id:differentRoom,p_name:'Excluded source '+suffix}))
  sql(`insert into public.st_v2_members(workspace_id,user_id,role) values('${workspace}','${outsider.id}','member');
    insert into public.st_v6_room_members(room_id,user_id,role) values
      ('${privateRoom}','${reviewer.id}','member'),('${privateRoom}','${outsider.id}','member');`)
  async function publishedRoomFile(room,actor,name) {
    const id=randomUUID(), path=workspace+'/rooms/'+room+'/'+id
    const content=Buffer.from('Synthetic approved room archive object '+id)
    const args={p_room:room,p_actor:actor,p_id:id,p_name:name,p_bytes:content.length,p_hash:digest(content)}
    assert.ok(data(await service.rpc('st_v6_room_file_command',{...args,p_action:'reserve'})))
    data(await service.storage.from('sectalk-workspace-files').upload(path,content,{contentType:'application/octet-stream'}))
    roomFilePaths.push(path)
    assert.equal(data(await service.rpc('st_v6_room_file_command',{...args,p_action:'publish'})).id,id)
    return {id,room,name,content}
  }
  const ownedFile=await publishedRoomFile(privateRoom,owner.id,'owner-private.txt')
  const thirdParty=await publishedRoomFile(privateRoom,outsider.id,'third-party-private.txt')
  const withoutReviewer=await publishedRoomFile(differentRoom,owner.id,'private-no-reviewer.txt')
  await button(content,'Refresh content approval').click()
  await content.getByLabel('Confirm workspace ID for room file export').fill(workspace)
  await button(content,'Request content and room file approval').click()
  await content.getByText('This request includes eligible standard room files.',{exact:true}).waitFor()
  await button(contentReview,'Refresh content approval').click()
  await contentReview.getByText('This request includes eligible standard room files.',{exact:true}).waitFor()
  await contentReview.getByLabel('Confirm content export workspace ID').fill(workspace)
  await button(contentReview,'Approve exact content revisions').click()
  await contentReview.getByText(/1 approved records/).waitFor()
  await button(content,'Refresh content approval').click()
  const approvedRoom=data(await current.client.rpc('st_v8_offboarding_content',scope))
  const roomGet=(file,token=current.token)=>fetch(new URL('/api/room-files?'+new URLSearchParams({
    room:file.room,file:file.id,offboarding:approvedRoom.id,
  }),app),{headers:{Authorization:'Bearer '+token}})
  const roomExact=await roomGet(ownedFile)
  assert.equal(roomExact.status,200,roomExact.ok?'':await roomExact.text())
  assert.equal(roomExact.headers.get('x-sectalk-file-sha256'),digest(ownedFile.content))
  assert.deepEqual(Buffer.from(await roomExact.arrayBuffer()),ownedFile.content)
  assert.equal((await roomGet(thirdParty)).status,404)
  assert.equal((await roomGet(withoutReviewer)).status,404)
  assert.equal((await roomGet(ownedFile,reviewerScope.token)).status,404)
  let roomRecord
  for(let index=0;index<2&&!roomRecord;index++){
    const [result]=await Promise.all([ownerPage.page.waitForEvent('download'),pageButton.click()])
    roomRecord=JSON.parse(await readFile(await result.path(),'utf8')).records.find(item=>item.kind==='room_file')
  }
  assert.equal(roomRecord.id,ownedFile.id)
  assert.equal(JSON.parse(roomRecord.json).sha256,digest(ownedFile.content))
  const [roomDownload]=await Promise.all([ownerPage.page.waitForEvent('download'),button(content,'Download '+ownedFile.name).click()])
  assert.deepEqual(await readFile(await roomDownload.path()),ownedFile.content)
  sql(`delete from public.st_v6_room_members where room_id='${privateRoom}' and user_id='${reviewer.id}';`)
  assert.equal((await roomGet(ownedFile)).status,404)
  sql(`insert into public.st_v6_room_members(room_id,user_id,role) values('${privateRoom}','${reviewer.id}','member');`)
  const hold=randomUUID()
  data(await current.client.rpc('st_v6_place_workspace_hold',{p_workspace:workspace,p_id:hold,p_room:privateRoom,p_member:null,
    p_from:null,p_until:null,p_reason:'Preserve the scoped synthetic room for the legal hold test.'}))
  assert.equal((await roomGet(ownedFile)).status,404)
  data(await current.client.rpc('st_v6_release_workspace_hold',{p_workspace:workspace,p_id:hold,p_reason:'Release the disposable fixture hold.'}))
  console.log('Passed private room source, immutable SHA-256, exact Storage bytes and denials for unauthorized uploader, inaccessible room, reviewer, role revocation and legal hold.')
} catch(cause) {
  primaryFailure=true
  throw cause
} finally {
  try {
    await browser.close()
    if(roomFilePaths.length)await service.storage.from('sectalk-workspace-files').remove(roomFilePaths)
    for(const workspace of workspaces)sql(`begin; set local session_replication_role=replica;
      delete from sectalk_private.st_v8_content_export_entries where export_id in (
        select id from sectalk_private.st_v8_content_exports where workspace='${workspace}');
      set local session_replication_role=origin;
      delete from sectalk_private.st_v6_workspace_holds where workspace_id='${workspace}';
      delete from sectalk_private.st_v6_room_files where workspace='${workspace}';
      delete from public.st_v2_workspaces where id='${workspace}'; commit;`)
    for(const actor of actors)sql(`delete from auth.users where id='${actor}';`)
  } catch(cause) {
    if(!primaryFailure)throw cause
    console.error('Disposable room archive fixture cleanup failed.')
  }
}
