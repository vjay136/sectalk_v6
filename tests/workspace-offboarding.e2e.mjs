import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import {execFileSync} from 'node:child_process'
import {createHash,randomBytes,randomUUID} from 'node:crypto'
import {createClient} from '@supabase/supabase-js'
import {verifyStaffPanel} from './workspace-admin-fixture.mjs'
import {stageWorkspaceFiles} from '../scripts/workspace-residency-files.mjs'

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
let artifact
let primaryFailure=false
let workspaceFilePath
let fixtureMalwareHash
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
function submit(panel,title,workspace,reason) {
  const section=panel.locator('details').filter({hasText:title})
  return (async()=>{
    await section.locator('summary').click()
    if(reason)await section.getByLabel('Offboarding purpose').fill(reason)
    await section.getByLabel('Confirm workspace ID').fill(workspace)
    await button(section.locator('form'),title).click()
  })()
}
const digest=value=>createHash('sha256').update(value).digest('hex')

try {
  const [owner,reviewer,outsider]=await Promise.all(['owner','reviewer','outside'].map(account))
  const name='Offboarding synthetic '+suffix, foreignName='Other protected workspace '+suffix
  const workspace=data(await owner.client.rpc('st_v2_create_workspace',{p_name:name}))
  const other=data(await outsider.client.rpc('st_v2_create_workspace',{p_name:foreignName}))
  workspaces.push(workspace,other)
  sql(`insert into public.st_v2_members(workspace_id,user_id,role) values('${workspace}','${reviewer.id}','admin');
    insert into sectalk_private.st_v8_offboarding_reviewers values('${workspace}','${reviewer.id}');`)
  const protectedBody='Synthetic private message which never enters the inventory '+suffix
  const channel=data(await owner.client.rpc('st_v2_create_channel',{p_workspace:workspace,p_name:'before-staging'}))
  const post=randomUUID()
  data(await owner.client.rpc('st_v2_post',{p_channel:channel,p_id:post,p_body:protectedBody}))
  const scope={p_workspace:workspace}, command={...scope,p_confirmation:workspace}
  assert.equal((await outsider.client.rpc('st_v8_workspace_offboarding',scope)).error?.code,'42501')
  assert.equal((await owner.client.rpc('st_v8_workspace_offboarding_change',{
    ...command,p_id:randomUUID(),p_action:'requested',p_reason:'This unverified attempt must fail.'})).error?.code,'42501')
  const ownerPage=await open(owner,'Organization settings')
  const reason='Prepare the exact organization inventory for a synthetic offboarding review.'
  await submit(ownerPage.panel,'Request offboarding inventory',workspace,reason)
  await ownerPage.panel.getByText('Awaiting independent approval',{exact:true}).waitFor()
  const current=await browserScope(ownerPage.page)
  const request=data(await current.client.rpc('st_v8_workspace_offboarding',scope)).request
  const action={...command,p_id:request.id}
  assert.equal((await current.client.rpc('st_v8_workspace_offboarding_change',{...action,p_action:'approved'})).error?.code,'42501')
  await current.client.rpc('st_v8_workspace_offboarding_change',{...action,p_action:'requested',p_reason:reason}).then(data)
  data(await current.client.rpc('st_v2_create_channel',{p_workspace:workspace,p_name:'after-snapshot'}))
  const judge=await open(reviewer,'Compliance exports')
  await submit(judge.panel,'Approve exact inventory',workspace)
  await judge.panel.getByText('Inventory export approved',{exact:true}).waitFor()
  const reviewerScope=await browserScope(judge.page)
  await ownerPage.refresh()
  const approved=data(await current.client.rpc('st_v8_workspace_offboarding',scope)).request
  const path='/api/compliance-exports/'+approved.case
  const calls=(token,method='GET')=>fetch(new URL(path,app),{method,headers:{Authorization:'Bearer '+token}})
  assert.equal((await calls(reviewerScope.token,'POST')).status,404)
  assert.equal((await calls(data(await outsider.client.auth.getSession()).session.access_token)).status,404)
  assert.equal((await current.client.rpc('st_v8_workspace_offboarding_change',{...action,p_action:'read_only'})).error?.code,'42501')
  const building=ownerPage.page.waitForResponse(r=>r.url().endsWith(path)&&r.request().method()==='POST')
  await button(ownerPage.panel,'Build inventory export').click()
  const built=await building
  assert.equal(built.status(),200,built.ok()?'':await built.text())
  artifact=sql(`copy(select artifact from sectalk_private.st_v7_compliance_cases where id='${approved.case}') to stdout;`).trim()
  const [download]=await Promise.all([ownerPage.page.waitForEvent('download'),button(ownerPage.panel,'Download inventory export').click()])
  const file=await readFile(await download.path(),'utf8')
  const bundle=JSON.parse(file)
  assert.equal(digest(bundle.manifest),bundle.manifest_sha256)
  assert.equal(bundle.manifest_sha256,approved.manifestSha256)
  assert.equal(bundle.records.length,1)
  assert.equal(bundle.records[0].sha256,request.sha256)
  assert.equal(digest(bundle.records[0].json),request.sha256)
  const inventory=JSON.parse(bundle.records[0].json)
  assert.equal(inventory.workspace,workspace)
  assert.equal(inventory.inventory.channels,request.snapshot.inventory.channels)
  const currentChannels=data(await current.client.from('st_v2_channels').select('id').eq('workspace_id',workspace))
  assert.equal(currentChannels.length,inventory.inventory.channels+1)
  for(const ignored of [protectedBody,foreignName,owner.email,outsider.email])assert.ok(!file.includes(ignored))
  assert.ok((await current.client.storage.from('sectalk-exports').download(artifact)).error)
  const raw=data(await service.storage.from('sectalk-exports').download(artifact))
  assert.ok(!(await raw.text()).includes(name))
  console.log('Fresh owner + independent TOTP approval, immutable manifest and real private encrypted artifact verified.')
  sql(`insert into public.st_v2_items(workspace_id,kind,title,created_by)
    select '${workspace}','task','Synthetic approved content task '||i,'${owner.id}' from generate_series(1,26) i;`)
  const content=ownerPage.panel.getByRole('region',{name:'Workspace content export',exact:true})
  const contentReview=judge.panel.getByRole('region',{name:'Workspace content export',exact:true})
  await content.getByLabel('Confirm content export workspace ID').fill(workspace)
  await button(content,'Request separate content approval').click()
  await content.getByText('Awaiting independent content approval.',{exact:true}).waitFor()
  await button(contentReview,'Refresh content approval').click()
  await contentReview.getByLabel('Confirm content export workspace ID').fill(workspace)
  await button(contentReview,'Approve exact content revisions').click()
  await contentReview.getByText(/27 approved records/).waitFor()
  await button(content,'Refresh content approval').click()
  const pageButton=button(content,'Download next content page')
  const pages=[]
  for(let index=0;index<2;index++){
    const [result]=await Promise.all([ownerPage.page.waitForEvent('download'),pageButton.click()])
    pages.push(JSON.parse(await readFile(await result.path(),'utf8')))
  }
  assert.deepEqual(pages.map(row=>row.records.length),[25,2])
  assert.equal(pages[0].manifestSha256,pages[1].manifestSha256)
  for(const row of pages.flatMap(page=>page.records))assert.equal(digest(row.json),row.sha256)
  console.log('Separate content consent and independent approval produced two authentic scoped manifest pages.')
  const fileId=randomUUID()
  const filename='offboarding-fixture.txt'
  const payload=Buffer.from('Benign archived workspace content '+suffix)
  const fileHash=digest(payload)
  const fileCommand={p_workspace:workspace,p_actor:owner.id,p_id:fileId,p_filename:filename,p_bytes:payload.length,p_hash:fileHash}
  data(await service.rpc('st_v6_workspace_file_command',{...fileCommand,p_action:'reserve'}))
  workspaceFilePath=workspace+'/'+fileId
  data(await service.storage.from('sectalk-workspace-files').upload(workspaceFilePath,payload,{contentType:'application/octet-stream'}))
  data(await service.rpc('st_v6_workspace_file_command',{...fileCommand,p_action:'publish'}))
  const unpublished=randomUUID()
  data(await service.rpc('st_v6_workspace_file_command',{...fileCommand,p_id:unpublished,p_action:'reserve'}))
  const fileGet=(exportId,token=current.token,target=fileId)=>fetch(new URL('/api/workspace-files?'+new URLSearchParams({
    workspace,file:target,offboarding:exportId,
  }),app),{headers:{Authorization:'Bearer '+token}})
  assert.equal((await fileGet(pages[0].id)).status,404)
  data(await current.client.rpc('st_v8_offboarding_content',{
    p_workspace:workspace,p_action:'withdraw',p_id:pages[0].id,p_confirmation:workspace,
  }))
  await button(content,'Refresh content approval').click()
  await content.getByLabel('Confirm workspace ID for file export').fill(workspace)
  await button(content,'Request content and workspace file approval').click()
  await content.getByText('This request includes eligible workspace files.',{exact:true}).waitFor()
  await button(contentReview,'Refresh content approval').click()
  await contentReview.getByText('This request includes eligible workspace files.',{exact:true}).waitFor()
  await contentReview.getByLabel('Confirm content export workspace ID').fill(workspace)
  await button(contentReview,'Approve exact content revisions').click()
  await contentReview.getByText(/28 approved records/).waitFor()
  await button(content,'Refresh content approval').click()
  const approvedFiles=data(await current.client.rpc('st_v8_offboarding_content',scope))
  assert.equal((await fileGet(approvedFiles.id,reviewerScope.token)).status,404)
  assert.equal((await fileGet(approvedFiles.id,current.token,unpublished)).status,404)
  const exact=await fileGet(approvedFiles.id)
  assert.equal(exact.status,200,exact.ok?'':await exact.text())
  assert.equal(exact.headers.get('x-sectalk-file-sha256'),fileHash)
  assert.deepEqual(Buffer.from(await exact.arrayBuffer()),payload)
  if(process.env.SECTALK_RESIDENCY_TARGET_DATABASE) {
    const targetDatabase=new URL(process.env.SECTALK_RESIDENCY_TARGET_DATABASE).origin
    assert.equal(targetDatabase,'http://127.0.0.1:56681')
    const targetKey=process.env.SECTALK_RESIDENCY_TARGET_KEY
    const dedicated=createClient(targetDatabase,targetKey,options).storage.from('sectalk-workspace-files')
    const staging={sourceApp:app.origin,sourceDatabase:backend.origin,targetDatabase,
      targetKey,workspace,exportId:approvedFiles.id,authorization:current.token,files:[fileId]}
    try {
      await assert.rejects(stageWorkspaceFiles({...staging,targetDatabase:backend.origin}),/must be separate/)
      await assert.rejects(stageWorkspaceFiles({...staging,authorization:reviewerScope.token}),/could not be read/)
      await assert.rejects(stageWorkspaceFiles({...staging,files:[unpublished]}),/could not be read/)
      await assert.rejects(stageWorkspaceFiles({...staging,workspace:randomUUID()}),/could not be read/)
      assert.ok((await dedicated.download(workspaceFilePath)).error)
      const copy=await stageWorkspaceFiles(staging)
      assert.equal(copy.copied,1)
      assert.deepEqual(Buffer.from(await data(await dedicated.download(workspaceFilePath)).arrayBuffer()),payload)
      const publicObject=await fetch(targetDatabase+'/storage/v1/object/public/sectalk-workspace-files/'+workspaceFilePath)
      assert.equal(publicObject.ok,false)
      await publicObject.body?.cancel()
      const retry=await stageWorkspaceFiles(staging)
      assert.equal(retry.copied,0)
      assert.equal(retry.reused,1)
      assert.equal(retry.manifestSha256,copy.manifestSha256)
      const mismatch=Buffer.from(payload)
      mismatch[0]^=1
      data(await dedicated.update(workspaceFilePath,mismatch,{contentType:'application/octet-stream'}))
      await assert.rejects(stageWorkspaceFiles(staging),/Existing data was preserved/)
      assert.deepEqual(Buffer.from(await data(await dedicated.download(workspaceFilePath)).arrayBuffer()),mismatch)
      assert.deepEqual(Buffer.from(await data(await service.storage.from('sectalk-workspace-files')
        .download(workspaceFilePath)).arrayBuffer()),payload)
      console.log('Dedicated project copied exact approved private bytes and refused conflicting, unpublished and unauthorized data.')
    } finally {
      await dedicated.remove([workspaceFilePath])
    }
  }
  let fileRecord
  for(let index=0;index<2&&!fileRecord;index++) {
    const [result]=await Promise.all([ownerPage.page.waitForEvent('download'),pageButton.click()])
    const parsed=JSON.parse(await readFile(await result.path(),'utf8'))
    fileRecord=parsed.records.find(item=>item.kind==='workspace_file')
  }
  assert.equal(fileRecord.id,fileId)
  assert.equal(digest(fileRecord.json),fileRecord.sha256)
  assert.equal(JSON.parse(fileRecord.json).fingerprint,digest('workspace-file:'+workspace+':'+fileHash))
  const [fileDownload]=await Promise.all([ownerPage.page.waitForEvent('download'),button(content,'Download '+filename).click()])
  assert.deepEqual(await readFile(await fileDownload.path()),payload)
  const altered=Buffer.from(payload)
  altered[0]^=1
  data(await service.storage.from('sectalk-workspace-files').update(workspaceFilePath,altered,{contentType:'application/octet-stream'}))
  assert.equal((await fileGet(approvedFiles.id)).status,404)
  data(await service.storage.from('sectalk-workspace-files').update(workspaceFilePath,payload,{contentType:'application/octet-stream'}))
  sql(`delete from sectalk_private.st_v8_offboarding_reviewers where workspace='${workspace}' and actor='${reviewer.id}';`)
  assert.equal((await fileGet(approvedFiles.id)).status,404)
  sql(`insert into sectalk_private.st_v8_offboarding_reviewers values('${workspace}','${reviewer.id}');`)
  sql(`insert into sectalk_private.st_v6_malware_hashes(sha256) values(decode('${fileHash}','hex'));`)
  fixtureMalwareHash=fileHash
  assert.equal((await fileGet(approvedFiles.id)).status,404)
  sql(`delete from sectalk_private.st_v6_malware_hashes where sha256=decode('${fileHash}','hex');`)
  fixtureMalwareHash=undefined
  console.log('Explicit file consent, published version pin, exact authenticated Storage bytes, and late quarantine digest denial passed.')
  data(await current.client.rpc('st_v8_offboarding_content',{p_workspace:workspace,p_action:'withdraw',
    p_id:approvedFiles.id,p_confirmation:workspace}))
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
  await contentReview.getByText(/28 approved records/).waitFor()
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
  console.log('Scoped private room file bytes, uploader consent, and live independent room access verified.')
  sql(`insert into public.st_v2_subscriptions(user_id,plan,status,period_end)
    values('${owner.id}','enterprise','active',now()+interval '1 day');`)
  const apiKey='sectalk_api_'+randomBytes(32).toString('base64url')
  data(await current.client.rpc('st_v6_create_integration_key',{
    p_workspace:workspace,p_label:'Offboarding API fixture',p_prefix:apiKey.slice(12,22),
    p_digest:digest(apiKey),p_scopes:['workspace:read'],p_lifetime_days:7,
  }))
  const workspaceApi=()=>fetch(new URL('/api/v1/workspace',app),{headers:{Authorization:'Bearer '+apiKey}})
  assert.equal((await workspaceApi()).status,200)
  const hold=randomUUID()
  data(await current.client.rpc('st_v6_place_workspace_hold',{p_workspace:workspace,p_id:hold,p_room:null,p_member:owner.id,
    p_from:null,p_until:null,p_reason:'Retain the synthetic scope during offboarding review.'}))
  await ownerPage.refresh()
  await ownerPage.panel.getByText('Active legal holds prevent read-only staging.',{exact:true}).waitFor()
  assert.equal((await fileGet(approvedFiles.id)).status,404)
  assert.equal((await roomGet(ownedFile)).status,404)
  assert.equal((await current.client.rpc('st_v8_workspace_offboarding_change',{...action,p_action:'read_only'})).error?.code,'42501')
  assert.equal((await workspaceApi()).status,200)
  data(await current.client.rpc('st_v6_release_workspace_hold',{p_workspace:workspace,p_id:hold,p_reason:'Finish synthetic preservation check.'}))
  await ownerPage.refresh()
  await submit(ownerPage.panel,'Stage workspace read-only',workspace)
  await ownerPage.panel.getByText('Read-only offboarding staged',{exact:true}).waitFor()
  const shutdown=ownerPage.panel.getByLabel('Offboarding integration receipt',{exact:true})
  await shutdown.getByText('API keys revoked',{exact:true}).waitFor()
  assert.equal(await shutdown.locator('dd').nth(1).textContent(),'1')
  assert.equal((await workspaceApi()).status,401)
  data(await current.client.rpc('st_v8_workspace_offboarding_change',{...action,p_action:'read_only'}))
  assert.equal((await current.client.rpc('st_v2_post',{p_channel:channel,p_id:randomUUID(),p_body:'Blocked synthetic write'})).error?.code,'PT423')
  assert.equal(data(await current.client.from('st_v2_posts').select('body').eq('id',post).single()).body,protectedBody)
  assert.ok(data(await outsider.client.rpc('st_v2_create_channel',{p_workspace:other,p_name:'other-workspace-active'})))
  for(const actor of [owner,reviewer,outsider])assert.equal(data(await service.auth.admin.getUserById(actor.id)).user.id,actor.id)
  const stages=sql(`copy(select string_agg(action,',' order by id) from sectalk_private.st_v8_offboarding_audit
    where request='${request.id}') to stdout;`).trim()
  assert.equal(stages,'requested,approved,read_only')
  console.log('Legal-hold block, integration shutdown receipt and API denial, retry-safe tenant-only writes, and preserved messages and global identities passed.')

  const storageReview=ownerPage.panel.getByRole('region',{name:'Offboarding Storage review',exact:true})
  const reviewScope=judge.panel.getByRole('region',{name:'Offboarding Storage review',exact:true})
  await storageReview.getByLabel('Confirm Storage workspace ID').fill(workspace)
  await button(storageReview,'Capture workspace Storage inventory').click()
  await ownerPage.panel.getByText('Current Storage inventory captured.',{exact:true}).waitFor()
  const blocked=data(await current.client.rpc('st_v8_offboarding_storage_plan',scope))
  assert.equal(blocked.clean,false)
  assert.equal(blocked.counts.pending,1)
  await judge.refresh()
  await reviewScope.getByText('Storage inventory SHA-256',{exact:true}).waitFor()
  assert.equal(await button(reviewScope,'Confirm exact Storage inventory').count(),0)

  // Resolve this fixture reservation, which has no object bytes in Storage.
  sql(`update sectalk_private.st_v6_workspace_files set deleted_at=now() where workspace='${workspace}' and id='${unpublished}';`)
  await ownerPage.refresh()
  await storageReview.getByLabel('Confirm Storage workspace ID').fill(workspace)
  await button(storageReview,'Capture workspace Storage inventory').click()
  await ownerPage.panel.getByText('Current Storage inventory captured.',{exact:true}).waitFor()
  const clean=data(await current.client.rpc('st_v8_offboarding_storage_plan',scope))
  assert.equal(clean.clean,true)
  assert.equal(clean.counts.published,4)
  assert.notEqual(clean.sha256,blocked.sha256)
  await judge.refresh()
  await reviewScope.getByLabel('Confirm Storage workspace ID').fill(workspace)
  await button(reviewScope,'Confirm exact Storage inventory').click()
  await reviewScope.getByText('Current Storage inventory independently confirmed.',{exact:true}).waitFor()
  data(await service.storage.from('sectalk-workspace-files').update(workspaceFilePath,altered,{contentType:'application/octet-stream'}))
  await ownerPage.refresh()
  await storageReview.getByText('Capture a new inventory. The previous capture changed or expired.',{exact:true}).waitFor()
  const protectedObject=data(await service.storage.from('sectalk-workspace-files').download(workspaceFilePath))
  assert.deepEqual(Buffer.from(await protectedObject.arrayBuffer()),altered)
  console.log('Private Storage review blocked a pending upload, captured and confirmed exact scope, and invalidated a same-size replacement.')
} catch(cause) {
  primaryFailure=true
  throw cause
} finally {
  try {
    await browser.close()
    if(artifact)await service.storage.from('sectalk-exports').remove([artifact])
    if(workspaceFilePath)await service.storage.from('sectalk-workspace-files').remove([workspaceFilePath])
    if(roomFilePaths.length)await service.storage.from('sectalk-workspace-files').remove(roomFilePaths)
    if(fixtureMalwareHash)sql(`delete from sectalk_private.st_v6_malware_hashes where sha256=decode('${fixtureMalwareHash}','hex');`)
    for(const workspace of workspaces)sql(`begin; set local session_replication_role=replica;
      delete from sectalk_private.st_v8_offboarding_audit where workspace='${workspace}';
      delete from sectalk_private.st_v7_tenant_key_audit where workspace='${workspace}';
      delete from sectalk_private.st_v8_content_export_entries where export_id in (
        select id from sectalk_private.st_v8_content_exports where workspace='${workspace}');
      set local session_replication_role=origin;
      delete from sectalk_private.st_v8_offboarding_requests where workspace='${workspace}';
      delete from sectalk_private.st_v6_workspace_files where workspace='${workspace}';
      delete from sectalk_private.st_v6_room_files where workspace='${workspace}';
      delete from sectalk_private.st_v6_workspace_holds where workspace_id='${workspace}';
      delete from public.st_v2_workspaces where id='${workspace}';
      delete from sectalk_private.st_v7_tenant_key_versions where workspace='${workspace}';
      delete from sectalk_private.st_v7_tenant_key_state where workspace='${workspace}'; commit;`)
    for(const actor of actors)sql(`delete from auth.users where id='${actor}';`)
  } catch(cause) {
    if(!primaryFailure)throw cause
    console.error('Disposable offboarding fixture cleanup failed.')
  }
}
