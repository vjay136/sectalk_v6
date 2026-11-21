import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { createServer } from 'node:http'
import { createClient } from '@supabase/supabase-js'
import { stageWorkspaceContent } from '../scripts/workspace-residency-content.mjs'
import { publishWorkspaceFiles } from '../scripts/workspace-residency-files.mjs'
import { inviteResidencyMember, restoreResidencyChannelPost, restoreResidencyPost } from '../scripts/workspace-residency-member.mjs'
import { inviteResidencyRoomMember } from '../scripts/workspace-residency-room-member.mjs'
import { fixtureAuthenticator } from './workspace-admin-fixture.mjs'

const sourceDatabase = process.env.SECTALK_STORAGE_TEST_URL
const targetDatabase = process.env.SECTALK_RESIDENCY_TARGET_DATABASE
const sourceApp = process.env.SECTALK_RESIDENCY_SOURCE_APP
const targetApp = process.env.SECTALK_RESIDENCY_TARGET_APP
const checkChannelImport = process.env.SECTALK_RESIDENCY_CHANNEL_IMPORT_QA === '1'
const checkRoomImport = process.env.SECTALK_RESIDENCY_ROOM_IMPORT_QA === '1'
const checkRoomMemberImport = process.env.SECTALK_RESIDENCY_ROOM_MEMBER_QA === '1'
const checkRoomHistory = process.env.SECTALK_RESIDENCY_ROOM_HISTORY_QA === '1'
assert.ok(!checkRoomMemberImport||checkRoomImport)
const checkChannelHistory = process.env.SECTALK_RESIDENCY_CHANNEL_HISTORY_QA === '1'
assert.ok(!checkChannelHistory||checkChannelImport)
const checkRoomFileImport = process.env.SECTALK_RESIDENCY_ROOM_FILE_QA === '1'
const checkRoomTaskImport = process.env.SECTALK_RESIDENCY_ROOM_TASK_QA === '1'
const checkDestinationComparison = process.env.SECTALK_RESIDENCY_COMPARISON_QA === '1'
const checkComparisonReceipt = process.env.SECTALK_RESIDENCY_COMPARISON_RECEIPT_QA === '1'
const checkBothFileScopes = process.env.SECTALK_RESIDENCY_BOTH_FILE_SCOPES_QA === '1'
const checkWriteHandoff = process.env.SECTALK_RESIDENCY_WRITE_HANDOFF_QA === '1'
const checkCutover = process.env.SECTALK_RESIDENCY_ACTIVATION_QA === '1'
const checkActiveRoute = process.env.SECTALK_RESIDENCY_ACTIVE_ROUTE_QA === '1'
const checkRollbackHold = process.env.SECTALK_RESIDENCY_ROLLBACK_HOLD_QA === '1'
const checkRollbackReview = process.env.SECTALK_RESIDENCY_ROLLBACK_REVIEW_QA === '1'
const checkRollbackManifest = process.env.SECTALK_RESIDENCY_ROLLBACK_MANIFEST_QA === '1'
const checkBoardReplay = process.env.SECTALK_RESIDENCY_BOARD_REPLAY_QA === '1'
const checkBoardAdditions = process.env.SECTALK_RESIDENCY_BOARD_ADDITIONS_QA === '1'
const checkMemberBoardReplay = process.env.SECTALK_RESIDENCY_MEMBER_BOARD_QA === '1'
const checkChannelReplay = process.env.SECTALK_RESIDENCY_CHANNEL_REPLAY_QA === '1'
const checkMemberChannelReplay = process.env.SECTALK_RESIDENCY_MEMBER_CHANNEL_QA === '1'
const checkSourceReplayReview = process.env.SECTALK_RESIDENCY_SOURCE_RECONCILE_QA === '1'
const checkSourceSignoff = process.env.SECTALK_RESIDENCY_SOURCE_SIGNOFF_QA === '1'
const checkExistingChannelReplay = process.env.SECTALK_RESIDENCY_EXISTING_CHANNEL_QA === '1'
const checkDefaultChannelReplay = process.env.SECTALK_RESIDENCY_DEFAULT_CHANNEL_QA === '1'
const checkRollbackFileCopy = process.env.SECTALK_RESIDENCY_ROLLBACK_FILE_QA === '1'
const checkDestinationRetirement = process.env.SECTALK_RESIDENCY_RETIRE_DESTINATION_QA === '1'
const existingChannelName = checkDefaultChannelReplay?'general':'approved-channel'
assert.ok(!checkComparisonReceipt||checkDestinationComparison)
assert.ok(!checkBothFileScopes||(checkDestinationComparison&&checkRoomFileImport))
assert.ok(!checkWriteHandoff||checkComparisonReceipt)
assert.ok(!checkCutover||(sourceApp&&targetApp&&!checkChannelImport&&!checkRoomImport&&!checkWriteHandoff))
assert.ok(!checkActiveRoute||checkCutover)
assert.ok(!checkRollbackHold||checkActiveRoute)
assert.ok(!checkRollbackReview||checkRollbackHold)
assert.ok(!checkRollbackManifest||checkRollbackReview)
assert.ok(!checkBoardReplay||checkRollbackManifest)
assert.ok(!checkBoardAdditions||checkBoardReplay)
assert.ok(!checkMemberBoardReplay||checkBoardAdditions)
assert.ok(!checkChannelReplay||checkBoardAdditions)
assert.ok(!checkMemberChannelReplay||checkChannelReplay)
assert.ok(!checkExistingChannelReplay||(checkCutover&&checkChannelReplay&&checkSourceReplayReview))
assert.ok(!checkDefaultChannelReplay||(checkExistingChannelReplay&&checkSourceSignoff))
assert.ok(!checkRollbackFileCopy||checkRollbackManifest)
assert.ok(!checkDestinationRetirement||checkRollbackManifest)
if(checkDestinationComparison)assert.ok(checkChannelHistory&&checkRoomTaskImport&&sourceApp&&targetApp)
if(checkRoomTaskImport)assert.ok(checkRoomImport)
if(checkRoomFileImport)assert.ok(sourceApp&&targetApp&&checkRoomImport)
assert.equal(sourceDatabase, 'http://127.0.0.1:56651')
assert.equal(targetDatabase, 'http://127.0.0.1:56801')
const sourceKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const targetKey = process.env.SECTALK_RESIDENCY_TARGET_KEY
const targetPublishable = process.env.SECTALK_RESIDENCY_TARGET_PUBLIC_KEY
assert.ok(sourceKey && targetKey && targetPublishable)
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const source = createClient(sourceDatabase, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const target = createClient(targetDatabase, targetKey, options)
const targetPublic = createClient(targetDatabase, targetPublishable, options)
const actors = []
const destinationActors = []
const cell = randomUUID()
const installationNonce = randomUUID()
let approval = randomUUID()
const claim = randomUUID()
const fileId = randomUUID()
const fileName = 'residency-approved.txt'
const fileBytes = Buffer.from('Approved source file '+randomUUID())
const workspaceFile={id:randomUUID(),bytes:Buffer.from('Approved workspace file '+randomUUID()),name:'second-approved-file.txt'}
const rollbackFile={id:randomUUID(),bytes:Buffer.from('New reviewed recovery file '+randomUUID()),name:'reviewed-rollback.txt'}
let rollbackStagingPath
const expectedRecords = (sourceApp ? 27 : 26)+(checkChannelImport ? 4 : 0)+(checkRoomImport ? 3 : 0)+(checkChannelHistory?1:0)+
  (checkRoomTaskImport?3:0)+(checkRoomHistory?2:0)+(checkBothFileScopes?1:0)+(checkExistingChannelReplay?1:0)
assert.ok(!checkRoomHistory||(checkRoomMemberImport&&checkChannelHistory))
const roomRoot=randomUUID(),roomReply=randomUUID()
const rootBody='Approved room thread restored from source',replyBody='Approved reply restored from source'
if(sourceApp)assert.ok(['http://127.0.0.1:3603','http://127.0.0.1:3615'].includes(new URL(sourceApp).origin))
const sourceProject = 'v6-i232-qa'
const destinationProject = 'v6-bundle243-qa'
let workspace
let unrelated
let targetReady = false
let targetForeignWorkspace
let channel, retryChannel, sourceGeneral
let room, retryRoom
const approvedRoomTasks=[randomUUID(),randomUUID()].sort()
const tasksOnlyRoom=randomUUID()
const firstTaskTitle='Approved migration readiness'
let sourceMember,targetMember
const importedPost=randomUUID()
const importedBody='Approved authored channel history '+importedPost.slice(0,8)
let browser
let scanner
let scanCalls=0

function sql(project, input) {
  return execFileSync('docker', ['exec', '-i', project, 'psql', '-U', 'postgres', '-d', 'postgres', '-XqtA', '-v', 'ON_ERROR_STOP=1'], {
    input, encoding: 'utf8', windowsHide: true,
  }).trim()
}
const sourceSql = input => sql('supabase_db_v6-i232-qa', input)
const targetSql = input => sql('supabase_db_v6-bundle243-qa', input)
function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}
async function account(label, destination = false, identityEmail) {
  const handle = `${label}_${randomUUID().slice(0, 8)}`
  const email = identityEmail ?? handle + '@example.invalid'
  const password = randomUUID() + '!sK'
  const admin = destination ? target : source
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const cleanup = destination ? destinationActors : actors
  cleanup.push(user.id)
  const client = createClient(destination ? targetDatabase : sourceDatabase, destination ? targetPublishable : sourceKey, options)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: 'Synthetic transfer operator' }))
  return { id: user.id, client }
}

async function makeMatchedMembers() {
  const email='member_'+randomUUID().slice(0,8)+'@example.invalid'
  const [sourceAccount,destinationAccount]=await Promise.all([account('source_member',false,email),account('target_member',true,email)])
  sourceMember=sourceAccount
  targetMember=destinationAccount
  sourceSql(`insert into public.st_v2_members(workspace_id,user_id,role) values('${workspace}','${sourceMember.id}','member');`)
}

try {
  if(sourceApp){
    const secret=process.env.SECTALK_RESIDENCY_SCANNER_TEST_SECRET
    assert.ok(secret && secret.length>=32)
    scanner=createServer(async (request,response)=>{
      const chunks=[]
      for await(const chunk of request)chunks.push(chunk)
      const scanned=Buffer.concat(chunks)
      if(request.url!=='/scan'||request.method!=='POST'||request.headers.authorization!=='Bearer '+secret||
        !(scanned.equals(fileBytes)||checkBothFileScopes&&scanned.equals(workspaceFile.bytes)||
          checkRollbackFileCopy&&scanned.equals(rollbackFile.bytes))){
        response.writeHead(403).end();return
      }
      scanCalls++
      response.writeHead(200,{'Content-Type':'application/json'}).end(JSON.stringify({
        verdict:'clean',sha256:createHash('sha256').update(scanned).digest('hex'),
      }))
    })
    await new Promise((ready,fail)=>scanner.once('error',fail).listen(3604,'127.0.0.1',ready))
  }
  const matchingOwnerEmail=checkBoardAdditions?'residency-owner-'+randomUUID()+'@example.invalid':undefined
  const [owner, reviewer, outsider] = await Promise.all([account('owner',false,matchingOwnerEmail),account('reviewer'),account('outside')])
  workspace = data(await owner.client.rpc('st_v2_create_workspace', { p_name: 'Synthetic approved transfer' }))
  unrelated = data(await outsider.client.rpc('st_v2_create_workspace', { p_name: 'Outside transfer' }))
  sourceSql(`insert into public.st_v2_members(workspace_id,user_id,role) values('${workspace}','${reviewer.id}','admin');
    insert into sectalk_private.st_v8_offboarding_reviewers values('${workspace}','${reviewer.id}');
    insert into public.st_v2_items(workspace_id,kind,title,details,due_at,completed,created_by,created_at)
      select '${workspace}','task','Selected synthetic task '||i,'Approved details for task '||i,
        case when i%2=0 then now()+i*interval '1 day' end,i%3=0,'${owner.id}',now()-i*interval '1 hour'
      from generate_series(1,26) i;
    insert into public.st_v2_items(workspace_id,kind,title,created_by)
      values('${unrelated}','task','Unrelated tenant task','${outsider.id}');`)
  if(checkChannelImport) {
    sourceGeneral=sourceSql(`select id from public.st_v2_channels where workspace_id='${workspace}' and name='general';`)
    channel=data(await owner.client.rpc('st_v2_create_channel',{p_workspace:workspace,p_name:'approved-channel'}))
    retryChannel=data(await owner.client.rpc('st_v2_create_channel',{p_workspace:workspace,p_name:'approved-race'}))
    const foreignChannel=sourceSql(`select id from public.st_v2_channels where workspace_id='${unrelated}' and name='general';`)
    sourceSql(`insert into public.st_v2_posts(id,channel_id,sender,body) values
      (gen_random_uuid(),'${channel}','${owner.id}','Approved source channel message only'),
      (gen_random_uuid(),'${channel}','${reviewer.id}','Second approved source channel message only'),
      (gen_random_uuid(),'${retryChannel}','${owner.id}','Approved retry source message only'),
      (gen_random_uuid(),'${sourceGeneral}','${owner.id}','Approved general source message only'),
      (gen_random_uuid(),'${foreignChannel}','${outsider.id}','Unrelated tenant channel message');`)
    if(checkChannelHistory){
      await makeMatchedMembers()
      data(await sourceMember.client.rpc('st_v2_post',{p_channel:channel,p_id:importedPost,p_body:importedBody}))
    }
  }
  if(checkExistingChannelReplay){
    channel=checkDefaultChannelReplay?sourceSql(`select id from public.st_v2_channels where workspace_id='${workspace}' and name='general';`):
      data(await owner.client.rpc('st_v2_create_channel',{p_workspace:workspace,p_name:existingChannelName}))
    await makeMatchedMembers()
    data(await sourceMember.client.rpc('st_v2_post',{p_channel:channel,p_id:importedPost,p_body:importedBody}))
  }
  if(checkRoomImport) {
    room=randomUUID();retryRoom=randomUUID()
    const privateRoom=randomUUID()
    for(const [id,name,kind] of [[room,'Approved destination room','public'],[retryRoom,'Approved retry room','public'],
      [privateRoom,'Source private room excluded','private']]) {
      data(await owner.client.rpc('st_v6_room_create',{p_id:id,p_workspace:workspace,p_name:name,p_kind:kind,p_template:'blank'}))
    }
    sourceSql(`insert into public.st_v6_room_members(room_id,user_id,role) values
      ('${room}','${reviewer.id}','member'),('${retryRoom}','${reviewer.id}','member'),('${privateRoom}','${reviewer.id}','member');
      insert into public.st_v6_room_posts(room_id,id,sender,body,kind) values
      ('${room}',gen_random_uuid(),'${owner.id}','Approved room source message only','message'),
      ('${room}',gen_random_uuid(),'${reviewer.id}','Second approved room source message only','message'),
      ('${retryRoom}',gen_random_uuid(),'${owner.id}','Approved retry room source message only','message'),
      ('${privateRoom}',gen_random_uuid(),'${owner.id}','Excluded source room private history','message');`)
    if(checkRoomTaskImport){
      data(await owner.client.rpc('st_v6_room_create',{
        p_id:tasksOnlyRoom,p_workspace:workspace,p_name:'Source room with tasks only',p_kind:'public',p_template:'blank',
      }))
      sourceSql(`insert into public.st_v6_room_members(room_id,user_id,role) values ('${tasksOnlyRoom}','${reviewer.id}','member');`)
      async function createTask(id,taskRoom,title,extras={}){
        assert.equal(data(await owner.client.rpc('st_v6_task_create',{
          p_id:id,p_room:taskRoom,p_chat:null,p_title:title,...extras,
        })),id)
      }
      await createTask(approvedRoomTasks[0],room,firstTaskTitle,{
        p_priority:'urgent',p_labels:['Verification','Release'],p_due_at:'2027-02-14T14:00:00Z',
      })
      await createTask(approvedRoomTasks[1],room,'Approved QA follow-up',{p_priority:'low'})
      await createTask(randomUUID(),tasksOnlyRoom,'A task with a missing room descriptor')
      await createTask(randomUUID(),privateRoom,'Excluded source room private task')
      const sourcePost=sourceSql(`select id from public.st_v6_room_posts where room_id='${room}' and sender='${owner.id}';`)
      await createTask(randomUUID(),room,'Excluded source room linked task',{p_source:sourcePost})
      sourceSql(`update public.st_v6_tasks set status='done',created_at='2026-11-01T12:00:00Z',updated_at='2026-11-05T12:00:00Z'
        where id='${approvedRoomTasks[0]}';`)
    }
  }
  if(checkRoomMemberImport){
    if(!sourceMember)await makeMatchedMembers()
    data(await sourceMember.client.rpc('st_v6_room_membership',{p_room:room,p_action:'join'}))
  }
  if(checkRoomHistory){
    data(await sourceMember.client.rpc('st_v6_room_post',{p_room:room,p_id:roomRoot,p_body:rootBody}))
    data(await sourceMember.client.rpc('st_v6_room_post',{p_room:room,p_id:roomReply,p_body:replyBody,p_parent:roomRoot}))
  }
  const [ownerProof, reviewerProof] = await Promise.all([fixtureAuthenticator(owner.client), fixtureAuthenticator(reviewer.client)])
  const proofClient = proof => createClient(sourceDatabase, sourceKey, { ...options, accessToken: async () => proof.session.access_token })
  const verifiedOwner = proofClient(ownerProof)
  const verifiedReviewer = proofClient(reviewerProof)
  if(sourceApp){
    const scope=checkRoomFileImport?{room}:{workspace}
    const route=checkRoomFileImport?'/api/room-files?':'/api/workspace-files?'
    const response=await fetch(sourceApp+route+new URLSearchParams({...scope,file:fileId}),{
      method:'POST',body:fileBytes,headers:{Authorization:'Bearer '+ownerProof.session.access_token,
        'Content-Type':'text/plain','X-SecTalk-File-Name':fileName},
    })
    assert.equal(response.status,200,await response.text())
  }
  if(checkBothFileScopes){
    const response=await fetch(sourceApp+'/api/workspace-files?'+new URLSearchParams({workspace,file:workspaceFile.id}),{
      method:'POST',body:workspaceFile.bytes,headers:{Authorization:'Bearer '+ownerProof.session.access_token,
        'Content-Type':'text/plain','X-SecTalk-File-Name':workspaceFile.name},
    })
    assert.equal(response.status,200,await response.text())
    const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
    browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
    const sourceOrigin=new URL(sourceApp).origin
    const {session}=data(await owner.client.auth.getSession())
    const context=await browser.newContext({storageState:{cookies:[],origins:[{origin:sourceOrigin,
      localStorage:[{name:'sb-127-auth-token',value:JSON.stringify(session)}],
    }]}})
    const sourceOwnerPage=await context.newPage()
    await sourceOwnerPage.goto(sourceOrigin+'/?workspace='+workspace)
    await sourceOwnerPage.getByRole('button',{name:'Organization settings',exact:true}).click()
    const exportPanel=sourceOwnerPage.getByRole('region',{name:'Workspace content export',exact:true})
    await exportPanel.getByLabel('Confirm workspace ID for combined file export',{exact:true}).fill(workspace)
    await exportPanel.getByRole('button',{name:'Request content and both file scopes',exact:true}).click()
    await exportPanel.getByText('Awaiting independent content approval.',{exact:true}).waitFor()
    const pending=data(await verifiedOwner.rpc('st_v8_offboarding_content',{p_workspace:workspace}))
    assert.ok(pending.id&&pending.includesFiles&&pending.includesRoomFiles)
    approval=pending.id
    await context.close()
  }
  const command = { p_workspace: workspace, p_id: approval, p_confirmation: workspace }
  const exportAction=checkRoomFileImport?'export_content_room_files':sourceApp?'export_content_files':'export_content'
  if(!checkBothFileScopes)data(await verifiedOwner.rpc('st_v8_offboarding_content', { ...command, p_action: exportAction }))
  else assert.equal((await verifiedOwner.rpc('st_v8_offboarding_content',{...command,p_action:'export_content_room_files'})).error?.code,'42501')
  data(await verifiedReviewer.rpc('st_v8_offboarding_content', { ...command, p_action: 'approve' }))
  const manifest = data(await verifiedOwner.rpc('st_v8_offboarding_content', { p_workspace: workspace }))
  assert.equal(manifest.records, expectedRecords)
  assert.match(manifest.manifestSha256, /^[0-9a-f]{64}$/)
  if(checkBothFileScopes){
    const scope={p_workspace:workspace,p_approval:approval}
    const coverage=(client,args=scope)=>client.rpc('st_v8_residency_source_coverage',args)
    const initial=data(await coverage(verifiedReviewer))
    assert.equal(initial.approvedRecords,expectedRecords)
    assert.deepEqual(initial.families,data(await coverage(verifiedOwner)).families)
    for(const kind of ['workspace_file','room_file'])assert.deepEqual(initial.families.find(row=>row.kind===kind),
      {kind,approved:1,current:1,drifted:0,unapproved:0,observed:1,capped:false})
    assert.ok(initial.families.some(row=>row.unapproved>0))
    assert.doesNotMatch(JSON.stringify(initial),new RegExp(fileId+'|'+workspaceFile.id+'|'+roomRoot))
    assert.equal((await coverage(outsider.client)).error?.code,'42501')
    assert.equal((await coverage(verifiedReviewer,{...scope,p_approval:randomUUID()})).error?.code,'42501')
    sourceSql(`update sectalk_private.st_v6_workspace_files set filename='Drifted source filename' where (workspace,id)=('${workspace}','${workspaceFile.id}');`)
    const drifted=data(await coverage(verifiedReviewer)).families.find(row=>row.kind==='workspace_file')
    assert.equal(drifted.drifted,1)
    assert.equal(drifted.current,0)
    sourceSql(`update sectalk_private.st_v6_workspace_files set filename='${workspaceFile.name}' where (workspace,id)=('${workspace}','${workspaceFile.id}');`)
  }
  targetSql(`begin;
    insert into sectalk_private.st_v8_residency_cells values('${cell}','apac','v6-bundle243-qa','Clean synthetic residency target','fixture',null);
    insert into sectalk_private.st_v8_residency_installation (cell,installation_nonce) values('${cell}','${installationNonce}');
    insert into sectalk_private.st_v8_residency_content_admissions values('${cell}','${workspace}','${sourceProject}',
      '${approval}','${manifest.manifestSha256}',${manifest.records},now()+interval '1 hour'); commit;`)
  targetReady = true

  const stages = { sourceDatabase, sourceProject, sourceKey, sourceSession: ownerProof.session.access_token,
    targetDatabase, targetKey, cell, installationNonce, workspace, approval }
  await assert.rejects(stageWorkspaceContent({ ...stages, targetDatabase: sourceDatabase }), /separate target/)
  await assert.rejects(stageWorkspaceContent({ ...stages, sourceSession: reviewerProof.session.access_token }), /not a current owner-approved/)
  await assert.rejects(stageWorkspaceContent({ ...stages, installationNonce: randomUUID() }), /403/)
  const records = []
  for (const p_after of [0, 25]) {
    const page = data(await verifiedOwner.rpc('st_v8_offboarding_content', { ...command, p_action: 'page', p_after }))
    records.push(...page.records)
  }
  const native = { p_cell: cell, p_nonce: installationNonce, p_source: sourceProject,
    p_workspace: workspace, p_approval: approval, p_records: records }
  assert.ok((await targetPublic.rpc('st_v8_stage_residency_content', native)).error)
  assert.equal((await target.rpc('st_v8_stage_residency_content', { ...native, p_workspace: unrelated })).error?.code, '42501')
  assert.equal((await target.rpc('st_v8_stage_residency_content', { ...native, p_records: records.slice(1) })).error?.code, '22023')
  const tampered = structuredClone(records)
  tampered[3].json = '{}'
  assert.equal((await target.rpc('st_v8_stage_residency_content', { ...native, p_records: tampered })).error?.code, '22023')
  tampered[3].sha256 = createHash('sha256').update(tampered[3].json).digest('hex')
  assert.equal((await target.rpc('st_v8_stage_residency_content', { ...native, p_records: tampered })).error?.code, '42501')
  const receipts = await Promise.all([stageWorkspaceContent(stages), stageWorkspaceContent(stages)])
  assert.deepEqual(receipts.map(item => item.staged).sort(), [false, true])
  assert.ok(receipts.every(item => item.count === expectedRecords && item.manifestSha256 === manifest.manifestSha256))
  const stored = JSON.parse(targetSql(`select records from sectalk_private.st_v8_residency_staged_content where approval='${approval}';`))
  assert.deepEqual(stored, records)
  assert.ok(stored.every(record => (record.scope===workspace || checkChannelImport && record.kind==='channel_message' &&
    [sourceGeneral,channel,retryChannel].includes(record.scope) || checkExistingChannelReplay &&
    record.kind==='channel_message' && record.scope===channel && record.id===importedPost ||
    checkRoomImport && record.kind==='room_message' &&
    [room,retryRoom].includes(record.scope) || checkRoomFileImport && record.kind==='room_file' &&
    record.scope===room && record.id===fileId || checkRoomTaskImport && record.kind==='room_task' &&
    [room,tasksOnlyRoom].includes(record.scope)) && !record.json.includes('Unrelated tenant') && !record.json.includes('Excluded source room')))

  const [destinationOwner, foreignOwner] = await Promise.all([account('target',true,matchingOwnerEmail),account('foreign',true)])
  targetForeignWorkspace = data(await foreignOwner.client.rpc('st_v2_create_workspace', { p_name: 'Foreign destination workspace' }))
  targetSql(`insert into sectalk_private.st_v8_residency_workspace_claims
    (id,cell,workspace,source_project,approval,owner_id,name,manifest_sha256,installation_nonce,expires_at)
    values('${claim}','${cell}','${workspace}','${sourceProject}','${approval}','${destinationOwner.id}',
    'Dedicated test workspace','${manifest.manifestSha256}','${installationNonce}',now()+interval '1 hour');`)
  const claimCommand={p_claim:claim,p_confirmation:workspace}
  const claimWorkspace=(client,params)=>client.rpc('st_v8_residency_workspace_claim',params)
  assert.equal(data(await claimWorkspace(destinationOwner.client)).claims[0].id,claim)
  assert.deepEqual(data(await claimWorkspace(foreignOwner.client)).claims,[])
  assert.equal((await claimWorkspace(destinationOwner.client,claimCommand)).error?.code,'42501')
  const importCommand = { p_workspace: workspace, p_approval: approval, p_confirmation: workspace }
  const importTasks = (client, args = importCommand) => client.rpc('st_v8_residency_task_import', args)
  assert.equal((await importTasks(destinationOwner.client)).error?.code, '42501')
  assert.ok((await importTasks(targetPublic)).error)
  const destinationProof = await fixtureAuthenticator(destinationOwner.client)
  const foreignProof = await fixtureAuthenticator(foreignOwner.client)
  const verifiedDestination = createClient(targetDatabase, targetPublishable, { ...options, accessToken: async () => destinationProof.session.access_token })
  const verifiedForeign = createClient(targetDatabase, targetPublishable, { ...options, accessToken: async () => foreignProof.session.access_token })
  assert.equal((await claimWorkspace(verifiedForeign,claimCommand)).error?.code,'42501')
  assert.equal((await claimWorkspace(verifiedDestination,{...claimCommand,p_confirmation:'wrong'})).error?.code,'42501')
  targetSql(`update sectalk_private.st_v8_residency_installation set installation_nonce='${randomUUID()}' where cell='${cell}';`)
  assert.deepEqual(data(await claimWorkspace(verifiedDestination)).claims,[])
  assert.equal((await claimWorkspace(verifiedDestination,claimCommand)).error?.code,'42501')
  targetSql(`update sectalk_private.st_v8_residency_installation set installation_nonce='${installationNonce}' where cell='${cell}';`)
  targetSql(`insert into public.st_v2_workspaces(id,name,owner) values('${workspace}','Keep this workspace','${foreignOwner.id}');`)
  assert.equal((await claimWorkspace(verifiedDestination,claimCommand)).error?.code,'PT409')
  assert.equal(targetSql(`select name from public.st_v2_workspaces where id='${workspace}';`),'Keep this workspace')
  targetSql(`delete from public.st_v2_workspaces where id='${workspace}' and owner='${foreignOwner.id}';`)
  if(checkDefaultChannelReplay){
    targetSql(`insert into public.st_v2_channels(id,workspace_id,name) values('${channel}','${targetForeignWorkspace}','unrelated-default-id');`)
    assert.equal((await claimWorkspace(verifiedDestination,claimCommand)).error?.code,'PT409')
    assert.equal(targetSql(`select count(*) from public.st_v2_workspaces where id='${workspace}';`),'0')
    assert.equal(targetSql(`select name from public.st_v2_channels where id='${channel}' and workspace_id='${targetForeignWorkspace}';`),'unrelated-default-id')
    targetSql(`delete from public.st_v2_channels where id='${channel}' and workspace_id='${targetForeignWorkspace}';`)
  }
  let page
  if (targetApp) {
    const app = new URL(targetApp)
    assert.ok(['http://127.0.0.1:3602',...(checkChannelImport||checkRoomImport?['http://127.0.0.1:3607']:[]),
      ...(checkChannelHistory?['http://127.0.0.1:3616']:[]),
      ...(checkRoomFileImport||checkRoomTaskImport||checkRoomMemberImport||checkCutover?['http://127.0.0.1:3608','http://127.0.0.1:3616']:[])].includes(app.origin))
    const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
    browser ??= await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
    const { session } = data(await destinationOwner.client.auth.getSession())
    const browserContext = await browser.newContext({ storageState: { cookies: [], origins: [{ origin: app.origin,
      localStorage: [{ name: 'sb-127-auth-token', value: JSON.stringify(session) }],
    }] } })
    page = await browserContext.newPage()
    await page.goto(app.href)
    await page.getByRole('navigation', { name: 'SecTalk features' }).getByRole('button', { name: 'Workspaces', exact: true }).click()
    const admission = page.getByRole('region', { name: 'Approved destination workspace', exact: true })
    await admission.getByLabel('Confirm approved workspace ID').fill(workspace)
    await admission.getByRole('button', { name: 'Claim destination workspace' }).click()
    await admission.waitFor({state:'hidden'})
    await page.getByRole('button', { name: 'Organization settings', exact: true }).waitFor()
  }
  const claimResults=await Promise.all([claimWorkspace(verifiedDestination,claimCommand),claimWorkspace(verifiedDestination,claimCommand)])
  assert.deepEqual(claimResults.map(data),[{workspace},{workspace}])
  assert.equal(targetSql(`select count(*) from public.st_v2_workspace_audit where workspace_id='${workspace}' and event='workspace.residency_claimed';`),'1')
  if(checkChannelImport) {
    const action={...importCommand,p_channel:channel}
    const importChannel=(client,args=action)=>client.rpc('st_v8_residency_channel_import',args)
    const listing=data(await importChannel(verifiedDestination,{p_workspace:workspace}))
    assert.equal(listing.manifestSha256,manifest.manifestSha256)
    assert.deepEqual(listing.channels.map(row=>[row.id,row.name,row.evidenceCount]),[
      [channel,'approved-channel',checkChannelHistory?3:2],[retryChannel,'approved-race',1],[sourceGeneral,'general',1],
    ])
    assert.ok(!JSON.stringify(listing).includes('source channel message'))
    assert.equal((await importChannel(verifiedForeign)).error?.code,'42501')
    assert.equal((await importChannel(verifiedDestination,{...action,p_confirmation:'wrong'})).error?.code,'42501')
    assert.equal((await importChannel(targetPublic)).error?.code,'42501')
    assert.equal((await importChannel(verifiedDestination,{...action,p_channel:randomUUID()})).error?.code,'PT409')
    const destinationGeneral=targetSql(`select id from public.st_v2_channels where workspace_id='${workspace}' and name='general';`)
    assert.equal(destinationGeneral,sourceGeneral)
    assert.equal(data(await importChannel(verifiedDestination,{...action,p_channel:sourceGeneral})).channel,sourceGeneral)
    assert.equal(targetSql(`select id from public.st_v2_channels where workspace_id='${workspace}' and name='general';`),destinationGeneral)
    targetSql(`insert into public.st_v2_channels(id,workspace_id,name) values('${channel}','${targetForeignWorkspace}','keep-channel');`)
    assert.equal((await importChannel(verifiedDestination)).error?.code,'PT409')
    assert.equal(targetSql(`select name from public.st_v2_channels where id='${channel}';`),'keep-channel')
    targetSql(`delete from public.st_v2_channels where (id,workspace_id)=('${channel}','${targetForeignWorkspace}');`)
    targetSql(`insert into sectalk_private.st_v8_workspace_standard_channel_sso(workspace,protocol,provider)
      values('${workspace}','saml','fixture-sso-provider');`)
    assert.equal((await importChannel(verifiedDestination)).error?.code,'42501')
    targetSql(`delete from sectalk_private.st_v8_workspace_standard_channel_sso where workspace='${workspace}';`)
    data(await verifiedDestination.rpc('st_v8_set_channel_mode_policy',{p_workspace:workspace,p_managed:true}))
    assert.equal((await importChannel(verifiedDestination)).error?.code,'PT409')
    data(await verifiedDestination.rpc('st_v8_set_channel_mode_policy',{p_workspace:workspace,p_managed:false}))
    if(page) {
      await page.getByRole('button',{name:'Organization settings',exact:true}).click()
      const channels=page.getByRole('region',{name:'Approved workspace channel import',exact:true})
      await channels.getByLabel('Approved standard channel').selectOption(channel)
      await channels.getByLabel('Confirm destination workspace for channel import').fill(workspace)
      await channels.getByRole('button',{name:'Import approved channel'}).click()
      await channels.getByRole('status').getByText('Channel #approved-channel imported.',{exact:false}).waitFor()
      await page.getByRole('group',{name:'Workspace sections'}).getByRole('button',{name:'Channels',exact:true}).click()
      await page.getByLabel('Channel',{exact:true}).selectOption(channel)
      await page.getByRole('log',{name:'Channel messages',exact:true}).waitFor()
      assert.equal(await page.getByText('Approved source channel message only',{exact:true}).count(),0)
    } else data(await importChannel(verifiedDestination))
    const same=await Promise.all([importChannel(verifiedDestination,{...action,p_channel:retryChannel}),
      importChannel(verifiedDestination,{...action,p_channel:retryChannel})]).then(results=>results.map(data))
    assert.deepEqual(same[0],same[1])
    const published=data(await verifiedDestination.from('st_v2_channels').select('id,name,workspace_id,visibility,encryption_mode')
      .eq('id',channel).single())
    assert.deepEqual(published,{id:channel,name:'approved-channel',workspace_id:workspace,visibility:'workspace',encryption_mode:'standard'})
    assert.deepEqual(data(await verifiedForeign.from('st_v2_channels').select('id').eq('id',channel)),[])
    assert.equal(targetSql(`select count(*) from public.st_v2_posts where channel_id in ('${channel}','${retryChannel}');`),'0')
    assert.equal(targetSql(`select count(*) from public.st_v2_workspace_audit where workspace_id='${workspace}' and event='channel.residency_imported';`),'3')
    assert.equal(sourceSql(`select count(*) from public.st_v2_posts where channel_id in ('${channel}','${retryChannel}','${sourceGeneral}');`),checkChannelHistory?'5':'4')
    console.log('Verified approved standard channel structure, exact scope and idempotent publish between two local projects.')
  }
  if(checkRoomImport) {
    const action={...importCommand,p_room:room}
    const importRoom=(client,args=action)=>client.rpc('st_v8_residency_room_import',args)
    const listing=data(await importRoom(verifiedDestination,{p_workspace:workspace}))
    assert.equal(listing.manifestSha256,manifest.manifestSha256)
    assert.deepEqual(listing.rooms.map(row=>[row.id,row.name,row.evidenceCount]),[
      [room,'Approved destination room',checkRoomHistory?4:2],[retryRoom,'Approved retry room',1],
    ])
    assert.ok(!JSON.stringify(listing).includes('source message only'))
    assert.ok((await importRoom(targetPublic)).error)
    assert.equal((await importRoom(verifiedForeign)).error?.code,'42501')
    assert.equal((await importRoom(verifiedDestination,{...action,p_confirmation:'wrong'})).error?.code,'42501')
    assert.equal((await importRoom(verifiedDestination,{...action,p_approval:randomUUID()})).error?.code,'42501')
    assert.equal((await importRoom(verifiedDestination,{...action,p_room:randomUUID()})).error?.code,'PT409')
    targetSql(`insert into sectalk_private.st_v8_workspace_standard_room_sso(workspace,protocol,provider)
      values('${workspace}','saml','fixture-sso-provider');`)
    assert.equal((await importRoom(verifiedDestination)).error?.code,'42501')
    targetSql(`delete from sectalk_private.st_v8_workspace_standard_room_sso where workspace='${workspace}';`)
    data(await verifiedDestination.rpc('st_v8_managed_room_policy',{p_workspace:workspace,p_enabled:true}))
    assert.equal((await importRoom(verifiedDestination)).error?.code,'PT409')
    data(await verifiedDestination.rpc('st_v8_managed_room_policy',{p_workspace:workspace,p_enabled:false}))
    const other=uuid=>targetSql(`insert into public.st_v6_rooms(id,workspace_id,name,kind,template,creator)
      values('${uuid}','${targetForeignWorkspace}','Foreign room to keep','private','blank','${foreignOwner.id}');`)
    other(room)
    assert.equal((await importRoom(verifiedDestination)).error?.code,'PT409')
    assert.equal(targetSql(`select name from public.st_v6_rooms where id='${room}';`),'Foreign room to keep')
    targetSql(`delete from public.st_v6_rooms where (id,workspace_id)=('${room}','${targetForeignWorkspace}');`)
    const nameConflict=randomUUID()
    targetSql(`insert into public.st_v6_rooms(id,workspace_id,name,kind,template,creator)
      values('${nameConflict}','${workspace}','APPROVED DESTINATION ROOM','private','blank','${destinationOwner.id}');`)
    assert.equal((await importRoom(verifiedDestination)).error?.code,'PT409')
    assert.equal(targetSql(`select name from public.st_v6_rooms where id='${nameConflict}';`),'APPROVED DESTINATION ROOM')
    targetSql(`delete from public.st_v6_rooms where (id,workspace_id)=('${nameConflict}','${workspace}');`)
    if(page) {
      await page.getByRole('button',{name:'Organization settings',exact:true}).click()
      const rooms=page.getByRole('region',{name:'Approved workspace room import',exact:true})
      await rooms.getByLabel('Approved standard room').selectOption(room)
      await rooms.getByLabel('Confirm destination workspace for room import').fill(workspace)
      const publishing=page.waitForResponse(response=>response.url().endsWith('/rpc/st_v8_residency_room_import') &&
        response.request().postDataJSON()?.p_room===room)
      await rooms.getByRole('button',{name:'Import approved room'}).click()
      const published=await publishing
      assert.equal(published.status(),200,published.ok()?'':await published.text())
      await rooms.getByRole('status').getByText('Room Approved destination room imported.',{exact:false}).waitFor()
      const navigation=page.getByRole('navigation',{name:'SecTalk features'})
      await navigation.getByRole('button',{name:'Rooms',exact:true}).click()
      const directory=page.getByRole('region',{name:'Room directory',exact:true})
      await directory.getByRole('button',{name:/Approved destination room/}).click()
      await page.getByText('Encryption mode · Standard workspace storage',{exact:true}).waitFor()
      assert.equal(await page.getByText('Approved room source message only',{exact:true}).count(),0)
      await navigation.getByRole('button',{name:'Workspaces',exact:true}).click()
    } else data(await importRoom(verifiedDestination))
    const concurrent=await Promise.all([importRoom(verifiedDestination,{...action,p_room:retryRoom}),
      importRoom(verifiedDestination,{...action,p_room:retryRoom})]).then(results=>results.map(data))
    assert.deepEqual(concurrent[0],concurrent[1])
    assert.equal(targetSql(`select name||':'||kind||':'||template||':'||classification||':'||encryption_mode
      from public.st_v6_rooms where id='${room}';`),'Approved destination room:private:blank:confidential:standard')
    assert.equal(targetSql(`select user_id||':'||role from public.st_v6_room_members where room_id='${room}';`),`${destinationOwner.id}:owner`)
    assert.deepEqual(data(await verifiedForeign.from('st_v6_rooms').select('id').eq('id',room)),[])
    assert.equal(targetSql(`select count(*) from public.st_v6_room_posts where room_id in ('${room}','${retryRoom}');`),'0')
    assert.equal(targetSql(`select count(*) from public.st_v2_workspace_audit where workspace_id='${workspace}' and event='room.residency_imported';`),'2')
    assert.equal(sourceSql(`select count(*) from public.st_v6_room_posts where room_id in ('${room}','${retryRoom}');`),checkRoomHistory?'5':'3')
    console.log('Verified approved standard room structure with private defaults between two local projects.')
  }
  if(checkRoomTaskImport){
    const restore=(client,args={})=>client.rpc('st_v8_residency_room_task_import',{
      ...importCommand,p_room:room,...args,
    })
    const listing=data(await verifiedDestination.rpc('st_v8_residency_room_task_import',{p_workspace:workspace}))
    assert.equal(listing.manifestSha256,manifest.manifestSha256)
    assert.deepEqual(listing.rooms,[{id:room,name:'Approved destination room',taskCount:2,importedAt:null}])
    assert.ok((await restore(targetPublic)).error)
    assert.equal((await restore(verifiedForeign)).error?.code,'42501')
    assert.equal((await restore(verifiedDestination,{p_confirmation:'wrong'})).error?.code,'42501')
    assert.equal((await restore(verifiedDestination,{p_approval:randomUUID()})).error?.code,'42501')
    const extraRoom={p_id:tasksOnlyRoom,p_workspace:workspace,p_name:'Native unapproved room',p_kind:'private',p_template:'blank'}
    assert.equal(data(await verifiedDestination.rpc('st_v6_room_create',extraRoom)),tasksOnlyRoom)
    assert.equal((await restore(verifiedDestination,{p_room:tasksOnlyRoom})).error?.code,'42501')
    assert.equal((await restore(verifiedDestination,{p_room:retryRoom})).error?.code,'PT409')
    targetSql(`insert into sectalk_private.st_v8_workspace_standard_room_sso(workspace,protocol,provider)
      values('${workspace}','saml','fixture-sso-provider');`)
    assert.equal((await restore(verifiedDestination)).error?.code,'42501')
    targetSql(`delete from sectalk_private.st_v8_workspace_standard_room_sso where workspace='${workspace}';`)
    const conflict=approvedRoomTasks[1]
    const conflictTitle='Native task must remain unchanged'
    assert.equal(data(await verifiedDestination.rpc('st_v6_task_create',{
      p_id:conflict,p_room:retryRoom,p_chat:null,p_title:conflictTitle,
    })),conflict)
    assert.equal((await restore(verifiedDestination)).error?.code,'PT409')
    assert.deepEqual(data(await verifiedDestination.from('st_v6_tasks').select('id').eq('room_id',room)),[])
    assert.equal(data(await verifiedDestination.from('st_v6_tasks').select('title').eq('id',conflict).single()).title,conflictTitle)
    targetSql(`delete from public.st_v6_tasks where (id,room_id)=('${conflict}','${retryRoom}');`)
    if(page){
      await page.getByRole('button',{name:'Organization settings',exact:true}).click()
      const panel=page.getByRole('region',{name:'Approved room task restore',exact:true})
      await panel.getByLabel('Imported room').selectOption(room)
      await panel.getByLabel('Confirm destination workspace for task restore').fill(workspace)
      await panel.getByRole('button',{name:'Restore approved room tasks',exact:true}).click()
      await panel.getByRole('status').getByText('2 approved room tasks restored to Approved destination room.',{exact:false}).waitFor()
      const navigation=page.getByRole('navigation',{name:'SecTalk features'})
      await navigation.getByRole('button',{name:'Rooms',exact:true}).click()
      const directory=page.getByRole('region',{name:'Room directory',exact:true})
      await directory.getByRole('button',{name:/Approved destination room/}).click()
      await directory.getByRole('group',{name:'Room tabs',exact:true}).getByRole('button',{name:'Tasks',exact:true}).click()
      const tasks=directory.getByRole('region',{name:'Scoped tasks',exact:true})
      await tasks.getByRole('button',{name:firstTaskTitle,exact:true}).click()
      await tasks.getByRole('group',{name:'Task detail tabs',exact:true}).getByRole('button',{name:'Audit',exact:true}).click()
      await tasks.getByText('Restored from approved transfer',{exact:true}).waitFor()
      await navigation.getByRole('button',{name:'Workspaces',exact:true}).click()
    }
    const replay=await Promise.all([restore(verifiedDestination),restore(verifiedDestination)]).then(results=>results.map(data))
    assert.deepEqual(replay[0],replay[1])
    assert.equal(replay[0].taskCount,2)
    const live=data(await verifiedDestination.from('st_v6_tasks')
      .select('id,author_id,title,status,priority,labels,due_at,created_at,updated_at').eq('room_id',room).order('id'))
    assert.equal(live.length,2)
    const manifestTasks=records.filter(item=>item.kind==='room_task'&&item.scope===room)
    assert.equal(manifestTasks.length,2)
    for(const [index,task] of live.entries()){
      const approved=JSON.parse(manifestTasks.find(item=>item.id===task.id).json)
      assert.equal(task.id,approvedRoomTasks[index])
      assert.equal(task.author_id,destinationOwner.id)
      assert.deepEqual([task.title,task.status,task.priority,task.labels,task.due_at,task.created_at,task.updated_at],
        [approved.title,approved.status,approved.priority,approved.labels,approved.dueAt,approved.createdAt,approved.updatedAt])
      const audit=data(await verifiedDestination.from('st_v6_task_audit').select('actor_id,action,detail').eq('task_id',task.id).single())
      assert.deepEqual(audit,{actor_id:destinationOwner.id,action:'residency_restored',detail:{
        approval,sourceRecordSha256:manifestTasks.find(item=>item.id===task.id).sha256,
      }})
      assert.deepEqual(data(await verifiedDestination.from('st_v6_task_people').select('user_id').eq('task_id',task.id)),[])
      assert.equal(data(await verifiedDestination.rpc('st_v6_task_source',{p_id:task.id})),null)
    }
    assert.deepEqual(data(await verifiedForeign.from('st_v6_tasks').select('id').eq('room_id',room)),[])
    assert.equal(sourceSql(`select count(*) from public.st_v6_tasks where room_id='${room}';`),'3')
    console.log('Restored exact approved room task fields and truthful audit in a private destination room, with atomic collision rollback and idempotent retries.')
  }
  assert.equal((await importTasks(verifiedForeign)).error?.code, '42501')
  assert.equal((await importTasks(verifiedDestination, { ...importCommand, p_confirmation: 'wrong' })).error?.code, '42501')
  targetSql(`update sectalk_private.st_v8_residency_content_admissions set manifest_sha256=repeat('0',64) where approval='${approval}';`)
  assert.equal((await importTasks(verifiedDestination)).error?.code, 'PT409')
  targetSql(`update sectalk_private.st_v8_residency_content_admissions set manifest_sha256='${manifest.manifestSha256}' where approval='${approval}';`)
  const conflictId = records.findLast(item=>item.kind==='workspace_task').id
  targetSql(`insert into public.st_v2_items(id,workspace_id,kind,title,created_by)
    values('${conflictId}','${targetForeignWorkspace}','task','Keep this task','${foreignOwner.id}');`)
  assert.equal((await importTasks(verifiedDestination)).error?.code, 'PT409')
  assert.deepEqual(data(await verifiedDestination.from('st_v2_items').select('id').eq('workspace_id', workspace)), [])
  assert.equal(data(await verifiedForeign.from('st_v2_items').select('title').eq('id', conflictId).single()).title, 'Keep this task')
  targetSql(`delete from public.st_v2_items where workspace_id='${targetForeignWorkspace}' and id='${conflictId}';`)
  if (page) {
    await page.getByRole('button', { name: 'Organization settings', exact: true }).click()
    const panel = page.getByRole('region', { name: 'Approved workspace task import', exact: true })
    await panel.getByLabel('Confirm destination workspace ID').fill(workspace)
    await panel.getByRole('button', { name: 'Import approved tasks' }).click()
    await panel.getByRole('status').getByText('26 workspace tasks imported.', { exact: false }).waitFor()
    await page.getByRole('button', { name: 'Board', exact: true }).click()
    await page.getByText('Selected synthetic task 1', { exact: true }).waitFor()
    console.log('Edge claimed the approved destination, imported the tasks through Organization settings, and showed them on Board.')
  }
  const [imported, retried] = await Promise.all([importTasks(verifiedDestination), importTasks(verifiedDestination)]).then(results => results.map(data))
  assert.deepEqual(imported, retried)
  assert.equal(imported.taskCount, 26)
  assert.equal(imported.manifestSha256, manifest.manifestSha256)
  assert.ok(imported.importedAt)
  const liveTasks = data(await verifiedDestination.from('st_v2_items')
    .select('id,title,details,due_at,completed,created_by,created_at').eq('workspace_id', workspace))
  const expected = new Map(records.map(item => [item.id, JSON.parse(item.json)]))
  assert.equal(liveTasks.length, 26)
  for (const item of liveTasks) {
    const approved = expected.get(item.id)
    assert.equal(item.title, approved.title)
    assert.equal(item.details, approved.details)
    assert.equal(item.completed, approved.completed)
    assert.equal(item.created_at, approved.createdAt)
    assert.equal(item.due_at, approved.dueAt)
    assert.equal(item.created_by, destinationOwner.id)
  }
  assert.deepEqual(data(await verifiedForeign.from('st_v2_items').select('id').eq('workspace_id', workspace)), [])
  if(sourceApp){
    assert.ok(targetApp)
    const publish={sourceApp,sourceDatabase,sourceKey,authorization:ownerProof.session.access_token,
      targetApp,targetSession:destinationProof.session.access_token,workspace,exportId:approval,files:[fileId],
      ...(checkRoomFileImport?{room}:{})}
    const route=checkRoomFileImport?'/api/room-files?':'/api/workspace-files?'
    const scope=checkRoomFileImport?{room}:{workspace}
    const destFor=(selection=scope,approved=approval)=>targetApp+route+
      new URLSearchParams({...selection,file:fileId,'residency-import':approved})
    const post=(bytes,name,token=publish.targetSession,url=destFor())=>fetch(url,{method:'POST',body:bytes,headers:{
      Authorization:'Bearer '+token,'Content-Type':'text/plain','X-SecTalk-File-Name':name}})
    assert.equal((await post(Buffer.from('changed'),fileName)).status,404)
    assert.equal((await post(fileBytes,'other.txt')).status,404)
    assert.equal((await post(fileBytes,fileName,foreignProof.session.access_token)).status,404)
    if(checkRoomFileImport){
      await assert.rejects(publishWorkspaceFiles({...publish,workspace:unrelated}),/selected source workspace/)
      assert.equal((await post(fileBytes,fileName,publish.targetSession,destFor({room:retryRoom}))).status,404)
      assert.equal((await post(fileBytes,fileName,publish.targetSession,destFor(scope,randomUUID()))).status,404)
      targetSql(`insert into sectalk_private.st_v8_workspace_standard_room_sso(workspace,protocol,provider)
        values('${workspace}','saml','fixture-sso-provider');`)
      assert.equal((await post(fileBytes,fileName)).status,404)
      targetSql(`delete from sectalk_private.st_v8_workspace_standard_room_sso where workspace='${workspace}';`)
      targetSql(`insert into sectalk_private.st_v6_room_files(room,workspace,id,uploader,filename,size_bytes,sha256)
        values('${room}','${workspace}','${fileId}','${destinationOwner.id}','${fileName}',${fileBytes.length},
          '${createHash('sha256').update(fileBytes).digest('hex')}');`)
      assert.equal((await post(fileBytes,fileName)).status,409)
      assert.equal(targetSql(`select count(*) from sectalk_private.st_v8_residency_room_file_imports
        where (room,file)=('${room}','${fileId}');`),'0')
      targetSql(`delete from sectalk_private.st_v6_room_files where (room,id)=('${room}','${fileId}');`)
    }
    const first=await publishWorkspaceFiles(publish)
    assert.equal(first.count,1)
    if(checkRoomFileImport)assert.equal(first.status,'room_files_published')
    assert.deepEqual(await publishWorkspaceFiles(publish),first)
    const protectedResponse=await fetch(targetApp+route+new URLSearchParams({...scope,file:fileId}),{
      headers:{Authorization:'Bearer '+foreignProof.session.access_token},
    })
    assert.equal(protectedResponse.status,404)
    if(checkRoomFileImport){
      await page.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Rooms',exact:true}).click()
      const directory=page.getByRole('region',{name:'Room directory',exact:true})
      await directory.getByRole('button',{name:/Approved destination room/}).click()
      const tabs=directory.getByRole('group',{name:'Room tabs',exact:true})
      await tabs.getByRole('button',{name:'Files',exact:true}).click()
      await directory.getByRole('region',{name:'Room files',exact:true}).waitFor()
    }else await page.getByRole('group',{name:'Workspace sections'}).getByRole('button',{name:'Files',exact:true}).click()
    await page.getByText(fileName,{exact:true}).waitFor()
    const [download]=await Promise.all([page.waitForEvent('download'),page.getByRole('button',{name:'Download file',exact:true}).click()])
    assert.deepEqual(await readFile(await download.path()),fileBytes)
    assert.equal(scanCalls,(checkRoomFileImport?4:3)+(checkBothFileScopes?1:0))
    if(checkRoomFileImport){
      assert.equal(targetSql(`select count(*) from sectalk_private.st_v8_residency_room_file_imports
        where (workspace,approval,room,file)=('${workspace}','${approval}','${room}','${fileId}') and published_at is not null;`),'1')
      assert.equal(sourceSql(`select count(*) from sectalk_private.st_v6_room_files
        where (workspace,room,id)=('${workspace}','${room}','${fileId}') and deleted_at is null;`),'1')
      await page.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Workspaces',exact:true}).click()
    }
    if(checkBothFileScopes){
      const result=await publishWorkspaceFiles({...publish,room:undefined,files:[workspaceFile.id]})
      assert.equal(result.status,'workspace_files_published')
      assert.equal(result.count,1)
      const readBack=await fetch(targetApp+'/api/workspace-files?'+new URLSearchParams({workspace,file:workspaceFile.id}),{
        headers:{Authorization:'Bearer '+destinationProof.session.access_token},
      })
      assert.equal(readBack.status,200)
      assert.deepEqual(Buffer.from(await readBack.arrayBuffer()),workspaceFile.bytes)
    }
    console.log('The admitted file reached the scanner fixture and opened byte-for-byte from the normal Files tab.')
  }
  if(!sourceMember)await makeMatchedMembers()
  const [sourceMemberProof,targetMemberProof]=await Promise.all([
    fixtureAuthenticator(sourceMember.client),fixtureAuthenticator(targetMember.client),
  ])
  const membership={sourceDatabase,sourceProject,sourceKey,sourceMemberSession:sourceMemberProof.session.access_token,
    targetDatabase,targetKey:targetPublishable,targetOwnerSession:destinationProof.session.access_token,
    targetMemberSession:targetMemberProof.session.access_token,workspace,approval}
  await assert.rejects(inviteResidencyMember({...membership,targetMemberSession:foreignProof.session.access_token}),/same confirmed email/)
  await assert.rejects(inviteResidencyMember({...membership,sourceMemberSession:reviewerProof.session.access_token}),/403/)
  await assert.rejects(inviteResidencyMember({...membership,targetOwnerSession:foreignProof.session.access_token}),/403/)
  await assert.rejects(inviteResidencyMember({...membership,sourceProject:'wrong-project'}),/403/)
  const memberInvite=await inviteResidencyMember(membership)
  assert.deepEqual(await inviteResidencyMember(membership),memberInvite)
  assert.equal(memberInvite.status,'destination_invitation_ready')
  const verifiedTargetMember=createClient(targetDatabase,targetPublishable,{...options,
    accessToken:async()=>targetMemberProof.session.access_token})
  assert.deepEqual(data(await verifiedTargetMember.from('st_v2_items').select('id').eq('workspace_id',workspace)),[])
  let memberPage
  if(targetApp){
    const { session } = data(await targetMember.client.auth.getSession())
    const context=await browser.newContext({storageState:{cookies:[],origins:[{origin:targetApp,
      localStorage:[{name:'sb-127-auth-token',value:JSON.stringify(session)}],
    }]}})
    memberPage=await context.newPage()
    await memberPage.goto(targetApp)
    await memberPage.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Workspaces',exact:true}).click()
    const invitation=memberPage.locator('.release-row').filter({hasText:'Dedicated test workspace'})
    await invitation.getByRole('button',{name:'Join',exact:true}).click()
    await memberPage.getByRole('group',{name:'Workspace sections'}).getByRole('button',{name:'Board',exact:true}).click()
    await memberPage.getByText('Selected synthetic task 1',{exact:true}).waitFor()
    if(checkRoomImport) {
      await memberPage.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Rooms',exact:true}).click()
      const directory=memberPage.getByRole('region',{name:'Room directory',exact:true})
      await directory.waitFor()
      assert.equal(await directory.getByRole('button',{name:/Approved destination room/}).count(),0)
    }
    console.log('The verified member accepted the normal destination invitation in Edge and opened the migrated Board.')
  }else{
    assert.equal(data(await verifiedTargetMember.rpc('st_v2_reply_invite',{p_invite:memberInvite.invitation,p_accept:true})),workspace)
  }
  assert.equal(data(await verifiedTargetMember.from('st_v2_items').select('id').eq('workspace_id',workspace)).length,26)
  assert.equal(targetSql(`select role from public.st_v2_members where workspace_id='${workspace}' and user_id='${targetMember.id}'`),'member')
  if(checkRoomImport)assert.deepEqual(data(await verifiedTargetMember.from('st_v6_rooms').select('id').eq('id',room)),[])
  if(checkRoomTaskImport)assert.deepEqual(data(await verifiedTargetMember.from('st_v6_tasks').select('id').eq('room_id',room)),[])
  if(checkRoomFileImport){
    const denied=await fetch(targetApp+'/api/room-files?'+new URLSearchParams({room,file:fileId}),{
      headers:{Authorization:'Bearer '+targetMemberProof.session.access_token},
    })
    assert.equal(denied.status,404)
  }
  assert.equal(sourceSql(`select role from public.st_v2_members where workspace_id='${workspace}' and user_id='${sourceMember.id}'`),'member')
  if(checkChannelHistory||checkRoomMemberImport||checkCutover){
    const sharedKey=randomBytes(32).toString('hex')
    for(const [command,side] of [[sourceSql,'source'],[targetSql,'destination']])command(`
      insert into sectalk_private.st_v8_residency_history_links(workspace,approval,source_project,destination_project,side,vault_id,expires_at)
      values('${workspace}','${approval}','${sourceProject}','${destinationProject}','${side}',vault.create_secret('${sharedKey}'),now()+interval '25 minutes');`)
  }
  if(checkRoomMemberImport){
    const scope={p_workspace:workspace,p_approval:approval,p_room:room}
    const sourceRoomMember=proofClient(sourceMemberProof)
    const sourceAttestation=(client,args={})=>client.rpc('st_v8_residency_room_member_proof',{
      ...scope,p_challenge:randomBytes(32).toString('hex'),...args,
    })
    assert.equal((await sourceAttestation(verifiedOwner)).error?.code,'42501')
    assert.equal((await sourceAttestation(sourceRoomMember,{p_room:retryRoom})).error?.code,'42501')
    const witness=data(await sourceAttestation(sourceRoomMember))
    assert.match(witness.signature,/^[0-9a-f]{64}$/)
    assert.ok(!witness.payload.includes('@example.invalid'))
    const payload={...scope,p_payload:witness.payload,p_signature:witness.signature}
    const claimRoom=(client,args=payload)=>client.rpc('st_v8_residency_room_member_claim',args)
    assert.equal((await claimRoom(targetPublic)).error?.code,'42501')
    assert.equal((await claimRoom(verifiedForeign)).error?.code,'42501')
    assert.equal((await claimRoom(verifiedTargetMember,{...payload,p_room:retryRoom})).error?.code,'42501')
    assert.equal((await claimRoom(verifiedTargetMember,{...payload,p_payload:witness.payload+' '})).error?.code,'42501')
    const different=await account('room_wrong',true)
    targetSql(`insert into public.st_v2_members(workspace_id,user_id,role) values('${workspace}','${different.id}','member');`)
    const differentProof=await fixtureAuthenticator(different.client)
    const wrongIdentity=createClient(targetDatabase,targetPublishable,{...options,accessToken:async()=>differentProof.session.access_token})
    assert.equal((await claimRoom(wrongIdentity)).error?.code,'42501')
    targetSql(`insert into sectalk_private.st_v8_workspace_standard_room_sso(workspace,protocol,provider)
      values('${workspace}','oidc','custom:room-fixture-disabled');`)
    assert.equal((await claimRoom(verifiedTargetMember)).error?.code,'42501')
    targetSql(`delete from sectalk_private.st_v8_workspace_standard_room_sso where workspace='${workspace}';`)
    const memberClaim=data(await claimRoom(verifiedTargetMember))
    const approve=(client,args={})=>client.rpc('st_v8_residency_room_member_invite',{
      p_workspace:workspace,p_claim:memberClaim,p_confirmation:workspace,...args,
    })
    assert.equal((await approve(verifiedTargetMember)).error?.code,'42501')
    assert.equal((await approve(verifiedDestination,{p_confirmation:'wrong'})).error?.code,'42501')
    data(await verifiedDestination.rpc('st_v6_room_membership',{p_room:room,p_action:'invite',p_target:targetMember.id,p_role:'read_only'}))
    assert.equal((await approve(verifiedDestination)).error?.code,'PT409')
    assert.equal(data(await verifiedTargetMember.from('st_v6_room_entries').select('invited_role').eq('room_id',room).single()).invited_role,'read_only')
    data(await verifiedTargetMember.rpc('st_v6_room_membership',{p_room:room,p_action:'decline'}))
    targetSql(`update sectalk_private.st_v8_residency_history_links set expires_at=now() where workspace='${workspace}';`)
    assert.equal((await approve(verifiedDestination)).error?.code,'42501')
    targetSql(`update sectalk_private.st_v8_residency_history_links set expires_at=now()+interval '25 minutes' where workspace='${workspace}';`)
    const roomTransfer={...membership,room}
    const invited=await inviteResidencyRoomMember(roomTransfer)
    assert.equal(invited.claim,memberClaim)
    assert.equal(invited.status,'pending')
    assert.deepEqual(await inviteResidencyRoomMember(roomTransfer),invited)
    assert.equal(targetSql(`select count(*) from public.st_v6_room_members where (room_id,user_id)=('${room}','${targetMember.id}');`),'0')
    assert.equal(data(await verifiedTargetMember.from('st_v6_room_entries').select('invited_role').eq('room_id',room).single()).invited_role,'member')
    if(memberPage){
      const directory=memberPage.getByRole('region',{name:'Room directory',exact:true})
      await directory.getByRole('button',{name:/Approved destination room/}).click()
      await directory.getByRole('button',{name:'Accept room invitation',exact:true}).click()
      await directory.getByRole('group',{name:'Room tabs',exact:true}).getByRole('button',{name:'Messages',exact:true}).waitFor()
    }else data(await verifiedTargetMember.rpc('st_v6_room_membership',{p_room:room,p_action:'accept'}))
    assert.equal(targetSql(`select role from public.st_v6_room_members where (room_id,user_id)=('${room}','${targetMember.id}');`),'member')
    assert.equal((await inviteResidencyRoomMember(roomTransfer)).status,'accepted')
    assert.deepEqual(data(await wrongIdentity.from('st_v6_rooms').select('id').eq('id',room)),[])
    assert.equal(targetSql(`select count(*) from sectalk_private.st_v8_residency_room_member_invites
      where id='${memberClaim}' and identity is null and challenge is null and invited_at is not null;`),'1')
    console.log('Verified the exact attested room membership, preserved existing requests, and accepted the ordinary role through native Rooms.')
  }
  if(checkExistingChannelReplay){
    const receipt=data(await verifiedDestination.rpc('st_v8_residency_channel_import',{...importCommand,p_channel:channel}))
    assert.equal(receipt.channel,channel)
    assert.equal(receipt.name,existingChannelName)
    const restored=await restoreResidencyChannelPost({...membership,channel,post:importedPost})
    assert.equal(restored.post,importedPost)
  }
  if(checkChannelHistory){
    const scope={p_workspace:workspace,p_approval:approval,p_channel:channel,p_post:importedPost}
    const sourceAuthor=proofClient(sourceMemberProof)
    const transfer={...membership,channel,post:importedPost}
    const witness=data(await sourceAuthor.rpc('st_v8_residency_channel_author_proof',{
      ...scope,p_challenge:randomBytes(32).toString('hex'),
    }))
    const targetPayload={...scope,p_payload:witness.payload,p_signature:witness.signature}
    const publish=(client,params=targetPayload)=>client.rpc('st_v8_residency_publish_channel_history',params)
    assert.equal((await publish(targetPublic)).error?.code,'42501')
    assert.equal((await publish(verifiedForeign)).error?.code,'42501')
    const different=await account('other_author',true)
    targetSql(`insert into public.st_v2_members(workspace_id,user_id,role) values('${workspace}','${different.id}','member');`)
    const differentProof=await fixtureAuthenticator(different.client)
    const differentClient=createClient(targetDatabase,targetPublishable,{...options,accessToken:async()=>differentProof.session.access_token})
    assert.equal((await publish(differentClient)).error?.code,'42501')
    assert.equal((await publish(verifiedTargetMember,{...targetPayload,p_channel:retryChannel})).error?.code,'42501')
    assert.equal((await publish(verifiedTargetMember,{...targetPayload,p_payload:witness.payload+' '})).error?.code,'42501')
    await assert.rejects(restoreResidencyChannelPost({...transfer,sourceMemberSession:ownerProof.session.access_token}),/403/)
    targetSql(`insert into sectalk_private.st_v8_workspace_standard_channel_sso(workspace,protocol,provider)
      values('${workspace}','oidc','custom:fixture-disabled');`)
    assert.equal((await publish(verifiedTargetMember)).error?.code,'42501')
    targetSql(`delete from sectalk_private.st_v8_workspace_standard_channel_sso where workspace='${workspace}';`)
    targetSql(`update sectalk_private.st_v8_residency_history_links set expires_at=now() where workspace='${workspace}';`)
    assert.equal((await publish(verifiedTargetMember)).error?.code,'42501')
    targetSql(`update sectalk_private.st_v8_residency_history_links set expires_at=now()+interval '25 minutes' where workspace='${workspace}';`)
    const copies=await Promise.all([restoreResidencyChannelPost(transfer),restoreResidencyChannelPost(transfer)])
    assert.deepEqual(copies[0],copies[1])
    assert.equal(copies[0].post,importedPost)
    const original=data(await sourceAuthor.from('st_v2_posts').select('id,channel_id,sender,body,created_at').eq('id',importedPost).single())
    const restored=data(await verifiedTargetMember.from('st_v2_posts').select('id,channel_id,sender,body,created_at').eq('id',importedPost).single())
    assert.deepEqual(restored,{...original,sender:targetMember.id})
    assert.notEqual(restored.sender,original.sender)
    assert.equal(targetSql(`select count(*) from public.st_v2_workspace_audit where event='channel.message_residency_imported' and target='${importedPost}';`),'1')
    if(targetApp){
      await page.getByRole('group',{name:'Workspace sections'}).getByRole('button',{name:'Channels',exact:true}).click()
      await page.getByLabel('Channel',{exact:true}).selectOption(channel)
      await page.getByText(importedBody,{exact:true}).waitFor()
    }
    console.log('Verified original author, exact historic body and time, tenant denial, retry and native Channels publication.')
  }
  if(checkRoomHistory){
    const transfer={...membership,room}
    const sourceAuthor=proofClient(sourceMemberProof)
    const scope={p_workspace:workspace,p_approval:approval,p_room:room,p_post:roomRoot}
    const witness=data(await sourceAuthor.rpc('st_v8_residency_room_author_proof',{
      ...scope,p_challenge:randomBytes(32).toString('hex'),
    }))
    const payload={...scope,p_payload:witness.payload,p_signature:witness.signature}
    assert.equal((await verifiedForeign.rpc('st_v8_residency_publish_room_history',payload)).error?.code,'42501')
    assert.equal((await verifiedTargetMember.rpc('st_v8_residency_publish_room_history',{
      ...payload,p_payload:witness.payload+' ',
    })).error?.code,'42501')
    await assert.rejects(restoreResidencyPost({...transfer,post:roomRoot,sourceMemberSession:ownerProof.session.access_token}),/403/)
    await assert.rejects(restoreResidencyPost({...transfer,post:roomReply}),/409/)
    const restored=await restoreResidencyPost({...transfer,post:roomRoot})
    assert.equal(restored.post,roomRoot)
    targetSql(`update public.st_v6_room_posts set body='Modified target root' where (room_id,id)=('${room}','${roomRoot}');`)
    await assert.rejects(restoreResidencyPost({...transfer,post:roomReply}),/409/)
    targetSql(`update public.st_v6_room_posts set body='${rootBody}' where (room_id,id)=('${room}','${roomRoot}');`)
    const reply=await restoreResidencyPost({...transfer,post:roomReply})
    assert.equal(reply.post,roomReply)
    assert.deepEqual(await restoreResidencyPost({...transfer,post:roomReply}),reply)
    const fields='id,sender,parent_id,kind,body,created_at,edited_at'
    const posts=client=>client.from('st_v6_room_posts').select(fields).eq('room_id',room).in('id',[roomRoot,roomReply]).order('id')
    const original=data(await posts(sourceAuthor))
    assert.equal(original.length,2)
    assert.ok(original.every(post=>post.sender===sourceMember.id))
    assert.deepEqual(data(await posts(verifiedTargetMember)),original.map(post=>({...post,sender:targetMember.id})))
    assert.equal(targetSql(`select count(*) from public.st_v2_workspace_audit where workspace_id='${workspace}'
      and actor='${targetMember.id}' and event='room.message_residency_imported';`),'2')
    if(memberPage){
      await memberPage.getByRole('button',{name:'Rooms',exact:true}).click()
      const directory=memberPage.getByRole('region',{name:'Room directory',exact:true})
      await directory.getByRole('button',{name:/Approved destination room/}).click()
      await directory.getByText(rootBody,{exact:true}).waitFor()
      await directory.getByRole('button',{name:/^Open thread/}).click()
      await directory.getByText(replyBody,{exact:true}).waitFor()
    }
    console.log('Verified approved room thread restoration, exact original text and timestamps, membership and reply ordering.')
  }
  if(checkDestinationComparison){
    const compare=(client,params={})=>client.rpc('st_v8_residency_compare_destination',{
      p_workspace:workspace,p_approval:approval,...params,
    })
    const comparison=data(await compare(verifiedDestination))
    assert.equal(comparison.manifestSha256,manifest.manifestSha256)
    assert.equal(comparison.records.length,expectedRecords)
    assert.equal(comparison.approvalCurrent,true)
    assert.ok(comparison.records.every(record=>Object.keys(record).sort().join(',')==='id,kind,scope,status'))
    assert.equal(comparison.records.filter(record=>record.kind==='workspace_task'&&record.status==='matched').length,26)
    assert.ok(approvedRoomTasks.every(id=>comparison.records.some(record=>record.id===id&&record.status==='matched')))
    assert.ok(comparison.records.some(record=>record.kind==='room_task'&&record.scope===tasksOnlyRoom&&record.status==='missing'))
    assert.ok(comparison.records.some(record=>record.id===importedPost&&record.status==='matched'))
    assert.ok(comparison.records.some(record=>record.kind==='room_message'&&record.status==='missing'))
    if(checkRoomHistory)for(const id of [roomRoot,roomReply]){
      assert.ok(comparison.records.some(record=>record.kind==='room_message'&&record.id===id&&record.status==='matched'))
    }
    assert.ok(comparison.records.some(record=>record.id===fileId&&record.status==='check_bytes'))
    if(checkBothFileScopes)assert.ok(comparison.records.some(record=>record.id===workspaceFile.id&&record.status==='check_bytes'))
    assert.ok((await compare(targetPublic)).error)
    assert.equal((await compare(verifiedTargetMember)).error?.code,'42501')
    assert.equal((await compare(verifiedForeign)).error?.code,'42501')
    assert.equal((await compare(verifiedDestination,{p_approval:randomUUID()})).error?.code,'42501')

    const changed=records.find(record=>record.kind==='workspace_task')
    targetSql(`update public.st_v2_items set title='Changed fixture task' where (workspace_id,id)=('${workspace}','${changed.id}');`)
    assert.equal(data(await compare(verifiedDestination)).records.find(record=>record.id===changed.id).status,'changed')
    const original=JSON.parse(changed.json).title.replaceAll("'","''")
    targetSql(`update public.st_v2_items set title='${original}' where (workspace_id,id)=('${workspace}','${changed.id}');`)
    if(checkRoomHistory){
      targetSql(`update public.st_v6_room_posts set body='Changed fixture reply' where (room_id,id)=('${room}','${roomReply}');`)
      assert.equal(data(await compare(verifiedDestination)).records.find(record=>record.id===roomReply).status,'changed')
      targetSql(`update public.st_v6_room_posts set body='${replyBody}' where (room_id,id)=('${room}','${roomReply}');`)
    }
    targetSql(`update sectalk_private.st_v8_residency_content_admissions set record_count=record_count+1 where approval='${approval}';`)
    assert.equal((await compare(verifiedDestination)).error?.code,'PT409')
    targetSql(`update sectalk_private.st_v8_residency_content_admissions set record_count=record_count-1,expires_at=now() where approval='${approval}';`)
    assert.equal(data(await compare(verifiedDestination)).approvalCurrent,false)
    targetSql(`update sectalk_private.st_v8_residency_content_admissions set expires_at=now()+interval '1 hour' where approval='${approval}';`)
    const fileScope=checkRoomFileImport?{room}:{workspace}
    const verifyUrl=targetApp+(checkRoomFileImport?'/api/room-files?':'/api/workspace-files?')
    const verifyBytes=(token,params={})=>fetch(verifyUrl+new URLSearchParams({
      ...fileScope,file:fileId,'residency-verify':approval,...params,
    }),{headers:{Authorization:'Bearer '+token}})
    const verificationArgs={p_kind:checkRoomFileImport?'room':'workspace',p_scope:checkRoomFileImport?room:workspace,
      p_approval:approval,p_file:fileId}
    assert.equal((await verifyBytes(foreignProof.session.access_token)).status,404)
    assert.equal((await verifyBytes(destinationProof.session.access_token,{'residency-verify':randomUUID()})).status,404)
    assert.ok((await verifiedDestination.rpc('st_v8_record_residency_file_verification',{
      ...verificationArgs,p_actor:destinationOwner.id,p_session:randomUUID(),p_snapshot:{},p_sha256:'0'.repeat(64),p_bytes:fileBytes.length,
    })).error)
    await page.getByRole('button',{name:'Organization settings',exact:true}).click()
    const panel=page.getByRole('region',{name:'Compare destination records',exact:true})
    await panel.getByRole('button',{name:'Compare approved records',exact:true}).click()
    await panel.getByRole('status').getByText(`Checked ${expectedRecords} approved records`,{exact:false}).waitFor()
    await panel.getByText(/Review \d+ records that need attention/).click()
    const verifyButton=panel.getByRole('button',{name:'Verify file '+fileId,exact:true})
    await verifyButton.click()
    await verifyButton.waitFor({state:'hidden'})
    const statusOf=async()=>data(await compare(verifiedDestination)).records.find(record=>record.id===fileId).status
    assert.equal(await statusOf(),'matched')
    const valid=await verifyBytes(destinationProof.session.access_token)
    assert.equal(valid.status,200)
    assert.deepEqual(await valid.json(),{verified:true})
    const evidenceCount=()=>targetSql(`select count(*) from sectalk_private.st_v8_residency_file_verifications
      where (workspace,approval,file)=('${workspace}','${approval}','${fileId}');`)
    assert.equal(evidenceCount(),'1')
    const path=checkRoomFileImport?`${workspace}/rooms/${room}/${fileId}`:`${workspace}/${fileId}`
    const bucket=target.storage.from('sectalk-workspace-files')
    data(await bucket.update(path,Buffer.alloc(fileBytes.length,120),{contentType:'application/octet-stream'}))
    assert.equal(await statusOf(),'check_bytes')
    assert.equal((await verifyBytes(destinationProof.session.access_token)).status,404)
    assert.equal(evidenceCount(),'1')
    data(await bucket.update(path,fileBytes,{contentType:'application/octet-stream'}))
    assert.equal(await statusOf(),'check_bytes')
    assert.equal((await verifyBytes(destinationProof.session.access_token)).status,200)
    assert.equal(await statusOf(),'matched')
    assert.equal(evidenceCount(),'2')
    if(checkComparisonReceipt){
      const receiptScope={p_workspace:workspace,p_approval:approval}
      const issue=(client,args=receiptScope)=>client.rpc('st_v8_residency_issue_comparison_receipt',args)
      const reviewReceipt=(client,proof,spec=receiptScope)=>client.rpc('st_v8_residency_review_comparison_receipt',{
        ...spec,...(proof?{p_proof:proof}:{}),
      })
      assert.equal((await issue(verifiedTargetMember)).error?.code,'42501')
      assert.equal((await issue(verifiedDestination,{...receiptScope,p_approval:randomUUID()})).error?.code,'42501')
      assert.equal((await reviewReceipt(outsider.client)).error?.code,'42501')
      assert.deepEqual(data(await reviewReceipt(verifiedReviewer)),{role:'reviewer',receipt:null})
      targetSql(`update sectalk_private.st_v8_residency_history_links set expires_at=now()+interval '3 seconds' where workspace='${workspace}';`)
      const expired=data(await issue(verifiedDestination))
      targetSql(`update sectalk_private.st_v8_residency_history_links set expires_at=now()+interval '25 minutes' where workspace='${workspace}';`)
      await new Promise(resolve=>setTimeout(resolve,Math.max(100,JSON.parse(expired.payload).expires*1000-Date.now()+150)))
      assert.equal((await reviewReceipt(verifiedReviewer,expired)).error?.code,'42501')
      await panel.getByRole('button',{name:'Create destination comparison receipt',exact:true}).click()
      const proofInput=panel.getByRole('textbox',{name:/Destination comparison receipt/})
      await proofInput.waitFor()
      const encoded=await proofInput.inputValue(), proof=JSON.parse(encoded), claims=JSON.parse(proof.payload)
      assert.deepEqual(Object.keys(claims).sort(),['approval','checked','counts','destination','expires','format','manifest','source','workspace'])
      const live=data(await compare(verifiedDestination))
      for(const [status,count] of Object.entries(claims.counts)){
        assert.equal(live.records.filter(record=>record.status===status).length,count)
      }
      assert.ok(claims.counts.missing>0&&claims.counts.matched>0)
      assert.equal((await reviewReceipt(verifiedOwner,proof)).error?.code,'42501')
      assert.equal((await reviewReceipt(verifiedReviewer,{...proof,payload:proof.payload+' '})).error?.code,'42501')
      assert.equal((await reviewReceipt(verifiedReviewer,proof,{...receiptScope,p_workspace:unrelated})).error?.code,'42501')
      const sourceOrigin=new URL(sourceApp).origin
      const {session}=data(await reviewer.client.auth.getSession())
      const context=await browser.newContext({storageState:{cookies:[],origins:[{origin:sourceOrigin,
        localStorage:[{name:'sb-127-auth-token',value:JSON.stringify(session)}],
      }]}})
      const sourcePage=await context.newPage()
      await sourcePage.goto(sourceOrigin+'/?workspace='+workspace)
      await sourcePage.getByRole('button',{name:'Compliance exports',exact:true}).click()
      const review=sourcePage.getByRole('region',{name:'Destination comparison review',exact:true})
      if(checkBothFileScopes){
        await sourcePage.getByText('Source migration coverage',{exact:true}).click()
        await sourcePage.getByRole('button',{name:'Check source coverage',exact:true}).click()
        const counts=sourcePage.getByRole('list',{name:'Source coverage totals',exact:true})
        await counts.getByText('Workspace files',{exact:true}).waitFor()
        assert.match(await counts.innerText(),/Room files.*1 observed.*1 current approvals/)
      }
      await review.getByRole('textbox',{name:'Paste destination comparison receipt',exact:true}).fill(encoded)
      await review.getByRole('button',{name:'Verify destination receipt',exact:true}).click()
      await review.getByRole('status').getByText('Destination receipt accepted at',{exact:false}).waitFor()
      const received=data(await reviewReceipt(verifiedReviewer,proof))
      assert.equal(received.role,'reviewer')
      assert.deepEqual(received.receipt.counts,claims.counts)
      assert.deepEqual(data(await reviewReceipt(verifiedOwner)).receipt,received.receipt)
      assert.equal(sourceSql(`select count(*) from public.st_v2_workspace_audit where workspace_id='${workspace}'
        and event='workspace.residency_comparison_reviewed' and actor='${reviewer.id}';`),'1')
      await context.close()
      console.log('Edge verified independent source review of destination comparison totals with expired, tampered and out-of-scope receipt denial.')
    }
    console.log('Verified exact restored rows, protected destination byte comparison, same-size replacement invalidation, and scoped comparison.')
  }
  if(checkWriteHandoff){
    const scope={p_workspace:workspace}
    const action=(client,p_action='status',p_proof=null)=>client.rpc('st_v8_residency_write_handoff',{
      ...scope,p_action,p_approval:approval,p_confirmation:workspace,p_proof,
    })
    const nativePost=(client,destination)=>client.rpc('st_v2_post',{
      p_channel:destination?channel:sourceGeneral,p_id:randomUUID(),p_body:'Disposable migration write check',
    })
    assert.equal(data(await action(verifiedDestination)).phase,'ready')
    assert.equal((await action(verifiedForeign,'prepare')).error?.code,'42501')
    assert.equal((await action(verifiedReviewer,'hold')).error?.code,'42501')
    await page.goto(new URL('/?workspace='+workspace,targetApp).href)
    const destinationHandoff=page.getByRole('region',{name:'Migration write handoff',exact:true})
    await destinationHandoff.getByLabel('Confirm handoff workspace ID',{exact:true}).fill(workspace)
    await destinationHandoff.getByRole('button',{name:'Put destination on standby',exact:true}).click()
    const destinationProofInput=destinationHandoff.getByRole('textbox',{name:/Destination write handoff proof/})
    await destinationProofInput.waitFor()
    const standbyWire=await destinationProofInput.inputValue(), standby=JSON.parse(standbyWire)
    assert.equal(data(await action(verifiedDestination)).phase,'standby')
    assert.deepEqual(data(await verifiedDestination.rpc('st_v7_workspace_payment_state',scope)),{mode:'read_only',reason:'residency',handoff:true})
    assert.equal((await nativePost(verifiedDestination,true)).error?.code,'PT423')
    assert.equal((await action(verifiedOwner,'hold',standby)).error?.code,'PT409')

    sourceSql(`insert into public.st_v2_subscriptions(user_id,plan,catalog_version,status,period_end)
        values('${owner.id}','enterprise',1,'active',now()+interval '90 days') on conflict (user_id) do update
        set plan=excluded.plan,catalog_version=excluded.catalog_version,status=excluded.status,period_end=excluded.period_end;
      insert into sectalk_private.st_v8_residency_cells values('${cell}','apac','${destinationProject}','Paired local target','fixture',null);
      insert into sectalk_private.st_v8_residency_installation (cell,installation_nonce) values('${cell}','${installationNonce}');
      insert into sectalk_private.st_v8_residency_cell_authorizations(workspace,cell) values('${workspace}','${cell}');
      insert into sectalk_private.st_v8_residency_verifiers(workspace,actor) values('${workspace}','${reviewer.id}');`)
    data(await verifiedOwner.rpc('st_v8_workspace_residency_change',{...scope,p_cell:cell}))
    const request=data(await verifiedOwner.rpc('st_v8_workspace_residency',scope)).request.id
    sourceSql(`update sectalk_private.st_v8_residency_requests set (observed_at,observation_nonce,reviewed_by,reviewed_at)=
      (now(),'${installationNonce}','${reviewer.id}',now()) where id='${request}';`)
    data(await verifiedOwner.rpc('st_v8_residency_source_pause',{
      ...scope,p_request:request,p_action:'pause',p_confirmation:workspace,
    }))
    assert.equal((await action(verifiedOwner,'hold',{...standby,payload:standby.payload+' '})).error?.code,'42501')
    const sourceOrigin=new URL(sourceApp).origin
    const {session}=data(await owner.client.auth.getSession())
    const browserContext=await browser.newContext({storageState:{cookies:[],origins:[{origin:sourceOrigin,
      localStorage:[{name:'sb-127-auth-token',value:JSON.stringify(session)}],
    }]}})
    const sourceOwnerPage=await browserContext.newPage()
    await sourceOwnerPage.goto(sourceOrigin+'/?workspace='+workspace)
    const sourceHandoff=sourceOwnerPage.getByRole('region',{name:'Migration write handoff',exact:true})
    const submitSourceProof=async(proof,name)=>{
      await sourceHandoff.getByLabel('Confirm handoff workspace ID',{exact:true}).fill(workspace)
      await sourceHandoff.getByRole('textbox',{name:'Paste destination write handoff proof',exact:true}).fill(proof)
      await sourceHandoff.getByRole('button',{name,exact:true}).click()
    }
    await submitSourceProof(standbyWire,'Hold guarded source writes')
    await sourceHandoff.getByRole('status').getByText('Guarded source writes are held beyond the temporary pause.',{exact:true}).waitFor()
    sourceSql(`update sectalk_private.st_v8_residency_source_pauses set started_at=now()-interval '40 minutes',ends_at=now()-interval '10 minutes'
      where workspace='${workspace}';`)
    assert.deepEqual(data(await verifiedOwner.rpc('st_v7_workspace_payment_state',scope)),{mode:'read_only',reason:'residency',handoff:true})
    assert.equal((await nativePost(verifiedOwner,false)).error?.code,'PT423')
    assert.equal((await action(verifiedOwner,'restore',standby)).error?.code,'42501')
    await destinationHandoff.getByLabel('Confirm handoff workspace ID',{exact:true}).fill(workspace)
    await destinationHandoff.getByRole('button',{name:'Cancel destination handoff',exact:true}).click()
    await destinationHandoff.getByRole('status').getByText('The destination handoff is cancelled.',{exact:false}).waitFor()
    const cancelWire=await destinationProofInput.inputValue(), cancelled=JSON.parse(cancelWire)
    assert.equal(JSON.parse(cancelled.payload).handoff,JSON.parse(standby.payload).handoff)
    await submitSourceProof(cancelWire,'Restore guarded source writes')
    await sourceHandoff.getByRole('status').getByText('Source write authority was restored.',{exact:false}).waitFor()
    data(await nativePost(verifiedOwner,false))
    assert.equal((await nativePost(verifiedDestination,true)).error?.code,'PT423')
    assert.equal((await action(verifiedOwner,'hold',standby)).error?.code,'42501')
    assert.equal((await action(verifiedDestination,'prepare')).error?.code,'PT409')
    await browserContext.close()
    console.log('Edge verified durable standby and source holds, guarded write denial after lease expiry and acknowledged rollback with destination still fenced.')
  }
  if(checkCutover){
    const scope={p_workspace:workspace,p_approval:approval}
    const handoff=(client,p_action,p_proof=null)=>client.rpc('st_v8_residency_write_handoff',{
      ...scope,p_action,p_proof,p_confirmation:workspace,
    })
    const cutover=(client,p_action='status',p_proof=null)=>client.rpc('st_v8_residency_cutover',{
      ...scope,p_action,p_proof,p_confirmation:workspace,
    })
    const verifyFile=async()=>{
      const response=await fetch(targetApp+'/api/workspace-files?'+new URLSearchParams({workspace,file:fileId,'residency-verify':approval}),{
        headers:{Authorization:'Bearer '+destinationProof.session.access_token},
      })
      assert.equal(response.status,200,await response.text())
    }
    const reviewNow=async()=>{
      const proof=data(await verifiedDestination.rpc('st_v8_residency_issue_comparison_receipt',scope))
      const review=data(await verifiedReviewer.rpc('st_v8_residency_review_comparison_receipt',{...scope,p_proof:proof}))
      assert.equal(review.receipt.counts.matched,expectedRecords)
    }
    await verifyFile()
    await reviewNow()
    const standby=data(await handoff(verifiedDestination,'prepare')).proof
    const handoffId=JSON.parse(standby.payload).handoff
    sourceSql(`insert into public.st_v2_subscriptions(user_id,plan,catalog_version,status,period_end)
        values('${owner.id}','enterprise',1,'active',now()+interval '90 days') on conflict (user_id) do update
        set plan=excluded.plan,catalog_version=excluded.catalog_version,status=excluded.status,period_end=excluded.period_end;
      insert into sectalk_private.st_v8_residency_cells values('${cell}','apac','${destinationProject}','Activation fixture target','fixture',null);
      insert into sectalk_private.st_v8_residency_installation (cell,installation_nonce) values('${cell}','${installationNonce}');
      insert into sectalk_private.st_v8_residency_cell_authorizations(workspace,cell) values('${workspace}','${cell}');
      insert into sectalk_private.st_v8_residency_verifiers(workspace,actor) values('${workspace}','${reviewer.id}');`)
    data(await verifiedOwner.rpc('st_v8_workspace_residency_change',{p_workspace:workspace,p_cell:cell}))
    const request=data(await verifiedOwner.rpc('st_v8_workspace_residency',{p_workspace:workspace})).request.id
    sourceSql(`update sectalk_private.st_v8_residency_requests set (observed_at,observation_nonce,reviewed_by,reviewed_at)=
      (now(),'${installationNonce}','${reviewer.id}',now()) where id='${request}';`)
    data(await verifiedOwner.rpc('st_v8_residency_source_pause',{
      p_workspace:workspace,p_request:request,p_action:'pause',p_confirmation:workspace,
    }))
    const routeUrl=sourceApp+'/api/workspaces/residency/route-link?workspace='+workspace
    const targetUrl=new URL('/?workspace='+workspace,targetApp).href
    const bearer=accessToken=>({headers:{Authorization:'Bearer '+accessToken}})
    const memberRequest=bearer(sourceMemberProof.session.access_token)
    if(checkActiveRoute){
      const rehearse=(client,p_action,p_rehearsal=null)=>client.rpc('st_v8_residency_routing_rehearsal',{
        p_workspace:workspace,p_action,p_rehearsal,p_confirmation:workspace,
      })
      const pending=data(await rehearse(verifiedOwner,'request'))
      assert.equal(pending.status,'pending')
      assert.equal((await fetch(routeUrl,memberRequest)).status,404)
      assert.equal(data(await rehearse(verifiedReviewer,'approve',pending.rehearsal)).status,'active')
      const rehearsed=await fetch(routeUrl,memberRequest)
      assert.equal(rehearsed.status,200,await rehearsed.clone().text())
      assert.deepEqual(await rehearsed.json(),{url:targetUrl})
      data(await rehearse(verifiedOwner,'end',pending.rehearsal))
      assert.equal((await fetch(routeUrl,memberRequest)).status,404)
    }
    data(await handoff(verifiedOwner,'hold',standby))
    const plan='1'.repeat(64),recovery='2'.repeat(64)
    assert.deepEqual(data(await cutover(verifiedDestination)),{admitted:false})
    assert.equal((await cutover(verifiedOwner,'issue')).error?.code,'42501')
    for(const [database,side] of [[sourceSql,'source'],[targetSql,'destination']])database(`
      insert into sectalk_private.st_v8_residency_activation_admissions values('${workspace}','${approval}','${handoffId}',
        '${side}','fixture','${manifest.manifestSha256}','${plan}','${recovery}',now()+interval '10 minutes');`)
    assert.equal((await cutover(verifiedOwner,'issue')).error?.code,'PT409')
    assert.equal((await cutover(verifiedForeign,'activate',standby)).error?.code,'42501')
    assert.equal((await cutover(verifiedDestination,'activate',standby)).error?.code,'42501')
    if(checkActiveRoute)assert.equal((await verifiedDestination.rpc('st_v8_residency_active_route',{
      ...scope,p_action:'issue',p_confirmation:workspace,
    })).error?.code,'42501')
    await new Promise(resolve=>setTimeout(resolve,1200))
    await reviewNow()

    const sourceOrigin=new URL(sourceApp).origin
    const {session}=data(await owner.client.auth.getSession())
    const context=await browser.newContext({storageState:{cookies:[],origins:[{origin:sourceOrigin,
      localStorage:[{name:'sb-127-auth-token',value:JSON.stringify(session)}],
    }]}})
    const sourceOwnerPage=await context.newPage()
    await sourceOwnerPage.goto(sourceOrigin+'/?workspace='+workspace)
    const sourceActivation=sourceOwnerPage.getByRole('region',{name:'Guarded destination activation',exact:true})
    await sourceActivation.getByLabel('Confirm activation workspace ID',{exact:true}).fill(workspace)
    await sourceActivation.getByRole('button',{name:'Create source activation proof',exact:true}).click()
    const proofBox=sourceActivation.getByRole('textbox',{name:/^Source activation proof/})
    await proofBox.waitFor()
    const encoded=await proofBox.inputValue(),proof=JSON.parse(encoded)
    await context.close()
    targetSql(`update sectalk_private.st_v8_residency_activation_admissions set recovery_sha256='${'3'.repeat(64)}' where workspace='${workspace}';`)
    assert.equal((await cutover(verifiedDestination,'activate',proof)).error?.code,'42501')
    targetSql(`update sectalk_private.st_v8_residency_activation_admissions set recovery_sha256='${recovery}' where workspace='${workspace}';`)
    const bucket=target.storage.from('sectalk-workspace-files'),path=workspace+'/'+fileId
    data(await bucket.update(path,Buffer.alloc(fileBytes.length,120),{contentType:'application/octet-stream'}))
    assert.equal((await cutover(verifiedDestination,'activate',proof)).error?.code,'PT409')
    data(await bucket.update(path,fileBytes,{contentType:'application/octet-stream'}))
    await verifyFile()
    await page.goto(new URL('/?workspace='+workspace,targetApp).href)
    const targetActivation=page.getByRole('region',{name:'Guarded destination activation',exact:true})
    await targetActivation.getByLabel('Confirm activation workspace ID',{exact:true}).fill(workspace)
    await targetActivation.getByRole('textbox',{name:'Paste source activation proof',exact:true}).fill(encoded)
    await targetActivation.getByRole('button',{name:'Activate guarded destination writes',exact:true}).click()
    await page.getByRole('status').getByText('Guarded destination writes are active.',{exact:false}).waitFor()
    assert.equal((await handoff(verifiedDestination,'cancel')).error?.code,'PT409')
    assert.equal((await handoff(verifiedOwner,'restore',standby)).error?.code,'42501')
    assert.equal((await cutover(verifiedDestination,'activate',proof)).error?.code,'42501')
    const general=db=>db(`select id from public.st_v2_channels where workspace_id='${workspace}' and name='general';`)
    assert.equal((await verifiedOwner.rpc('st_v2_post',{p_channel:general(sourceSql),p_id:randomUUID(),p_body:'Held source'})).error?.code,'PT423')
    if(checkRollbackFileCopy){
      const response=await fetch(targetApp+'/api/workspace-files?'+new URLSearchParams({workspace,file:rollbackFile.id}),{
        method:'POST',body:rollbackFile.bytes,headers:{Authorization:'Bearer '+destinationProof.session.access_token,
          'Content-Type':'text/plain','X-SecTalk-File-Name':rollbackFile.name},
      })
      assert.equal(response.status,200,await response.text())
    }
    const acceptedDestinationPost=randomUUID()
    data(await verifiedDestination.rpc('st_v2_post',{p_channel:general(targetSql),p_id:acceptedDestinationPost,p_body:'Activated destination'}))
    let recoveredChannel,recoveredPost,reportedPost,otherSenderPost,channelRevision,postRevision,memberPostRevision
    let existingChannelPost,existingChannelRevision
    if(checkExistingChannelReplay){
      existingChannelPost=randomUUID()
      data(await verifiedDestination.rpc('st_v2_post',{
        p_channel:channel,p_id:existingChannelPost,p_body:'Recovery to a previously migrated channel',
      }))
      existingChannelRevision=data(await verifiedDestination.from('st_v2_posts')
        .select('id,channel_id,body,created_at').eq('id',existingChannelPost).single())
    }
    if(checkChannelReplay){
      recoveredChannel=data(await verifiedDestination.rpc('st_v2_create_channel',{p_workspace:workspace,p_name:'rollback-verified-chat'}))
      recoveredPost=randomUUID();reportedPost=randomUUID();otherSenderPost=randomUUID()
      data(await verifiedDestination.rpc('st_v2_post',{p_channel:recoveredChannel,p_id:recoveredPost,p_body:'Reviewed recovery chat message'}))
      if(!checkSourceSignoff)data(await verifiedDestination.rpc('st_v2_post',{
        p_channel:recoveredChannel,p_id:reportedPost,p_body:'Synthetic reported recovery control',
      }))
      data(await verifiedTargetMember.rpc('st_v2_post',{p_channel:recoveredChannel,p_id:otherSenderPost,p_body:'Separate author control'}))
      if(!checkSourceSignoff)data(await verifiedTargetMember.rpc('st_v7_submit_channel_report',{
        p_channel:recoveredChannel,p_post:reportedPost,p_category:'other',p_details:'Synthetic recovery exclusion',
        p_share_with_safety:true,p_share_with_workspace:false,
      }))
      channelRevision=data(await verifiedDestination.from('st_v2_channels').select('id,name,created_at').eq('id',recoveredChannel).single())
      postRevision=data(await verifiedDestination.from('st_v2_posts').select('id,channel_id,body,created_at').eq('id',recoveredPost).single())
      if(checkMemberChannelReplay)memberPostRevision=data(await verifiedDestination.from('st_v2_posts')
        .select('id,channel_id,body,created_at').eq('id',otherSenderPost).single())
    }
    let updatedTargetTask
    let replayTaskIds=[]
    let addedTask,nonOwnerTask,addedRevision,memberRevision
    if(checkRollbackReview){
      updatedTargetTask=targetSql(`select id from public.st_v2_items where workspace_id='${workspace}' and title='Selected synthetic task 1';`)
      data(await verifiedDestination.rpc('st_v2_complete_task',{p_item:updatedTargetTask,p_complete:true}))
      if(checkBoardReplay){
        const secondTask=targetSql(`select id from public.st_v2_items where workspace_id='${workspace}' and title='Selected synthetic task 2';`)
        data(await verifiedDestination.rpc('st_v2_complete_task',{p_item:secondTask,p_complete:true}))
        replayTaskIds=[updatedTargetTask,secondTask].sort()
        if(checkBoardAdditions){
          addedTask=data(await verifiedDestination.rpc('st_v2_add_item',{
            p_workspace:workspace,p_kind:'task',p_title:'Post-activation recovery task',p_details:'Keep this exact private Board detail.',
            p_due:'2027-01-15T12:00:00Z',
          }))
          nonOwnerTask=data(await verifiedTargetMember.rpc('st_v2_add_item',{
            p_workspace:workspace,p_kind:'task',p_title:'Separate member task',p_details:'Requires separate identity proof.',p_due:null,
          }))
          addedRevision=data(await verifiedDestination.from('st_v2_items').select('id,title,details,created_at,due_at,completed')
            .eq('id',addedTask).single())
          if(checkMemberBoardReplay)memberRevision=data(await verifiedDestination.from('st_v2_items')
            .select('id,title,details,created_at,due_at,completed').eq('id',nonOwnerTask).single())
        }
      }
      targetSql(`insert into public.st_v2_members(workspace_id,user_id,role) values('${workspace}','${foreignOwner.id}','admin');
        insert into sectalk_private.st_v8_offboarding_reviewers(workspace,actor) values('${workspace}','${foreignOwner.id}');`)
    }
    assert.equal(targetSql(`select count(*) from public.st_v2_workspace_audit where workspace_id='${workspace}'
      and event='workspace.residency_destination_activated' and target='${handoffId}';`),'1')
    console.log('Edge verified guarded destination activation, independent fresh evidence, rejection of drift and unshared plans, and source remaining held.')
    if(checkActiveRoute){
      const routing=(client,p_action='status',p_proof=null)=>client.rpc('st_v8_residency_active_route',{
        ...scope,p_action,p_proof,p_confirmation:workspace,
      })
      assert.deepEqual(data(await routing(verifiedDestination)),{status:'ready',side:'destination',approval})
      await page.reload()
      const destinationRouting=page.getByRole('region',{name:'Active workspace routing',exact:true})
      await destinationRouting.getByLabel('Confirm active route workspace ID').fill(workspace)
      await destinationRouting.getByRole('button',{name:'Create destination activation proof',exact:true}).click()
      const destinationProofField=destinationRouting.getByRole('textbox',{name:'Destination activation proof',exact:true})
      await destinationProofField.waitFor()
      const destinationRouteProof=JSON.parse(await destinationProofField.inputValue())
      assert.equal((await routing(verifiedOwner,'publish',proof)).error?.code,'42501')
      assert.equal((await routing(verifiedOwner,'publish',{...destinationRouteProof,payload:destinationRouteProof.payload+' '})).error?.code,'42501')
      assert.equal((await routing(sourceMember.client,'publish',destinationRouteProof)).error?.code,'42501')
      const sourceOwnerContext=await browser.newContext({storageState:{cookies:[],origins:[{origin:sourceOrigin,
        localStorage:[{name:'sb-127-auth-token',value:JSON.stringify(session)}],
      }]}})
      const publishPage=await sourceOwnerContext.newPage()
      await publishPage.goto(sourceOrigin+'/?workspace='+workspace)
      const sourceRouting=publishPage.getByRole('region',{name:'Active workspace routing',exact:true})
      await sourceRouting.getByLabel('Confirm active route workspace ID').fill(workspace)
      await sourceRouting.getByRole('textbox',{name:'Paste destination activation proof',exact:true}).fill(JSON.stringify(destinationRouteProof))
      await sourceRouting.getByRole('button',{name:'Publish active workspace route',exact:true}).click()
      await sourceRouting.getByRole('button',{name:'Open the active workspace',exact:true}).waitFor()
      assert.equal(data(await routing(verifiedOwner,'publish',destinationRouteProof)).status,'active')
      assert.equal(sourceSql(`select count(*) from public.st_v2_workspace_audit where workspace_id='${workspace}'
        and event='workspace.residency_active_route_published' and target='${handoffId}';`),'1')
      await sourceOwnerContext.close()
      sourceSql(`update sectalk_private.st_v8_residency_source_pauses set ends_at=clock_timestamp()-interval '1 second'
          where workspace='${workspace}';
        update sectalk_private.st_v8_residency_history_links set expires_at=clock_timestamp()-interval '1 second' where workspace='${workspace}';
        update sectalk_private.st_v8_residency_activation_admissions set expires_at=clock_timestamp()-interval '1 second' where workspace='${workspace}';`)
      const stranger=await account('route_stranger')
      const strangerSession=data(await stranger.client.auth.getSession()).session
      assert.equal((await fetch(routeUrl)).status,401)
      assert.equal((await fetch(routeUrl,bearer(strangerSession.access_token))).status,404)
      assert.equal((await verifiedOwner.rpc('st_v2_post',{p_channel:general(sourceSql),p_id:randomUUID(),p_body:'Still held source'})).error?.code,'PT423')
      const memberRoute=await fetch(routeUrl,memberRequest)
      assert.equal(memberRoute.status,200,await memberRoute.clone().text())
      assert.deepEqual(await memberRoute.json(),{url:targetUrl})
      assert.match(memberRoute.headers.get('cache-control'),/no-store/)
      assert.equal(memberRoute.headers.get('referrer-policy'),'no-referrer')
      const memberContext=await browser.newContext({storageState:{cookies:[],origins:[
        {origin:sourceOrigin,localStorage:[{name:'sb-127-auth-token',value:JSON.stringify(data(await sourceMember.client.auth.getSession()).session)}]},
        {origin:targetApp,localStorage:[{name:'sb-127-auth-token',value:JSON.stringify(data(await targetMember.client.auth.getSession()).session)}]},
      ]}})
      const memberRoutePage=await memberContext.newPage()
      await memberRoutePage.goto(sourceOrigin+'/?workspace='+workspace)
      await memberRoutePage.getByRole('button',{name:'Open the active workspace',exact:true}).click()
      await memberRoutePage.waitForURL(targetUrl)
      await memberRoutePage.getByRole('group',{name:'Workspace sections'}).getByRole('button',{name:'Board',exact:true}).click()
      await memberRoutePage.getByText('Selected synthetic task 1',{exact:true}).waitFor()
      await memberContext.close()
      // Simulate a membership change applied by the isolated fixture while normal source writes are held.
      sourceSql(`begin; set local session_replication_role=replica;
        update public.st_v2_members set suspended_at=clock_timestamp() where workspace_id='${workspace}' and user_id='${sourceMember.id}'; commit;`)
      assert.equal((await fetch(routeUrl,memberRequest)).status,404)
      sourceSql(`begin; set local session_replication_role=replica;
        update public.st_v2_members set suspended_at=null where workspace_id='${workspace}' and user_id='${sourceMember.id}'; commit;`)
      sourceSql(`update sectalk_private.st_v8_residency_cells set retired_at=clock_timestamp() where id='${cell}';`)
      assert.equal((await fetch(routeUrl,memberRequest)).status,404)
      console.log('Edge verified activation-proof publication, durable member navigation after expiry, one idempotent event and retired-cell denial.')
      if(checkRollbackHold){
        const retirement=(client,p_action='status')=>client.rpc('st_v8_residency_retire_destination',{
          p_workspace:workspace,p_action,p_confirmation:workspace,
        })
        if(checkDestinationRetirement){
          assert.equal(data(await retirement(verifiedDestination)).state,'inactive')
          assert.equal((await retirement(verifiedDestination,'issue')).error?.code,'42501')
        }
        const manifestAction=(client,p_action='status',p_packet)=>client.rpc('st_v8_residency_rollback_manifest',{
          p_workspace:workspace,p_action,p_confirmation:workspace,p_packet,
        })
        let rollbackPacket,rollbackPacketBytes,recoverySigner,boardPacket,boardPacketBytes,channelPacket,channelPacketBytes,rollbackFileCopy
        const channelAction=(client,p_action='status',p_packet)=>client.rpc('st_v8_residency_rollback_channels',{
          p_workspace:workspace,p_action,p_confirmation:workspace,p_packet,
        })
        const recoveryAuthor=async (member,origin,chat=false)=>{
          const context=await browser.newContext({storageState:{cookies:[],origins:[{origin,
            localStorage:[{name:'sb-127-auth-token',value:JSON.stringify(data(await member.client.auth.getSession()).session)}],
          }]}})
          const authorPage=await context.newPage()
          await authorPage.goto(new URL('/?workspace='+workspace,origin).href)
          const panel=authorPage.getByRole('region',{name:chat?'My chat message recovery':'My Board task recovery',exact:true})
          const choose=async (button,expected)=>{
            await panel.getByLabel(chat?'Confirm my chat recovery workspace ID':'Confirm my Board recovery workspace ID').fill(workspace)
            await panel.getByRole('button',{name:button,exact:true}).click()
            await panel.getByRole('button',{name:expected,exact:true}).waitFor()
          }
          return {context,choose}
        }
        const boardAction=(client,p_action='status',p_packet)=>client.rpc('st_v8_residency_rollback_board_replay',{
          p_workspace:workspace,p_action,p_confirmation:workspace,p_packet,
        })
        const rollback=(client,p_action,p_confirmation=workspace,p_approval=approval)=>client.rpc('st_v8_residency_rollback_hold',{
          p_workspace:workspace,p_action,p_approval,p_confirmation,
        })
        const memberLink=async()=>{
          try{return await fetch(routeUrl,memberRequest)}
          catch(error){
            if(error.cause?.code!=='ECONNRESET')throw error
            // The local dev proxy occasionally closes an idle connection during a fixture SQL operation.
            return await fetch(routeUrl,memberRequest)
          }
        }
        sourceSql(`update sectalk_private.st_v8_residency_cells set retired_at=null where id='${cell}';`)
        assert.equal((await memberLink()).status,200)
        assert.equal((await rollback(verifiedOwner,'hold_destination')).error?.code,'42501')
        assert.equal((await rollback(verifiedDestination,'suspend_source_route')).error?.code,'42501')
        assert.equal((await rollback(verifiedDestination,'hold_destination',workspace,randomUUID())).error?.code,'42501')
        assert.equal((await rollback(verifiedTargetMember,'hold_destination')).error?.code,'42501')
        assert.equal((await rollback(verifiedDestination,'hold_destination','wrong workspace')).error?.code,'42501')
        targetSql(`update sectalk_private.st_v8_residency_history_links set expires_at=clock_timestamp()-interval '1 second' where workspace='${workspace}';
          update sectalk_private.st_v8_residency_activation_admissions set expires_at=clock_timestamp()-interval '1 second' where workspace='${workspace}';`)
        await page.reload()
        const targetReview=page.getByRole('region',{name:'Residency rollback preparation',exact:true})
        await targetReview.getByLabel('Confirm rollback workspace ID').fill(workspace)
        await targetReview.getByRole('button',{name:'Hold guarded destination writes',exact:true}).click()
        await targetReview.getByText('Guarded destination writes are held for rollback review.',{exact:true}).waitFor()
        assert.equal((await verifiedDestination.rpc('st_v2_post',{p_channel:general(targetSql),p_id:randomUUID(),p_body:'New write after rollback hold'})).error?.code,'PT423')
        const retained=data(await verifiedDestination.from('st_v2_posts').select('body').eq('channel_id',general(targetSql)))
        assert.ok(retained.some(post=>post.body==='Activated destination'))
        assert.equal((await routing(verifiedDestination,'issue')).error?.code,'PT409')
        assert.equal(data(await rollback(verifiedDestination,'hold_destination')).state,'held')
        assert.equal(targetSql(`select count(*) from public.st_v2_workspace_audit where workspace_id='${workspace}'
          and event='workspace.residency_rollback_destination_held' and target='${handoffId}';`),'1')

        if(checkRollbackReview){
          const review=(client,p_action='status',candidate)=>client.rpc('st_v8_residency_rollback_reconcile',{
            p_workspace:workspace,p_action,p_confirmation:workspace,p_review:candidate?.id,p_digest:candidate?.digest,
          })
          assert.equal((await review(verifiedTargetMember)).error?.code,'42501')
          assert.equal((await review(verifiedForeign,'capture')).error?.code,'42501')
          const panel=page.getByRole('region',{name:'Destination rollback change review',exact:true})
          if(checkRollbackManifest){
            recoverySigner=randomBytes(32)
            for(const database of [sourceSql,targetSql]) database(`
              insert into sectalk_private.st_v8_residency_rollback_manifest_admissions
                values('${handoffId}',vault.create_secret('${recoverySigner.toString('hex')}',null,'Disposable recovery manifest fixture'),
                  '${'9'.repeat(64)}',clock_timestamp()+interval '10 minutes');`)
            assert.equal((await manifestAction(verifiedDestination,'issue')).error?.code,'PT409')
          }
          const capture=async()=>{
            await panel.getByLabel('Confirm change review workspace ID').fill(workspace)
            await panel.getByRole('button',{name:'Capture destination changes',exact:true}).click()
            await panel.getByText('Awaiting independent review.',{exact:true}).waitFor()
            return data(await review(verifiedDestination))
          }
          const first=await capture()
          assert.equal(first.state,'pending')
          if(checkDestinationRetirement){
            assert.equal(data(await retirement(verifiedDestination)).state,'review_required')
            assert.equal((await retirement(verifiedDestination,'issue')).error?.code,'PT409')
          }
          assert.ok(first.changes.some(item=>item.kind==='channel_message'&&item.id===acceptedDestinationPost&&item.state==='added'))
          const changedTask=first.changes.find(item=>item.kind==='workspace_task'&&item.id===updatedTargetTask)
          assert.ok(changedTask?.state==='changed'&&changedTask.before!==changedTask.after)
          assert.ok(!JSON.stringify(first).includes('Activated destination')&&!JSON.stringify(first).includes('Selected synthetic task'))
          assert.equal((await review(verifiedDestination,'confirm',first)).error?.code,'42501')
          assert.equal((await review(verifiedForeign,'confirm',{...first,digest:'0'.repeat(64)})).error?.code,'42501')
          if(checkSourceSignoff){
            // Removing the disposable extra post invalidates the first review and leaves a recoverable manifest.
            targetSql(`delete from public.st_v2_posts where id='${acceptedDestinationPost}' and channel_id='${general(targetSql)}';`)
          }else targetSql(`update storage.objects set metadata=coalesce(metadata,'{}'::jsonb)||'{"fixtureDrift":true}'::jsonb
            where bucket_id='sectalk-workspace-files' and name='${workspace}/${fileId}';`)
          assert.equal((await review(verifiedForeign,'confirm',first)).error?.code,'PT409')
          await panel.getByRole('button',{name:'Refresh change review',exact:true}).click()
          await panel.getByText('The evidence or reviewer access changed. Capture a new review.',{exact:true}).waitFor()
          const second=await capture()
          assert.notEqual(second.id,first.id)
          assert.notEqual(second.digest,first.digest)
          if(!checkSourceSignoff)assert.ok(second.changes.some(item=>item.kind==='storage_object'&&item.state==='changed'))
          const reviewContext=await browser.newContext({storageState:{cookies:[],origins:[{origin:targetApp,
            localStorage:[{name:'sb-127-auth-token',value:JSON.stringify(data(await foreignOwner.client.auth.getSession()).session)}],
          }]}})
          const reviewerPage=await reviewContext.newPage()
          await reviewerPage.goto(new URL('/?workspace='+workspace,targetApp).href)
          const independentPanel=reviewerPage.getByRole('region',{name:'Destination rollback change review',exact:true})
          await independentPanel.getByText(second.digest,{exact:true}).waitFor()
          await independentPanel.getByText('View record revisions',{exact:true}).click()
          await independentPanel.getByText(checkSourceSignoff?recoveredChannel:acceptedDestinationPost,{exact:true}).waitFor()
          await independentPanel.getByLabel('Confirm change review workspace ID').fill(workspace)
          await independentPanel.getByRole('button',{name:'Confirm independent change review',exact:true}).click()
          await independentPanel.getByText('The independent review is current. Workspace writes remain held.',{exact:true}).waitFor()
          assert.equal(data(await review(verifiedForeign,'confirm',second)).state,'reviewed')
          assert.equal(targetSql(`select count(*) from public.st_v2_workspace_audit where workspace_id='${workspace}'
            and event='workspace.residency_rollback_review_confirmed' and target='${second.id}';`),'1')
          await reviewContext.close()
          if(checkRollbackFileCopy){
            const getCopy=(token,file,reviewId=second.id)=>fetch(targetApp+'/api/workspace-files?'+
              new URLSearchParams({workspace,file,'residency-rollback':reviewId}),{headers:{Authorization:'Bearer '+token}})
            const session=destinationProof.session.access_token
            assert.equal((await getCopy(foreignProof.session.access_token,rollbackFile.id)).status,404)
            assert.equal((await getCopy(session,rollbackFile.id,first.id)).status,404)
            assert.equal((await getCopy(session,fileId)).status,404)
            assert.equal((await verifiedDestination.rpc('st_v8_residency_rollback_file_copy',{
              p_workspace:workspace,p_review:second.id,p_file:rollbackFile.id,p_sha256:'0'.repeat(64),
            })).error?.code,'42501')
            await panel.getByRole('button',{name:'Refresh change review',exact:true}).click()
            await panel.getByText('The independent review is current. Workspace writes remain held.',{exact:true}).waitFor()
            await panel.getByText('View record revisions',{exact:true}).click()
            const download=page.waitForEvent('download')
            await panel.getByRole('listitem').filter({hasText:rollbackFile.id}).getByRole('button',{name:'Download reviewed file copy',exact:true}).click()
            const browserFile=await download
            assert.equal(browserFile.suggestedFilename(),'sectalk-file-recovery-'+rollbackFile.id+'.json')
            const copy=JSON.parse(await readFile(await browserFile.path(),'utf8'))
            rollbackFileCopy=copy
            assert.equal(copy.format,'sectalk-residency-file-copy-v1')
            assert.equal(copy.proof.signature,createHmac('sha256',recoverySigner).update(copy.proof.payload).digest('hex'))
            assert.deepEqual(Buffer.from(copy.contentBase64,'base64'),rollbackFile.bytes)
            const fileProof=JSON.parse(copy.proof.payload)
            assert.equal(fileProof.review,second.id)
            assert.equal(fileProof.file,rollbackFile.id)
            assert.equal(fileProof.ownerTag,createHmac('sha256',recoverySigner)
              .update('sectalk-file-replay-owner-v1:'+handoffId+':'+matchingOwnerEmail).digest('hex'))
            assert(!copy.proof.payload.includes(matchingOwnerEmail))
            assert.equal(fileProof.fileRevision,second.changes.find(change=>change.id===rollbackFile.id).after)
            assert.equal(fileProof.objectRevision,second.changes.find(change=>change.id===fileProof.object).after)
            assert.equal(fileProof.sha256,createHash('sha256').update(rollbackFile.bytes).digest('hex'))
            console.log('Edge downloaded the exact newly added workspace file bound to both independently reviewed native revisions.')
          }
          console.log('Edge and native roles reconciled exact post-activation post, task and Storage revisions, rejected stale evidence, and retained one independent receipt.')
          if(checkRollbackManifest){
            assert.equal((await manifestAction(verifiedForeign,'issue')).error?.code,'42501')
            const manifestPanel=page.getByRole('region',{name:'Rollback recovery manifest',exact:true})
            await manifestPanel.getByRole('button',{name:'Refresh manifest status',exact:true}).click()
            await manifestPanel.getByLabel('Confirm recovery manifest workspace ID').fill(workspace)
            const download=page.waitForEvent('download')
            await manifestPanel.getByRole('button',{name:'Download recovery manifest',exact:true}).click()
            const artifact=await download
            assert.equal(artifact.suggestedFilename(),'sectalk-rollback-manifest-'+workspace+'.json')
            rollbackPacketBytes=await readFile(await artifact.path())
            rollbackPacket=JSON.parse(rollbackPacketBytes.toString('utf8'))
            const manifestRecord=JSON.parse(rollbackPacket.payload)
            assert.equal(manifestRecord.digest,second.digest)
            assert.equal(manifestRecord.review,second.id)
            assert.deepEqual(manifestRecord.changes,second.changes)
            assert.ok(!rollbackPacket.payload.includes('Activated destination')&&!rollbackPacket.payload.includes('Selected synthetic task'))
            assert.equal((await manifestAction(verifiedOwner,'receive',rollbackPacket)).error?.code,'42501')
            if(checkDestinationRetirement){
              assert.equal((await retirement(verifiedForeign,'issue')).error?.code,'42501')
              assert.equal(data(await retirement(verifiedOwner)).state,'inactive')
              const retiring=manifestPanel.getByRole('region',{name:'Destination retirement',exact:true})
              await retiring.getByLabel('Confirm destination retirement workspace ID').fill(workspace)
              const download=page.waitForEvent('download')
              await retiring.getByRole('button',{name:'Retire destination and download proof',exact:true}).click()
              const file=await download
              assert.equal(file.suggestedFilename(),'sectalk-retired-destination-'+workspace+'.json')
              const packet=JSON.parse(await readFile(await file.path(),'utf8'))
              const proof=JSON.parse(packet.payload)
              assert.equal(packet.signature,createHmac('sha256',recoverySigner).update(packet.payload).digest('hex'))
              assert.deepEqual({...proof,expires:undefined,receipt:undefined},{format:'sectalk-residency-retired-destination-v1',
                workspace,handoff:handoffId,approval,source:sourceProject,destination:destinationProject,
                review:manifestRecord.review,digest:manifestRecord.digest,plan:manifestRecord.plan,expires:undefined,receipt:undefined})
              await retiring.getByText(proof.receipt,{exact:true}).waitFor()
              const renewal=data(await retirement(verifiedDestination,'issue'))
              assert.equal(renewal.receipt,proof.receipt)
              assert.equal((await verifiedDestination.rpc('st_v2_post',{
                p_channel:general(targetSql),p_id:randomUUID(),p_body:'Retired destination stays held',
              })).error?.code,'PT423')
              assert.equal(targetSql(`begin;
                delete from sectalk_private.st_v8_residency_rollback_holds where workspace='${workspace}';
                select sectalk_private.st_v7_workspace_payment_mode('${workspace}')->>'mode'; rollback;`),'read_only')
              assert.equal(targetSql(`select count(*) from public.st_v2_workspace_audit
                where workspace_id='${workspace}' and event='workspace.residency_rollback_destination_retired' and target='${proof.receipt}';`),'1')
              console.log('Edge retired the reviewed destination and downloaded its signed receipt. Native writes stayed held.')
            }
            if(checkChannelReplay){
              if(checkMemberChannelReplay){
                const boardConsent=p_action=>verifiedTargetMember.rpc('st_v8_residency_board_author_consent',{
                  p_workspace:workspace,p_action,p_confirmation:workspace,
                })
                assert.equal(data(await boardConsent('approve')),'approved')
                const boardOnly=data(await channelAction(verifiedDestination,'issue')).packet
                assert.ok(!JSON.parse(boardOnly.payload).records.some(item=>item.id===otherSenderPost))
                assert.equal(data(await boardConsent('revoke')),'ready')
                const chatAuthor=await recoveryAuthor(targetMember,targetApp,true)
                await chatAuthor.choose('Approve my chat recovery','Withdraw my chat recovery approval')
                await chatAuthor.context.close()
              }
              const channelPanel=page.getByRole('region',{name:'Standard channel rollback replay',exact:true})
              await channelPanel.getByRole('button',{name:'Refresh channel replay',exact:true}).click()
              await channelPanel.getByLabel('Confirm channel recovery workspace ID').fill(workspace)
              const download=page.waitForEvent('download')
              await channelPanel.getByRole('button',{name:'Download channel recovery file',exact:true}).click()
              channelPacketBytes=await readFile(await (await download).path())
              channelPacket=JSON.parse(channelPacketBytes.toString('utf8'))
              const records=JSON.parse(channelPacket.payload).records
              const expected=checkMemberChannelReplay?[recoveredChannel,recoveredPost,otherSenderPost]:[recoveredChannel,recoveredPost]
              if(checkExistingChannelReplay){
                expected.push(existingChannelPost)
                assert.equal(records.find(item=>item.id===existingChannelPost)?.existingChannelName,existingChannelName)
                assert(!records.some(item=>item.id===channel))
              }
              assert.deepEqual(records.map(item=>item.id).sort(),expected.sort())
              assert(!records.some(item=>item.id===acceptedDestinationPost))
              assert.ok(!channelPacket.payload.includes(reportedPost))
              if(checkMemberChannelReplay)assert.equal(records.find(item=>item.id===otherSenderPost).destinationAuthor,targetMember.id)
              else assert.ok(!channelPacket.payload.includes(otherSenderPost))
            }
            if(checkBoardReplay){
              if(checkMemberBoardReplay){
                const consentless=data(await boardAction(verifiedDestination,'issue')).packet
                assert.ok(!JSON.parse(consentless.payload).tasks.some(task=>task.id===nonOwnerTask))
                const author=await recoveryAuthor(targetMember,targetApp)
                await author.choose('Approve my task recovery','Withdraw my task recovery approval')
                await author.context.close()
              }
              const boardPanel=page.getByRole('region',{name:'Board task rollback replay',exact:true})
              await boardPanel.getByRole('button',{name:'Refresh Board replay',exact:true}).click()
              await boardPanel.getByLabel('Confirm Board recovery workspace ID').fill(workspace)
              const download=page.waitForEvent('download')
              await boardPanel.getByRole('button',{name:'Download Board recovery file',exact:true}).click()
              boardPacketBytes=await readFile(await (await download).path())
              boardPacket=JSON.parse(boardPacketBytes.toString('utf8'))
              const tasks=JSON.parse(boardPacket.payload).tasks
              assert.deepEqual(tasks.filter(task=>task.kind!=='added').map(task=>task.id),replayTaskIds)
              assert.ok(tasks.filter(task=>task.kind!=='added').every(task=>task.completed===true))
              assert.ok(!boardPacket.payload.includes('Selected synthetic task'))
              if(checkBoardAdditions){
                assert.deepEqual(tasks.filter(task=>task.kind==='added').map(task=>task.id),
                  checkMemberBoardReplay?[addedTask,nonOwnerTask]:[addedTask])
                assert.ok(!boardPacket.payload.includes(matchingOwnerEmail))
                if(checkMemberBoardReplay){
                  assert.equal(tasks.find(task=>task.id===nonOwnerTask).destinationAuthor,targetMember.id)
                  assert.match(tasks.find(task=>task.id===nonOwnerTask).authorTag,/^[0-9a-f]{64}$/)
                }else assert.ok(!boardPacket.payload.includes(nonOwnerTask))
              }
            }
          }
        }

        const rollbackContext=await browser.newContext({storageState:{cookies:[],origins:[{origin:sourceOrigin,
          localStorage:[{name:'sb-127-auth-token',value:JSON.stringify(session)}],
        }]}})
        const sourceReviewPage=await rollbackContext.newPage()
        await sourceReviewPage.goto(sourceOrigin+'/?workspace='+workspace)
        const sourceReview=sourceReviewPage.getByRole('region',{name:'Residency rollback preparation',exact:true})
        await sourceReview.getByLabel('Confirm rollback workspace ID').fill(workspace)
        await sourceReview.getByRole('button',{name:'Suspend destination member link',exact:true}).click()
        await sourceReview.getByText('Member routing is suspended. Guarded source writes remain held.',{exact:true}).waitFor()
        if(checkRollbackManifest){
          const sourceManifest=sourceReviewPage.getByRole('region',{name:'Rollback recovery manifest',exact:true})
          assert.equal((await manifestAction(verifiedOwner,'receive',{...rollbackPacket,payload:rollbackPacket.payload+' '})).error?.code,'42501')
          const expiredWire=JSON.stringify({...JSON.parse(rollbackPacket.payload),expires:Math.floor(Date.now()/1000)-60})
          assert.equal((await manifestAction(verifiedOwner,'receive',{payload:expiredWire,
            signature:createHmac('sha256',recoverySigner).update(expiredWire).digest('hex'),
          })).error?.code,'42501')
          sourceSql(`update sectalk_private.st_v8_residency_rollback_manifest_admissions set plan_sha256='${'8'.repeat(64)}' where handoff='${handoffId}';`)
          assert.equal((await manifestAction(verifiedOwner,'receive',rollbackPacket)).error?.code,'42501')
          sourceSql(`update sectalk_private.st_v8_residency_rollback_manifest_admissions set plan_sha256='${'9'.repeat(64)}' where handoff='${handoffId}';`)
          await sourceManifest.getByLabel('Confirm recovery manifest workspace ID').fill(workspace)
          await sourceManifest.getByLabel('Signed manifest file').setInputFiles({
            name:'reviewed.json',mimeType:'application/json',buffer:rollbackPacketBytes,
          })
          await sourceManifest.getByRole('button',{name:'Verify recovery manifest',exact:true}).click()
          await sourceManifest.getByText('The source verified the recovery manifest. Workspace writes remain held.',{exact:true}).waitFor()
          const recorded=data(await manifestAction(verifiedOwner,'receive',rollbackPacket))
          assert.equal(recorded.digest,JSON.parse(rollbackPacket.payload).digest)
          assert.equal(recorded.changeCount,JSON.parse(rollbackPacket.payload).changes.length)
          assert.equal((await manifestAction(verifiedOwner,'receive',{...rollbackPacket,signature:'0'.repeat(64)})).error?.code,'PT409')
          assert.equal(sourceSql(`select count(*) from public.st_v2_workspace_audit where workspace_id='${workspace}'
            and event='workspace.residency_rollback_manifest_received' and target='${handoffId}';`),'1')
          console.log('Edge transferred a signed recovery manifest and the held source rejected tampering, expiry, and mismatched plans before one durable receipt.')
          if(checkRollbackFileCopy){
            const fileBytes=Buffer.from(rollbackFileCopy.contentBase64,'base64')
            const sha256=createHash('sha256').update(fileBytes).digest('hex')
            const proof=rollbackFileCopy.proof
            const claim=JSON.parse(proof.payload)
            const admit=(client,overrides={})=>client.rpc('st_v8_residency_source_file_admission',{
              p_workspace:workspace,p_file:rollbackFile.id,p_proof:proof,p_sha256:sha256,p_bytes:fileBytes.length,...overrides,
            })
            const sign=changes=>{
              const payload=JSON.stringify({...claim,...changes})
              return {payload,signature:createHmac('sha256',recoverySigner).update(payload).digest('hex')}
            }
            assert.equal((await admit(proofClient(sourceMemberProof))).error?.code,'42501')
            assert.equal((await admit(verifiedOwner,{p_sha256:'0'.repeat(64)})).error?.code,'42501')
            assert.equal((await admit(verifiedOwner,{p_bytes:fileBytes.length+1})).error?.code,'42501')
            assert.equal((await admit(verifiedOwner,{p_proof:{...proof,payload:proof.payload+' '}})).error?.code,'42501')
            assert.equal((await admit(verifiedOwner,{p_proof:sign({objectRevision:'0'.repeat(64)})})).error?.code,'42501')
            assert.equal((await admit(verifiedOwner,{p_proof:sign({ownerTag:'0'.repeat(64)})})).error?.code,'42501')
            assert.equal((await admit(verifiedOwner,{p_proof:sign({expires:claim.expires-600})})).error?.code,'42501')
            const result=data(await admit(verifiedOwner))
            assert.deepEqual({...result,proofSha256:undefined},{state:'proof_verified',handoff:handoffId,
              file:rollbackFile.id,filename:rollbackFile.name,sha256,bytes:fileBytes.length,review:claim.review,proofSha256:undefined})
            assert.match(result.proofSha256,/^[0-9a-f]{64}$/)
            assert.equal(sourceSql(`select count(*) from sectalk_private.st_v6_workspace_files where (workspace,id)=('${workspace}','${rollbackFile.id}');`),'0')
            assert.equal(sourceSql(`select count(*) from storage.objects where (bucket_id,name)=('sectalk-workspace-files','${workspace}/${rollbackFile.id}');`),'0')
            console.log('The held source verified the signed file proof and exact browser-computed hash without publishing a file.')

            assert.equal((await verifiedOwner.rpc('st_v8_residency_source_file_stage',{
              p_workspace:workspace,p_file:rollbackFile.id,p_proof:proof,p_sha256:sha256,p_bytes:fileBytes.length,
            })).error?.code,'42501')
            const stage=(token,bytes)=>fetch(sourceApp+'/api/workspace-files?'+new URLSearchParams({
              workspace,file:rollbackFile.id,'residency-rollback-stage':'1',
            }),{method:'POST',body:bytes,headers:{Authorization:'Bearer '+token,'Content-Type':'application/octet-stream',
              'X-SecTalk-Rollback-File-Proof':Buffer.from(JSON.stringify(proof)).toString('base64url'),
            }})
            assert.equal((await stage(sourceMemberProof.session.access_token,fileBytes)).status,404)
            assert.equal((await stage(ownerProof.session.access_token,Buffer.from('Wrong bytes'))).status,404)
            rollbackStagingPath=[workspace,handoffId,rollbackFile.id,sha256].join('/')
            await sourceManifest.getByLabel('Signed recovery file',{exact:true}).setInputFiles({
              name:'reviewed-file.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(rollbackFileCopy)),
            })
            const stagedResponse=sourceReviewPage.waitForResponse(response=>response.url().includes('residency-rollback-stage=1'))
            await sourceManifest.getByRole('button',{name:'Stage reviewed file copy',exact:true}).click()
            const staged=await stagedResponse
            assert.equal(staged.status(),200,await staged.text())
            await sourceManifest.getByText(/was staged in private storage/).waitFor()
            const retries=await Promise.all([stage(ownerProof.session.access_token,fileBytes),stage(ownerProof.session.access_token,fileBytes)])
            const receipt=await staged.json()
            for(const retry of retries){
              assert.equal(retry.status,200,await retry.clone().text())
              assert.deepEqual(await retry.json(),receipt)
            }
            const stagedFiles=source.storage.from('sectalk-residency-recovery')
            const stored=data(await stagedFiles.download(rollbackStagingPath))
            assert.deepEqual(Buffer.from(await stored.arrayBuffer()),fileBytes)
            assert.ok((await verifiedOwner.storage.from('sectalk-residency-recovery').download(rollbackStagingPath)).error)
            assert.equal(sourceSql(`select count(*) from sectalk_private.st_v8_residency_source_file_copies where (handoff,file)=('${handoffId}','${rollbackFile.id}');`),'1')
            assert.equal(sourceSql(`select count(*) from public.st_v2_workspace_audit where workspace_id='${workspace}' and event='workspace.residency_file_replay_staged' and target='${rollbackFile.id}';`),'1')
            assert.equal(sourceSql(`select count(*) from sectalk_private.st_v6_workspace_files where (workspace,id)=('${workspace}','${rollbackFile.id}');`),'0')
            assert.equal(sourceSql(`select count(*) from storage.objects where (bucket_id,name)=('sectalk-workspace-files','${workspace}/${rollbackFile.id}');`),'0')
            console.log('Edge staged a reviewed file in private recovery Storage. Exact retries retained one receipt and the live workspace remained held.')
            const fileReview=(client,options={})=>client.rpc('st_v8_residency_source_file_review',{p_workspace:workspace,...options})
            const fileRow=data(await fileReview(verifiedOwner)).files[0]
            assert.equal(fileRow.state,'staged')
            assert.equal(fileRow.file,rollbackFile.id)
            assert.equal(fileRow.sha256,sha256)
            assert.equal(fileRow.bytes,fileBytes.length)
            const decision={p_file:rollbackFile.id,p_confirmation:workspace,p_digest:fileRow.digest}
            const restore=(token,digest=fileRow.digest)=>fetch(sourceApp+'/api/workspace-files?'+new URLSearchParams({
              workspace,file:rollbackFile.id,'residency-rollback-restore':digest,
            }),{method:'POST',headers:{Authorization:'Bearer '+token}})
            const restoreArgs={p_workspace:workspace,p_file:rollbackFile.id,p_digest:fileRow.digest}
            assert.equal((await restore(ownerProof.session.access_token)).status,409)
            assert.equal((await fileReview(verifiedOwner,decision)).error?.code,'42501')
            assert.equal((await fileReview(proofClient(sourceMemberProof))).error?.code,'42501')
            assert.equal((await fileReview(verifiedReviewer,{...decision,p_digest:'0'.repeat(64)})).error?.code,'PT409')
            const fileReviewerContext=await browser.newContext({storageState:{cookies:[],origins:[{origin:sourceOrigin,
              localStorage:[{name:'sb-127-auth-token',value:JSON.stringify(reviewerProof.session)}],
            }]}})
            try {
              const fileReviewerPage=await fileReviewerContext.newPage()
              await fileReviewerPage.goto(sourceOrigin+'/?workspace='+workspace)
              const stagedPanel=fileReviewerPage.getByRole('region',{name:'Staged rollback files',exact:true})
              await stagedPanel.getByText(sha256,{exact:true}).waitFor()
              await stagedPanel.getByLabel('Confirm staged file workspace ID').fill(workspace)
              await stagedPanel.getByRole('button',{name:'Approve staged file',exact:true}).click()
              await stagedPanel.getByText('Approved for restoration',{exact:true}).waitFor()
            } finally { await fileReviewerContext.close() }
            assert.equal(data(await fileReview(verifiedReviewer,decision)).files[0].state,'approved')
            assert.equal(data(await fileReview(verifiedOwner)).files[0].state,'approved')
            assert.equal(sourceSql(`select count(*) from public.st_v2_workspace_audit where workspace_id='${workspace}' and event='workspace.residency_file_replay_approved' and target='${rollbackFile.id}';`),'1')
            const stagedObjectFilter=`where (bucket_id,name)=('sectalk-residency-recovery','${rollbackStagingPath}')`
            sourceSql(`update storage.objects set metadata=jsonb_set(metadata,'{size}',to_jsonb(${fileBytes.length+1})) ${stagedObjectFilter};`)
            try {
              assert.equal(data(await fileReview(verifiedReviewer)).files[0].state,'changed')
              assert.equal((await fileReview(verifiedReviewer,decision)).error?.code,'PT409')
            } finally {
              sourceSql(`update storage.objects set metadata=jsonb_set(metadata,'{size}',to_jsonb(${fileBytes.length})) ${stagedObjectFilter};`)
            }
            assert.equal(sourceSql(`select count(*) from sectalk_private.st_v6_workspace_files where (workspace,id)=('${workspace}','${rollbackFile.id}');`),'0')
            console.log('Edge approved the exact private receipt as independent reviewer; stale evidence and native object drift were denied while the source stayed held.')
            assert.equal((await restore(reviewerProof.session.access_token)).status,404)
            assert.equal((await restore(ownerProof.session.access_token,'0'.repeat(64))).status,409)
            assert.equal((await verifiedOwner.rpc('st_v8_residency_source_file_restore',{...restoreArgs,p_action:'publish'})).error?.code,'PT409')
            const livePath=workspace+'/'+rollbackFile.id
            const liveBucket=source.storage.from('sectalk-workspace-files')
            data(await liveBucket.upload(livePath,Buffer.alloc(fileBytes.length,32),{contentType:'application/octet-stream'}))
            try {
              assert.equal((await restore(ownerProof.session.access_token)).status,409)
              assert.equal(sourceSql(`select count(*) from sectalk_private.st_v6_workspace_files where (workspace,id)=('${workspace}','${rollbackFile.id}');`),'0')
            } finally { data(await liveBucket.remove([livePath])) }
            const ownerPanel=sourceReviewPage.getByRole('region',{name:'Source rollback verification',exact:true})
            await ownerPanel.getByRole('button',{name:'Refresh source verification',exact:true}).click()
            const ownerStaged=ownerPanel.getByRole('region',{name:'Staged rollback files',exact:true})
            await ownerStaged.getByText('Approved for restoration',{exact:true}).waitFor()
            await ownerStaged.getByLabel('Confirm staged file workspace ID').fill(workspace)
            const restorationResponse=sourceReviewPage.waitForResponse(response=>response.url().includes('residency-rollback-restore='))
            await ownerStaged.getByRole('button',{name:'Restore approved file',exact:true}).click()
            const restored=await restorationResponse
            assert.equal(restored.status(),200,await restored.text())
            await ownerStaged.getByText('Restored to workspace Files',{exact:true}).waitFor()
            const retryRestore=await restore(ownerProof.session.access_token)
            assert.equal(retryRestore.status,200,await retryRestore.clone().text())
            assert.deepEqual(await retryRestore.json(),await restored.json())
            assert.equal(data(await fileReview(verifiedReviewer)).files[0].state,'restored')
            assert.equal(sourceSql(`select count(*) from sectalk_private.st_v8_residency_file_write_permits;`),'0')
            assert.equal(sourceSql(`select count(*) from public.st_v2_workspace_audit where workspace_id='${workspace}' and event='workspace.residency_file_replay_restored' and target='${rollbackFile.id}';`),'1')
            await sourceReviewPage.getByRole('group',{name:'Workspace sections'}).getByRole('button',{name:'Files',exact:true}).click()
            const fileCard=sourceReviewPage.getByRole('article').filter({has:sourceReviewPage.getByRole('heading',{name:rollbackFile.name,exact:true})})
            await fileCard.waitFor()
            const downloaded=sourceReviewPage.waitForEvent('download')
            await fileCard.getByRole('button',{name:'Download file',exact:true}).click()
            assert.deepEqual(await readFile(await (await downloaded).path()),fileBytes)
            await sourceReviewPage.getByRole('group',{name:'Workspace sections'}).getByRole('button',{name:'Organization settings',exact:true}).click()
            console.log('Edge restored the independently approved file to normal source Files and downloaded exact bytes while ordinary writes stayed held.')
          }
          let sourceChatAuthor
          if(checkChannelReplay){
            assert.equal((await channelAction(verifiedOwner,'stage',{...channelPacket,payload:channelPacket.payload+' '})).error?.code,'42501')
            if(checkMemberChannelReplay){
              const boardConsent=p_action=>proofClient(sourceMemberProof).rpc('st_v8_residency_board_author_consent',{
                p_workspace:workspace,p_action,p_confirmation:workspace,
              })
              assert.equal(data(await boardConsent('approve')),'approved')
              assert.equal((await channelAction(verifiedOwner,'stage',channelPacket)).error?.code,'42501')
              assert.equal(data(await boardConsent('revoke')),'ready')
              sourceChatAuthor=await recoveryAuthor(sourceMember,sourceOrigin,true)
              await sourceChatAuthor.choose('Approve my chat recovery','Withdraw my chat recovery approval')
            }
            const channelPanel=sourceReviewPage.getByRole('region',{name:'Standard channel rollback replay',exact:true})
            await channelPanel.getByRole('button',{name:'Refresh channel replay',exact:true}).click()
            await channelPanel.getByLabel('Confirm channel recovery workspace ID').fill(workspace)
            await channelPanel.getByLabel('Signed channel recovery file').setInputFiles({
              name:'reviewed-channel.json',mimeType:'application/json',buffer:channelPacketBytes,
            })
            await channelPanel.getByRole('button',{name:'Stage channel recovery file',exact:true}).click()
            await channelPanel.getByText('The original independent source reviewer can apply the staged channels and messages.',{exact:true}).waitFor()
            assert.equal((await channelAction(verifiedOwner,'apply')).error?.code,'42501')
          }
          if(checkBoardReplay){
            const boardPanel=sourceReviewPage.getByRole('region',{name:'Board task rollback replay',exact:true})
            await boardPanel.getByRole('button',{name:'Refresh Board replay',exact:true}).click()
            assert.equal((await boardAction(verifiedOwner,'stage',{...boardPacket,payload:boardPacket.payload+' '})).error?.code,'42501')
            if(checkBoardAdditions){
              const sign=claim=>{
                const payload=JSON.stringify(claim)
                return {payload,signature:createHmac('sha256',recoverySigner).update(payload).digest('hex')}
              }
              const claim=JSON.parse(boardPacket.payload)
              assert.equal((await boardAction(verifiedOwner,'stage',sign({...claim,ownerTag:'0'.repeat(64)}))).error?.code,'42501')
              const changed=structuredClone(claim)
              changed.tasks.find(task=>task.id===addedTask).title='Changed signed task title'
              assert.equal((await boardAction(verifiedOwner,'stage',sign(changed))).error?.code,'42501')
            }
            let sourceAuthor
            if(checkMemberBoardReplay){
              assert.equal((await boardAction(verifiedOwner,'stage',boardPacket)).error?.code,'42501')
              sourceAuthor=await recoveryAuthor(sourceMember,sourceOrigin)
              await sourceAuthor.choose('Approve my task recovery','Withdraw my task recovery approval')
            }
            await boardPanel.getByLabel('Confirm Board recovery workspace ID').fill(workspace)
            await boardPanel.getByLabel('Signed Board recovery file').setInputFiles({
              name:'reviewed-board.json',mimeType:'application/json',buffer:boardPacketBytes,
            })
            await boardPanel.getByRole('button',{name:'Stage Board recovery file',exact:true}).click()
            await boardPanel.getByText('The original independent source reviewer can apply the staged Board task changes.',{exact:true}).waitFor()
            assert.equal((await boardAction(verifiedOwner,'apply')).error?.code,'42501')
            assert.equal((await verifiedOwner.rpc('st_v2_complete_task',{p_item:replayTaskIds[0],p_complete:true})).error?.code,'PT423')
            const taskList=replayTaskIds.map(id=>"'"+id+"'").join(',')
            const completed=()=>sourceSql(`select count(*) from public.st_v2_items where id in (${taskList}) and completed;`)
            if(checkMemberBoardReplay){
              await sourceAuthor.choose('Withdraw my task recovery approval','Approve my task recovery')
              assert.equal((await boardAction(verifiedReviewer,'apply')).error?.code,'PT409')
              assert.equal(completed(),'0')
              assert.equal(sourceSql(`select count(*) from public.st_v2_items where id='${nonOwnerTask}';`),'0')
              await sourceAuthor.choose('Approve my task recovery','Withdraw my task recovery approval')
              await sourceAuthor.context.close()
            }
            const holdId=randomUUID()
            data(await verifiedOwner.rpc('st_v6_place_workspace_hold',{
              p_workspace:workspace,p_id:holdId,p_room:null,p_member:null,p_from:'2026-01-01T00:00:00Z',p_until:null,
              p_reason:'Temporary preservation test for rollback review',
            }))
            assert.equal((await boardAction(verifiedReviewer,'apply')).error?.code,'PT423')
            if(checkChannelReplay)assert.equal((await channelAction(verifiedReviewer,'apply')).error?.code,'PT423')
            data(await verifiedOwner.rpc('st_v6_release_workspace_hold',{
              p_workspace:workspace,p_id:holdId,p_reason:'Disposable rollback test',
            }))
            const oldTitle=sourceSql(`select title from public.st_v2_items where id='${replayTaskIds[1]}';`)
            assert.match(oldTitle,/^Selected synthetic task [12]$/)
            const revise=title=>sourceSql(`begin; set local session_replication_role=replica;
              update public.st_v2_items set title='${title}' where id='${replayTaskIds[1]}'; commit;`)
            revise('Different approved-source title')
            assert.equal((await boardAction(verifiedReviewer,'apply')).error?.code,'PT409')
            assert.equal(completed(),'0')
            revise(oldTitle)
            if(checkBoardAdditions){
              sourceSql(`insert into public.st_v2_items(id,workspace_id,kind,title,created_by)
                values('${addedTask}','${unrelated}','task','Existing unrelated task ID','${outsider.id}');`)
              assert.equal((await boardAction(verifiedReviewer,'apply')).error?.code,'PT409')
              assert.equal(completed(),'0')
              assert.equal(sourceSql(`select title from public.st_v2_items where id='${addedTask}';`),'Existing unrelated task ID')
              sourceSql(`delete from public.st_v2_items where id='${addedTask}' and workspace_id='${unrelated}';`)
            }
            const sourceReviewerContext=await browser.newContext({storageState:{cookies:[],origins:[{origin:sourceOrigin,
              localStorage:[{name:'sb-127-auth-token',value:JSON.stringify(data(await reviewer.client.auth.getSession()).session)}],
            }]}})
            const reviewPage=await sourceReviewerContext.newPage()
            await reviewPage.goto(sourceOrigin+'/?workspace='+workspace)
            if(checkChannelReplay){
              if(checkMemberChannelReplay){
                await sourceChatAuthor.choose('Withdraw my chat recovery approval','Approve my chat recovery')
                assert.equal((await channelAction(verifiedReviewer,'apply')).error?.code,'PT409')
                assert.equal(sourceSql(`select count(*) from public.st_v2_channels where id='${recoveredChannel}';`),'0')
                await sourceChatAuthor.choose('Approve my chat recovery','Withdraw my chat recovery approval')
                await sourceChatAuthor.context.close()
              }
              const unrelatedChannel=sourceSql(`select id from public.st_v2_channels where workspace_id='${unrelated}' and name='general';`)
              sourceSql(`insert into public.st_v2_posts(id,channel_id,sender,body)
                values('${recoveredPost}','${unrelatedChannel}','${outsider.id}','Unrelated occupied message ID');`)
              assert.equal((await channelAction(verifiedReviewer,'apply')).error?.code,'PT409')
              assert.equal(sourceSql(`select count(*) from public.st_v2_channels where id='${recoveredChannel}';`),'0')
              sourceSql(`delete from public.st_v2_posts where id='${recoveredPost}' and sender='${outsider.id}';`)
              if(checkExistingChannelReplay){
                sourceSql(`begin; set local session_replication_role=replica;
                  update public.st_v2_channels set name='changed-source-channel' where id='${channel}' and workspace_id='${workspace}';
                  commit;`)
                assert.equal((await channelAction(verifiedReviewer,'apply')).error?.code,'PT409')
                assert.equal(sourceSql(`select count(*) from public.st_v2_channels where id='${recoveredChannel}';`),'0')
                sourceSql(`begin; set local session_replication_role=replica;
                  update public.st_v2_channels set name='${existingChannelName}' where id='${channel}' and workspace_id='${workspace}';
                  commit;`)
              }
              const channelPanel=reviewPage.getByRole('region',{name:'Standard channel rollback replay',exact:true})
              await channelPanel.getByText('Review the staged channels and messages',{exact:true}).click()
              await channelPanel.getByText('Reviewed recovery chat message',{exact:true}).waitFor()
              if(checkExistingChannelReplay)await channelPanel.getByText(existingChannelName,{exact:true}).waitFor()
              await channelPanel.getByLabel('Confirm channel recovery workspace ID').fill(workspace)
              await channelPanel.getByRole('button',{name:'Apply reviewed channels and messages',exact:true}).click()
              await channelPanel.getByText('Reviewed channels and messages were replayed. Workspace writes remain held.',{exact:true}).waitFor()
              assert.deepEqual(data(await verifiedOwner.from('st_v2_channels').select('id,name,created_at,owner').eq('id',recoveredChannel).single()),
                {...channelRevision,owner:owner.id})
              assert.deepEqual(data(await verifiedOwner.from('st_v2_posts').select('id,channel_id,body,created_at,sender').eq('id',recoveredPost).single()),
                {...postRevision,sender:owner.id})
              if(checkExistingChannelReplay){
                assert.deepEqual(data(await verifiedOwner.from('st_v2_posts').select('id,channel_id,body,created_at,sender')
                  .eq('id',existingChannelPost).single()),{...existingChannelRevision,sender:owner.id})
              }
              assert.deepEqual(data(await verifiedOwner.from('st_v2_posts').select('id').eq('id',reportedPost)),[])
              if(checkMemberChannelReplay){
                assert.deepEqual(data(await verifiedOwner.from('st_v2_posts').select('id,channel_id,body,created_at,sender')
                  .eq('id',otherSenderPost).single()),{...memberPostRevision,sender:sourceMember.id})
              }else assert.deepEqual(data(await verifiedOwner.from('st_v2_posts').select('id').eq('id',otherSenderPost)),[])
              assert.equal(data(await channelAction(verifiedReviewer,'apply')).state,'applied')
              assert.equal(sourceSql(`select count(*) from public.st_v2_workspace_audit where workspace_id='${workspace}'
                and event='workspace.residency_channel_replay_applied' and target='${handoffId}';`),'1')
              await reviewPage.getByRole('group',{name:'Workspace sections'}).getByRole('button',{name:'Channels',exact:true}).click()
              await reviewPage.getByRole('combobox',{name:'Channel',exact:true}).selectOption(recoveredChannel)
              await reviewPage.getByRole('log',{name:'Channel messages',exact:true})
                .getByText('Reviewed recovery chat message',{exact:true}).waitFor()
              if(checkExistingChannelReplay){
                await reviewPage.getByRole('combobox',{name:'Channel',exact:true}).selectOption(channel)
                await reviewPage.getByRole('log',{name:'Channel messages',exact:true})
                  .getByText('Recovery to a previously migrated channel',{exact:true}).waitFor()
                console.log('Edge recovered a new message in its previously migrated standard channel after denying source channel drift.')
                await reviewPage.getByRole('combobox',{name:'Channel',exact:true}).selectOption(recoveredChannel)
              }
              if(checkMemberChannelReplay){
                await reviewPage.getByRole('log',{name:'Channel messages',exact:true})
                  .getByText('Separate author control',{exact:true}).waitFor()
                console.log('Edge verified distinct two-sided chat approval, source withdrawal and exact restored member authorship.')
              }else console.log('Edge verified exact owner-authored new channel and message replay, excluding reports and other authors.')
            }
            const approvedPanel=reviewPage.getByRole('region',{name:'Board task rollback replay',exact:true})
            await approvedPanel.getByText('Review the staged task changes',{exact:true}).click()
            await approvedPanel.getByText(replayTaskIds[0],{exact:true}).waitFor()
            if(checkBoardAdditions)await approvedPanel.getByText('New task · Post-activation recovery task',{exact:true}).waitFor()
            await approvedPanel.getByLabel('Confirm Board recovery workspace ID').fill(workspace)
            await approvedPanel.getByRole('button',{name:'Apply reviewed task changes',exact:true}).click()
            await approvedPanel.getByText('Reviewed Board task changes were replayed. Workspace writes remain held.',{exact:true}).waitFor()
            assert.equal(completed(),'2')
            if(checkBoardAdditions){
              const recovered=data(await verifiedOwner.from('st_v2_items').select('id,title,details,created_at,due_at,completed,created_by')
                .eq('id',addedTask).single())
              assert.deepEqual(recovered,{...addedRevision,created_by:owner.id})
              if(checkMemberBoardReplay){
                const recoveredMember=data(await verifiedOwner.from('st_v2_items').select('id,title,details,created_at,due_at,completed,created_by')
                  .eq('id',nonOwnerTask).single())
                assert.deepEqual(recoveredMember,{...memberRevision,created_by:sourceMember.id})
              }else assert.deepEqual(data(await verifiedOwner.from('st_v2_items').select('id').eq('id',nonOwnerTask)),[])
              await reviewPage.getByRole('group',{name:'Workspace sections'}).getByRole('button',{name:'Board',exact:true}).click()
              await reviewPage.getByText('Post-activation recovery task',{exact:true}).waitFor()
              if(checkMemberBoardReplay){
                await reviewPage.getByText('Separate member task',{exact:true}).waitFor()
                console.log('Edge verified member approval on both projects, withdrawal blocking the staged batch, and exact source-author readback.')
              }
              console.log('Edge recovered the exact new owner-authored task, with signer identity and collision checks and source Board readback.')
            }
            assert.equal(data(await boardAction(verifiedReviewer,'apply')).state,'applied')
            assert.equal(sourceSql(`select count(*) from public.st_v2_workspace_audit where workspace_id='${workspace}'
              and event='workspace.residency_board_replay_applied' and target='${handoffId}';`),'1')
            if(checkSourceReplayReview){
              assert(checkMemberBoardReplay&&checkMemberChannelReplay,'Source review requires both two-project author-controlled fixtures.')
              const readSource=(client,id=workspace)=>client.rpc('st_v8_residency_source_replay_review',{p_workspace:id})
              const result=data(await readSource(verifiedOwner))
              assert.deepEqual(data(await readSource(verifiedReviewer)),result)
              assert.equal((await readSource(proofClient(sourceMemberProof))).error?.code,'42501')
              assert.equal(result.state,'held')
              const outcomes=new Map(result.records.map(record=>[record.id,record.result]))
              for(const id of [...replayTaskIds,addedTask,nonOwnerTask,recoveredChannel,recoveredPost,otherSenderPost]){
                assert.equal(outcomes.get(id),'matched',id)
              }
              if(checkExistingChannelReplay)assert.equal(outcomes.get(existingChannelPost),'matched')
              if(!checkSourceSignoff)assert.equal(outcomes.get(reportedPost),'not_replayed')
              if(checkRollbackFileCopy){
                const destinationObject=JSON.parse(rollbackFileCopy.proof.payload).object
                const file=result.records.find(record=>record.kind==='workspace_file'&&record.id===rollbackFile.id)
                const object=result.records.find(record=>record.kind==='storage_object'&&record.id===destinationObject)
                assert.equal(file.result,'matched')
                assert.equal(object.result,'matched')
                assert.match(file.sourceReceipt,/^[0-9a-f]{64}$/)
                assert.equal(object.sourceReceipt,file.sourceReceipt)
              }
              assert(!JSON.stringify(result).includes('Reviewed recovery chat message'))
              const sourcePanel=reviewPage.getByRole('region',{name:'Source rollback verification',exact:true})
              await sourcePanel.getByRole('button',{name:'Refresh source verification',exact:true}).click()
              const matched=result.records.filter(record=>record.result==='matched').length
              await sourcePanel.getByText(`${matched} of ${result.records.length} reviewed changes verified at the source. Workspace writes are held.`,{exact:true}).waitFor()
              await sourcePanel.getByText('View source verification by record',{exact:true}).click()
              if(checkSourceSignoff){
                assert.deepEqual(result.records.filter(record=>record.result!=='matched'),[])
                const evidenceOwner=sourceReviewPage.getByRole('region',{name:'Source rollback verification',exact:true})
                await evidenceOwner.getByRole('button',{name:'Refresh source verification',exact:true}).click()
                await evidenceOwner.getByLabel('Confirm source evidence workspace ID').fill(workspace)
                await evidenceOwner.getByRole('button',{name:'Record source evidence',exact:true}).click()
                await evidenceOwner.getByText('Awaiting independent sign-off on the recorded source evidence.',{exact:true}).waitFor()
                await sourcePanel.getByRole('button',{name:'Refresh source verification',exact:true}).click()
                await sourcePanel.getByLabel('Confirm source evidence workspace ID').fill(workspace)
                await sourcePanel.getByRole('button',{name:'Sign off on source evidence',exact:true}).click()
                await sourcePanel.getByText('The independent reviewer signed off on all changes in this manifest.',{exact:true}).waitFor()
                if(checkRollbackFileCopy){
                  const evidence=client=>client.rpc('st_v8_residency_source_evidence',{p_workspace:workspace})
                  const original=data(await evidence(verifiedOwner))
                  const objectId=JSON.parse(rollbackFileCopy.proof.payload).object
                  const assertFileChanged=async()=>{
                    const drifted=data(await evidence(verifiedReviewer))
                    assert.equal(drifted.coverage,'incomplete')
                    assert.equal(drifted.records.find(record=>record.id===rollbackFile.id).result,'source_changed')
                    assert.equal(drifted.records.find(record=>record.id===objectId).result,'source_changed')
                    assert.equal((await verifiedReviewer.rpc('st_v8_residency_source_evidence',{
                      p_workspace:workspace,p_action:'confirm',p_confirmation:workspace,
                      p_review:original.evidenceId,p_digest:original.evidenceDigest,
                    })).error?.code,'PT409')
                  }
                  const fileFilter=`where (workspace,id)=('${workspace}','${rollbackFile.id}')`
                  sourceSql(`update sectalk_private.st_v6_workspace_files set filename='Drifted source name.txt' ${fileFilter};`)
                  try { await assertFileChanged() }
                  finally { sourceSql(`update sectalk_private.st_v6_workspace_files set filename='${rollbackFile.name}' ${fileFilter};`) }
                  const liveFilter=`where (bucket_id,name)=('sectalk-workspace-files','${workspace}/${rollbackFile.id}')`
                  sourceSql(`update storage.objects set metadata=metadata||'{"fixturePostSignoffDrift":true}'::jsonb ${liveFilter};`)
                  try { await assertFileChanged() }
                  finally { sourceSql(`update storage.objects set metadata=metadata-'fixturePostSignoffDrift' ${liveFilter};`) }
                  console.log('The exact file and storage records were included in final sign-off. Later file or Storage drift withdrew coverage for both records.')
                }
                console.log('Edge recorded and independently signed the exact source evidence, with both write holds preserved.')
              }else{
                await sourcePanel.getByText(reportedPost,{exact:true}).waitFor()
                assert.equal(await sourcePanel.getByRole('button',{name:'Sign off on source evidence',exact:true}).count(),0)
                console.log('Edge reconciled restored Board tasks and channel history, showed unresolved IDs, and withheld the sign-off action.')
              }
            }
            await sourceReviewerContext.close()
            console.log('Edge replayed two reviewed Board completions atomically with holds, stale-source, owner self-review and ordinary writes denied.')
          }
        }
        await rollbackContext.close()
        if(checkDestinationRetirement){
          targetSql(`update storage.objects set metadata=metadata||'{"retirementDrift":true}'::jsonb
            where (bucket_id,name)=('sectalk-workspace-files','${workspace}/${fileId}');`)
          assert.equal((await retirement(verifiedDestination,'issue')).error?.code,'PT409')
          assert.equal(data(await retirement(verifiedDestination)).retired,true)
          console.log('Later destination Storage drift blocked proof renewal while the retirement hold remained active.')
        }
        assert.equal((await memberLink()).status,404)
        assert.equal((await routing(verifiedOwner,'publish',destinationRouteProof)).error?.code,'PT409')
        assert.equal((await verifiedOwner.rpc('st_v2_post',{p_channel:general(sourceSql),p_id:randomUUID(),p_body:'Source must remain held'})).error?.code,'PT423')
        assert.equal(data(await rollback(verifiedOwner,'suspend_source_route')).state,'held')
        assert.equal(sourceSql(`select count(*) from public.st_v2_workspace_audit where workspace_id='${workspace}'
          and event='workspace.residency_rollback_route_suspended' and target='${handoffId}';`),'1')
        console.log('Edge verified both rollback preparations after credential expiry: target writes paused, source link suspended, and source writes still held.')
      }
    }
  }
  sourceSql(`delete from sectalk_private.st_v8_offboarding_reviewers where workspace='${workspace}' and actor='${reviewer.id}';`)
  if(checkRoomMemberImport)await assert.rejects(inviteResidencyRoomMember({...membership,room}),/403/)
  if(checkChannelHistory)await assert.rejects(restoreResidencyChannelPost({...membership,channel,post:importedPost}),/403/)
  if(checkRoomHistory)await assert.rejects(restoreResidencyPost({...membership,room,post:roomReply}),/403/)
  await assert.rejects(stageWorkspaceContent(stages), /403/)
  data(await verifiedOwner.rpc('st_v8_offboarding_content', { ...command, p_action: 'withdraw' }))
  await assert.rejects(stageWorkspaceContent(stages), /not a current owner-approved/)
  console.log('Two real Supabase projects verified approved staging and live task import, with collision rollback, retries, role isolation and revocation.')
} finally {
  await browser?.close()
  if(scanner)await new Promise(resolve=>scanner.close(resolve))
  if(rollbackStagingPath)await source.storage.from('sectalk-residency-recovery').remove([rollbackStagingPath])
  if(sourceApp&&workspace){
    const path=checkRoomFileImport?workspace+'/rooms/'+room+'/'+fileId:workspace+'/'+fileId
    const paths=checkBothFileScopes?[path,workspace+'/'+workspaceFile.id]:[path]
    if(checkRollbackFileCopy)paths.push(workspace+'/'+rollbackFile.id)
    await source.storage.from('sectalk-workspace-files').remove(paths)
    await target.storage.from('sectalk-workspace-files').remove(paths)
  }
  if(checkRoomFileImport&&workspace){
    if(targetReady)targetSql(`delete from sectalk_private.st_v6_room_files where workspace='${workspace}';`)
    sourceSql(`delete from sectalk_private.st_v6_room_files where workspace='${workspace}';`)
  }
  if (targetReady) targetSql(`begin;
    delete from sectalk_private.st_v6_workspace_files where workspace='${workspace}';
    delete from public.st_v2_workspaces where id='${workspace}';
    delete from sectalk_private.st_v8_residency_workspace_claims where id='${claim}';
    delete from sectalk_private.st_v8_residency_staged_content where cell='${cell}' and approval='${approval}';
    delete from sectalk_private.st_v8_residency_content_admissions where cell='${cell}' and approval='${approval}';
    delete from sectalk_private.st_v8_residency_installation where cell='${cell}';
    delete from sectalk_private.st_v8_residency_cells where id='${cell}'; commit;`)
  if(targetForeignWorkspace)targetSql(`delete from public.st_v2_workspaces where id='${targetForeignWorkspace}';`)
  if((checkChannelHistory||checkRoomMemberImport||checkCutover)&&workspace)for(const command of [sourceSql,targetSql])command(`
    with retired as (delete from sectalk_private.st_v8_residency_history_links where workspace='${workspace}' and approval='${approval}' returning vault_id)
    delete from vault.secrets s using retired r where s.id=r.vault_id;`)
  if(checkRollbackManifest&&workspace)for(const command of [sourceSql,targetSql])command(`
    with retired as (delete from sectalk_private.st_v8_residency_rollback_manifest_admissions a
      using sectalk_private.st_v8_residency_write_handoffs f where f.workspace='${workspace}' and a.handoff=f.handoff returning a.vault_id)
    delete from vault.secrets s using retired r where s.id=r.vault_id;`)
  for(const id of destinationActors)targetSql(`delete from auth.users where id='${id}';`)
  if (workspace) sourceSql(`begin; set local session_replication_role=replica;
    delete from sectalk_private.st_v8_content_export_entries where export_id='${approval}';
    ${checkWriteHandoff||checkCutover?`delete from sectalk_private.st_v8_residency_audit where workspace='${workspace}';`:''}
    set local session_replication_role=origin;
    delete from sectalk_private.st_v6_workspace_files where workspace='${workspace}';
    delete from public.st_v2_workspaces where id='${workspace}'; commit;`)
  if((checkWriteHandoff||checkCutover)&&workspace)sourceSql(`delete from sectalk_private.st_v8_residency_installation where cell='${cell}';
    delete from sectalk_private.st_v8_residency_cells where id='${cell}';`)
  if (unrelated) sourceSql(`delete from public.st_v2_workspaces where id='${unrelated}';`)
  for (const id of actors) sourceSql(`delete from auth.users where id='${id}';`)
}
