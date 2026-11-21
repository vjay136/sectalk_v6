// Disposable Auth QA only. Each run leaves distinct synthetic records and immutable receipts for audit inspection.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { createClient } from '@supabase/supabase-js'
import { verifyStaffPanel } from './workspace-admin-fixture.mjs'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const backend = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname,'127.0.0.1')
assert.equal(backend.origin,'http://127.0.0.1:55321')
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const options = {auth:{persistSession:false,autoRefreshToken:false}}
const service = createClient(backend.origin,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const {chromium} = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const browser = await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
const sourceKind = process.env.SECTALK_OFFBOARDING_SOURCE ?? 'task'
const batchMode = process.env.SECTALK_OFFBOARDING_BATCH === '1'
const reconciliationMode = process.env.SECTALK_OFFBOARDING_RECONCILE === '1'
const archiveReconciliationMode = process.env.SECTALK_OFFBOARDING_ARCHIVE_RECONCILE === '1'
const rootReconciliationMode = process.env.SECTALK_OFFBOARDING_ROOT_RECONCILE === '1'
assert.ok(!(batchMode && reconciliationMode) && (!(batchMode || reconciliationMode) || sourceKind === 'task'))
assert.ok(!archiveReconciliationMode || ['archivedChannelHistory','archivedRoom'].includes(sourceKind))
assert.ok(!rootReconciliationMode || sourceKind==='task' && !batchMode && !reconciliationMode)
const sources = {
  task: {label:'task', table:'st_v2_items', audit:'task', archiveField:'details'},
  post: {label:'channel post', table:'st_v2_posts', audit:'post', archiveField:'body'},
  room: {label:'room message', table:'st_v6_room_posts', audit:'room_post', archiveField:'body'},
  roomTask: {label:'room task', table:'st_v6_tasks', audit:'room_task', archiveField:'title'},
  thread: {label:'room thread', table:'st_v6_room_posts', audit:'room_thread', archiveField:'body'},
  archivedChannel: {label:'archived channel', table:'st_v2_channels', audit:'archive', archiveField:'name'},
  archivedChannelHistory: {label:'archived channel', table:'st_v2_channels', audit:'archive', archiveField:'name'},
  archivedRoom: {label:'archived room', table:'st_v6_rooms', audit:'archive', archiveField:'name'},
  revokedApiKey: {label:'revoked API key', table:'st_v6_integration_keys', audit:'integration', archiveField:'label'},
  revokedWebhook: {label:'revoked webhook', table:'st_v6_webhooks', audit:'integration', archiveField:'label'},
  declinedInvitation: {label:'declined invitation', table:'st_v2_invites', audit:'invitation', archiveField:'status'},
  expiredInvitationLink: {label:'expired invitation link', table:'st_v6_workspace_link_invites', audit:'invitation link', archiveField:'state'},
  archivedWorkspaceGroup: {label:'archived workspace group', table:'st_v6_workspace_groups', audit:'workspace group', archiveField:'name'},
  withdrawnQuote: {label:'withdrawn quote', table:'st_v8_enterprise_orders', audit:'billing quote', archiveField:'reference'},
  rejectedSeatChange: {label:'rejected seat change', table:'st_v8_workspace_seat_changes', audit:'seat change', archiveField:'outcome'},
  suspendedMembership: {label:'suspended membership', table:'st_v2_members', audit:'membership', archiveField:'membership'},
  auditCustody: {label:'audit custody', table:'st_v2_workspace_audit', audit:'workspace audit', archiveField:'event'},
  workflowCustody: {label:'workflow custody', table:'st_v8_offboarding_requests', audit:'offboarding workflow', archiveField:'state'},
  providerKeyRetirement: {label:'external key retirement', table:'st_v7_tenant_key_versions', audit:'external key', archiveField:'version'}
}
assert.ok(Object.hasOwn(sources,sourceKind))
const {label:sourceLabel, table:sourceTable, audit:auditScope, archiveField} = sources[sourceKind]
const roomSource = sourceKind === 'room' || sourceKind === 'roomTask' || sourceKind === 'thread'
const integrationSource = sourceKind === 'revokedApiKey' || sourceKind === 'revokedWebhook'
const invitationSource = sourceKind === 'declinedInvitation'
const expiredLinkSource = sourceKind === 'expiredInvitationLink'
const groupSource = sourceKind === 'archivedWorkspaceGroup'
const quoteSource = sourceKind === 'withdrawnQuote'
const seatChangeSource = sourceKind === 'rejectedSeatChange'
const membershipSource = sourceKind === 'suspendedMembership'
const auditCustodySource = sourceKind === 'auditCustody'
const workflowCustodySource = sourceKind === 'workflowCustody'
const providerKeySource = sourceKind === 'providerKeyRetirement'
const suffix = randomUUID().slice(0,8)
const password = randomUUID()+'!5Qa'

function data(result) {if (result.error) throw result.error; return result.data}

function sql(statement) {
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-q','-At','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true}).trim()
}

async function account(kind) {
  const handle='delete_'+kind+'_'+suffix, email=handle+'@example.invalid'
  const {user}=data(await service.auth.admin.createUser({email,password,email_confirm:true}))
  const client=createClient(backend.origin,publicKey,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:'Disposable Offboarding '+kind}))
  return {id:user.id,email,client}
}

const button=(scope,name)=>scope.getByRole('button',{name,exact:true})
async function open(actor,tab) {
  const page=await browser.newPage({acceptDownloads:true})
  await page.goto(app.href)
  await page.getByLabel('Email address',{exact:true}).fill(actor.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await button(page.getByRole('navigation',{name:'SecTalk features'}),'Workspaces').click()
  await button(page,tab).click()
  const panel=page.getByRole('region',{name:'Workspace offboarding',exact:true})
  await verifyStaffPanel(panel)
  await button(panel,'Refresh offboarding status').waitFor()
  const token=await page.evaluate(()=>{
    const key=Object.keys(localStorage).find(name=>/^sb-.+-auth-token$/.test(name))
    return JSON.parse(localStorage.getItem(key)).access_token
  })
  const native=createClient(backend.origin,publicKey,{...options,global:{headers:{Authorization:'Bearer '+token}}})
  return {page,panel,native,sourcePanel:panel.getByRole('region',{name:'Permanent workspace '+sourceLabel+' deletion'})}
}

async function verifyBatch(requester,judge,workspace,task,post,control,postBody) {
  const sourcePanel=requester.panel.getByRole('region',{name:'Permanent workspace channel post deletion'})
  await sourcePanel.getByLabel('Approved channel post',{exact:true}).selectOption(post)
  await sourcePanel.getByLabel('Confirm channel post offboarding workspace ID').fill(workspace)
  const downloadEvent=requester.page.waitForEvent('download')
  await button(sourcePanel,'Download approved channel post copy').click()
  const download=await downloadEvent
  const copy=JSON.parse(await readFile(await download.path(),'utf8'))
  assert.equal(JSON.parse(copy.json).body,postBody)
  assert.equal(createHash('sha256').update(copy.json).digest('hex'),copy.sha256)

  for (const view of [requester,judge]) {
    await view.panel.locator('summary').filter({hasText:/^Batch source deletion$/}).click()
  }
  const ownerPanel=requester.panel.getByRole('region',{name:'Batch source deletion'})
  const reviewerPanel=judge.panel.getByRole('region',{name:'Batch source deletion'})
  const options=ownerPanel.getByLabel('Add copied source')
  await options.selectOption(await options.locator('option').filter({hasText:task}).getAttribute('value'))
  await options.selectOption(await options.locator('option').filter({hasText:post}).getAttribute('value'))
  await ownerPanel.getByLabel('Confirm batch workspace ID',{exact:true}).fill(workspace)
  await button(ownerPanel,'Prepare exact deletion batch').click()
  await ownerPanel.getByText('Awaiting independent batch review',{exact:true}).waitFor()
  const batch=await ownerPanel.locator('p').filter({hasText:/^Batch ID /}).locator('code').textContent()
  assert.match(batch,/^[a-f0-9-]{36}$/)
  assert.equal(await ownerPanel.getByText('Permanently delete this batch',{exact:true}).count(),0)

  await button(reviewerPanel,'Refresh deletion batches').click()
  await reviewerPanel.getByText('Batch of 2 sources',{exact:true}).waitFor()
  assert.equal(await reviewerPanel.getByText(task,{exact:true}).count(),1)
  assert.equal(await reviewerPanel.getByText(post,{exact:true}).count(),1)
  await reviewerPanel.getByLabel('Confirm batch review workspace ID').fill(workspace)
  await button(reviewerPanel,'Approve exact deletion batch').click()
  await reviewerPanel.getByText('Batch independently approved',{exact:true}).waitFor()

  await button(ownerPanel,'Refresh deletion batches').click()
  await ownerPanel.getByText('Permanently delete this batch',{exact:true}).click()
  await ownerPanel.getByLabel('Confirm batch deletion workspace ID').fill(workspace)
  await ownerPanel.getByLabel('Confirm exact batch ID').fill(control)
  await ownerPanel.getByRole('checkbox',{name:/I retained the approved copies/}).check()
  await button(ownerPanel,'Permanently delete approved batch').click()
  await ownerPanel.getByRole('alert').getByText('Enter the exact batch ID to confirm permanent deletion.').waitFor()
  await ownerPanel.getByLabel('Confirm exact batch ID').fill(batch)
  await button(ownerPanel,'Permanently delete approved batch').click()
  await ownerPanel.getByText('Batch deleted from the live workspace',{exact:true}).waitFor()
  assert.equal(sql(`select id from public.st_v2_items where id in ('${task}','${control}');`),control)
  assert.equal(sql(`select count(*) from public.st_v2_posts where id='${post}';`),'0')
  assert.equal(sql(`select count(*) from sectalk_private.st_v8_offboarding_source_batch_decisions
    where batch='${batch}';`),'2')
  console.log('PASS offboarding mixed batch downloads, independent exact approval, terminal confirmation and live deletion')
}

async function verifyReconciliation(requester,judge,workspace) {
  const storageId=randomUUID()
  const path=workspace+'/synthetic-metadata-only'
  sql(`insert into storage.objects(id,bucket_id,name,metadata,version)
    values('${storageId}','sectalk-workspace-files','${path}','{"size":12}','${randomUUID()}');`)
  for (const view of [requester,judge]) {
    await view.panel.locator('summary').filter({hasText:/^Source erasure reconciliation$/}).click()
  }
  const section=view=>view.panel.getByRole('region',{name:'Source erasure reconciliation',exact:true})
  const ownerPanel=section(requester), reviewerPanel=section(judge)
  const metadata=ownerPanel.getByRole('region',{name:'Current Storage metadata'})
  await metadata.getByText('Untracked objects',{exact:true}).waitFor()
  assert.equal(await metadata.locator('div').filter({hasText:'Untracked objects'}).locator('dd').textContent(),'1')
  assert.equal(await ownerPanel.getByText(path,{exact:true}).count(),0)
  await ownerPanel.getByText('Provider bytes, backups, and full tenant erasure are unverified.',{exact:true}).waitFor()
  await ownerPanel.getByLabel('Confirm reconciliation workspace ID').fill(workspace)
  await button(ownerPanel,'Capture current source reconciliation').click()
  await ownerPanel.getByText('Current reconciliation awaits independent review.',{exact:true}).waitFor()
  await button(reviewerPanel,'Refresh source reconciliation').click()
  await reviewerPanel.getByText('Current reconciliation awaits independent review.',{exact:true}).waitFor()

  sql(`update storage.objects set version='${randomUUID()}' where id='${storageId}';`)
  await reviewerPanel.getByLabel('Confirm reconciliation workspace ID').fill(workspace)
  await button(reviewerPanel,'Confirm exact source reconciliation').click()
  await reviewerPanel.getByRole('alert').getByText('Confirm the latest exact, current source reconciliation').waitFor()
  await button(reviewerPanel,'Refresh source reconciliation').click()
  await reviewerPanel.getByText('Reconciliation changed, expired, or is blocked.',{exact:true}).waitFor()
  assert.equal(await button(reviewerPanel,'Confirm exact source reconciliation').count(),0)

  await ownerPanel.getByLabel('Confirm reconciliation workspace ID').fill(workspace)
  await button(ownerPanel,'Capture current source reconciliation').click()
  await ownerPanel.getByText('Current reconciliation awaits independent review.',{exact:true}).waitFor()
  await button(reviewerPanel,'Refresh source reconciliation').click()
  await reviewerPanel.getByLabel('Confirm reconciliation workspace ID').fill(workspace)
  await button(reviewerPanel,'Confirm exact source reconciliation').click()
  await reviewerPanel.getByText('Current reconciliation independently confirmed.',{exact:true}).waitFor()
  assert.equal(sql(`select count(*) from sectalk_private.st_v8_offboarding_reconciliation_receipts r
    join sectalk_private.st_v8_offboarding_reconciliations p on p.id=r.reconciliation where p.workspace='${workspace}';`),'1')
  console.log('PASS offboarding reconciliation counts, stale metadata denial, and independent fresh review')
}

async function verifyThread(requester,judge,{workspace,root,replies,control,controlReply,hold,owner}) {
  for (const view of [requester,judge]) {
    await view.panel.locator('summary').filter({hasText:/^Permanent room thread deletion$/}).click()
  }
  const scoped=view=>view.panel.getByRole('region',{name:'Permanent room thread deletion',exact:true})
  const ownerPanel=scoped(requester), reviewerPanel=scoped(judge)
  const selection=ownerPanel.getByLabel('Approved room thread',{exact:true})
  await selection.selectOption(root)
  assert.equal(await selection.locator('option[value="'+control+'"]').count(),0)
  await ownerPanel.getByLabel('Confirm thread offboarding workspace ID').fill(workspace)
  const downloadEvent=requester.page.waitForEvent('download')
  await button(ownerPanel,'Download approved thread copy').click()
  const download=await downloadEvent
  assert.equal(download.suggestedFilename(),'sectalk-approved-room-thread-'+root+'.json')
  const copy=JSON.parse(await readFile(await download.path(),'utf8'))
  assert.equal(copy.root,root)
  assert.equal(createHash('sha256').update(copy.manifestJson).digest('hex'),copy.sha256)
  assert.deepEqual(new Set(copy.records.map(item=>item.id)),new Set([root,...replies]))
  for (const item of copy.records) assert.equal(createHash('sha256').update(item.json).digest('hex'),item.sha256)
  await button(ownerPanel,'Prepare exact thread deletion plan').waitFor()
  await ownerPanel.getByLabel('Confirm thread offboarding workspace ID').fill(workspace)
  await button(ownerPanel,'Prepare exact thread deletion plan').click()
  await ownerPanel.getByText('Awaiting independent thread review',{exact:true}).waitFor()
  assert.equal(await ownerPanel.getByText('Permanently delete this room thread',{exact:true}).count(),0)

  await button(reviewerPanel,'Refresh thread deletion status').click()
  await reviewerPanel.getByText('Show exact message manifest',{exact:true}).click()
  for (const reply of replies) assert.equal(await reviewerPanel.getByText(reply,{exact:true}).count(),1)
  await reviewerPanel.getByLabel('Confirm thread review workspace ID').fill(workspace)
  await button(reviewerPanel,'Approve exact room thread deletion').click()
  await reviewerPanel.getByText('Thread independently approved',{exact:true}).waitFor()
  await button(ownerPanel,'Refresh thread deletion status').click()
  await ownerPanel.getByText('Thread independently approved',{exact:true}).waitFor()

  sql(`insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values('${hold}','${workspace}','${owner}','Preserve the scoped synthetic thread.','${owner}');`)
  await button(ownerPanel,'Refresh thread deletion status').click()
  await ownerPanel.getByText('Active preservation holds block thread deletion.',{exact:true}).waitFor()
  assert.equal(await ownerPanel.getByText('Permanently delete this room thread',{exact:true}).count(),0)
  sql(`update sectalk_private.st_v6_workspace_holds set released_at=now(),released_by='${owner}',
    release_reason='Release the disposable test hold.' where id='${hold}';`)

  await button(ownerPanel,'Refresh thread deletion status').click()
  await ownerPanel.getByText('Permanently delete this room thread',{exact:true}).click()
  await ownerPanel.getByLabel('Confirm thread deletion workspace ID').fill(workspace)
  await ownerPanel.getByLabel('Confirm exact root message ID').fill(control)
  await ownerPanel.getByRole('checkbox',{name:/I retained the approved thread copy/}).check()
  await button(ownerPanel,'Permanently delete approved thread').click()
  await ownerPanel.getByRole('alert').getByText('Enter the exact root message ID to confirm thread deletion.').waitFor()
  await ownerPanel.getByLabel('Confirm exact root message ID').fill(root)
  await button(ownerPanel,'Permanently delete approved thread').click()
  await ownerPanel.getByText('Thread deleted from the live workspace',{exact:true}).waitFor()
  assert.equal(sql(`select count(*) from public.st_v6_room_posts where id in ('${[root,...replies].join("','")}');`),'0')
  assert.equal(sql(`select count(*) from public.st_v6_room_posts where id in ('${control}','${controlReply}');`),'2')
  assert.equal(sql(`select count(*) from sectalk_private.st_v8_offboarding_room_thread_decisions d
    join sectalk_private.st_v8_offboarding_room_thread_deletions p on p.id=d.deletion where p.root='${root}';`),'2')
  if(process.env.SECTALK_OFFBOARDING_RECONCILE_RECEIPTS==='1') {
    await requester.panel.locator('summary').filter({hasText:/^Source erasure reconciliation$/}).click()
    const census=requester.panel.getByRole('region',{name:'Source erasure reconciliation',exact:true})
    const receipts=census.getByRole('region',{name:'Verified scoped deletion receipts'})
    await receipts.locator('dt').filter({hasText:'Complete thread deletion receipts'}).locator('xpath=following-sibling::dd[1]')
      .getByText('1',{exact:true}).waitFor()
  }
  console.log('PASS complete thread copy, independent manifest review, hold pause and exact live deletion')
}

async function verifyArchivedStructure(requester,judge,workspace,record,control,hold,owner,kind,historyPosts) {
  const native=data(await requester.native.rpc('st_v8_offboarding_archived_'+kind+'_status',{p_workspace:workspace}))
  assert.deepEqual(native[kind==='room'?'rooms':'channels'].map(item=>item.id),[record])
  const title=kind==='room'?'Remove empty archived rooms':'Remove archived channels'
  const selectionName=kind==='room'?'Empty archived room':'Archived channel'
  for (const view of [requester,judge]) {
    await view.panel.locator('summary').filter({hasText:new RegExp('^'+title+'$')}).click()
  }
  const section=view=>view.panel.getByRole('region',{name:title,exact:true})
  const ownerPanel=section(requester), reviewPanel=section(judge)
  const selection=ownerPanel.getByLabel(selectionName,{exact:true})
  await selection.selectOption(record)
  assert.equal(await selection.locator('option[value="'+control+'"]').count(),0)
  await ownerPanel.getByLabel('Confirm archived '+kind+' workspace ID').fill(workspace)
  const downloadEvent=requester.page.waitForEvent('download')
  await button(ownerPanel,'Download archived '+kind+' copy').click()
  const download=await downloadEvent
  assert.equal(download.suggestedFilename(),'sectalk-approved-archived-'+kind+'-'+record+'.json')
  const copy=JSON.parse(await readFile(await download.path(),'utf8'))
  const bytes=JSON.parse(copy.json)
  assert.equal(createHash('sha256').update(copy.json).digest('hex'),copy.sha256)
  assert.equal(bytes[kind].id,record)
  if (kind==='room') {
    assert.deepEqual(bytes.retainedProof.auditEvents.map(event=>event.action),['room.created','room.archive'])
    assert.deepEqual(bytes.retainedProof.creatorMembership,{role:'owner',room_id:record,user_id:owner})
  } else {
    assert.equal(bytes.archiveAudit.action,'archive')
    assert.equal(bytes.archiveAudit.actor,owner)
    assert.deepEqual((bytes.messages??[]).map(message=>message.id).sort(),[...historyPosts].sort())
    if (historyPosts.length) {
      assert.equal(copy.format,'sectalk-offboarding-archived-channel-history-copy-v1')
      assert.ok(bytes.messages.every(message=>message.sender===owner && message.body.includes('Original archived message')))
    }
  }

  await button(ownerPanel,'Prepare exact '+kind+' removal plan').waitFor()
  await ownerPanel.getByLabel('Confirm archived '+kind+' workspace ID').fill(workspace)
  await button(ownerPanel,'Prepare exact '+kind+' removal plan').click()
  await ownerPanel.getByText('Awaiting independent review',{exact:true}).waitFor()
  assert.equal(await ownerPanel.getByText('Permanently remove this archived '+kind,{exact:true}).count(),0)
  await button(reviewPanel,'Refresh archived '+kind+' status').click()
  await reviewPanel.getByText(copy.sha256,{exact:true}).waitFor()
  assert.equal(await reviewPanel.getByLabel(selectionName,{exact:true}).count(),0)
  if (historyPosts.length) {
    await reviewPanel.getByText('Review '+historyPosts.length+' archived messages',{exact:true}).click()
    for (const id of historyPosts) {
      const message=reviewPanel.getByRole('listitem').filter({hasText:id})
      assert.match(await message.locator('code').nth(1).textContent(),/^[a-f0-9]{64}$/)
    }
  }
  await reviewPanel.getByLabel('Confirm '+kind+' review workspace ID').fill(workspace)
  await button(reviewPanel,'Approve exact archived '+kind+' removal').click()
  await reviewPanel.getByText('Removal independently approved',{exact:true}).waitFor()

  sql(`insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values('${hold}','${workspace}','${owner}','Preserve the synthetic archived ${kind}.','${owner}');`)
  await button(ownerPanel,'Refresh archived '+kind+' status').click()
  await ownerPanel.getByText('Active preservation holds block archived '+kind+' removal.',{exact:true}).waitFor()
  assert.equal(await ownerPanel.getByText('Permanently remove this archived '+kind,{exact:true}).count(),0)
  sql(`update sectalk_private.st_v6_workspace_holds set released_at=now(),released_by='${owner}',
    release_reason='Release this disposable hold.' where id='${hold}';`)

  await button(ownerPanel,'Refresh archived '+kind+' status').click()
  await ownerPanel.getByText('Permanently remove this archived '+kind,{exact:true}).click()
  await ownerPanel.getByLabel('Confirm '+kind+' removal workspace ID').fill(workspace)
  await ownerPanel.getByLabel('Confirm exact archived '+kind+' ID').fill(control)
  await ownerPanel.getByRole('checkbox',{name:new RegExp('I retained the approved '+kind+' copy')}).check()
  await button(ownerPanel,'Permanently remove approved '+kind).click()
  await ownerPanel.getByRole('alert').getByText('Enter the exact archived '+kind+' ID.').waitFor()
  await ownerPanel.getByLabel('Confirm exact archived '+kind+' ID').fill(record)
  await button(ownerPanel,'Permanently remove approved '+kind).click()
  await ownerPanel.getByText('Removed from the live workspace',{exact:true}).waitFor()
  if (kind==='room') {
    assert.equal(sql(`select count(*) from public.st_v6_rooms where id='${record}';`),'0')
    assert.equal(sql(`select count(*) from public.st_v6_room_posts where room_id='${control}';`),'1')
    assert.equal(sql(`select count(*) from sectalk_private.st_v8_offboarding_retained_room_proof r
      cross join lateral jsonb_array_elements(r.proof->'auditEvents') e
      join sectalk_private.st_v6_audit_chain a on a.source='public.st_v6_room_audit' and a.source_id=(e->>'id')::bigint
      where r.room='${record}' and a.operation='DELETE' and a.row_hash=sectalk_private.st_v6_audit_row_hash(e);`),'2')
  } else {
    assert.equal(sql(`select count(*) from public.st_v2_channels where id='${record}';`),'0')
    assert.equal(sql(`select count(*) from public.st_v2_posts where channel_id='${control}';`),'1')
    if (historyPosts.length) {
      const ids=historyPosts.map(id=>`'${id}'`).join(',')
      assert.equal(sql(`select count(*) from public.st_v2_posts where id in (${ids});`),'0')
      assert.equal(sql(`select count(*) from sectalk_private.st_v7_search_document where kind='channel' and object_id in (${ids});`),'0')
      assert.equal(sql(`select count(*) from sectalk_private.st_v8_offboarding_retired_channel_posts where post in (${ids});`),String(historyPosts.length))
    }
    assert.equal(sql(`select count(*) from sectalk_private.st_v8_offboarding_retained_channel_archive r
      join sectalk_private.st_v6_audit_chain a on a.source='sectalk_private.st_v6_channel_audit' and a.source_id=r.audit_id
      where r.audit_row->>'channel_id'='${record}' and a.operation='DELETE' and encode(a.row_hash,'hex')=r.sha256;`),'1')
  }
  console.log('PASS archived '+kind+' copy, independent review, hold pause, physical removal and retained native audit')
}

async function verifyArchiveReconciliation(requester,judge,workspace,kind,historyPosts) {
  const title='Source erasure reconciliation'
  for (const view of [requester,judge]) {
    await view.panel.locator('summary').filter({hasText:/^Source erasure reconciliation$/}).click()
  }
  const section=view=>view.panel.getByRole('region',{name:title,exact:true})
  const ownerPanel=section(requester), reviewPanel=section(judge)
  const value=(panel,label)=>panel.getByText(label,{exact:true}).locator('xpath=following-sibling::dd[1]')
  const receipt=kind==='room'?'Verified archived room removal receipts':'Verified archived channel removal receipts'
  assert.equal(await value(ownerPanel,receipt).textContent(),'1')
  assert.equal(await value(ownerPanel,'Verified archived channel message removals').textContent(),String(historyPosts.length))
  await ownerPanel.getByText('Provider bytes, backups, and full tenant erasure are unverified.',{exact:true}).waitFor()

  await ownerPanel.getByLabel('Confirm reconciliation workspace ID').fill(workspace)
  await button(ownerPanel,'Capture current source reconciliation').click()
  await ownerPanel.getByText('Current reconciliation awaits independent review.',{exact:true}).waitFor()
  await button(reviewPanel,'Refresh source reconciliation').click()
  await reviewPanel.getByLabel('Confirm reconciliation workspace ID').fill(workspace)
  await button(reviewPanel,'Confirm exact source reconciliation').click()
  await reviewPanel.getByText('Current reconciliation independently confirmed.',{exact:true}).waitFor()

  if (historyPosts.length) {
    const id=historyPosts[0]
    sql(`insert into sectalk_private.st_v7_search_document(kind,object_id,fingerprint,first_terms,second_terms)
      values('channel','${id}',decode(repeat('0',64),'hex'),to_tsvector('synthetic stale searchable data'),to_tsvector(''));`)
    await button(reviewPanel,'Refresh source reconciliation').click()
    await reviewPanel.getByText('Archive receipt findings block capture and approval.',{exact:true}).waitFor()
    assert.equal(await value(reviewPanel,'Archived channel receipts needing attention').textContent(),'1')
    assert.equal(await value(reviewPanel,receipt).textContent(),'0')
    assert.equal(await button(reviewPanel,'Confirm exact source reconciliation').count(),0)
    await button(ownerPanel,'Refresh source reconciliation').click()
    await ownerPanel.getByText('Archive receipt findings block capture and approval.',{exact:true}).waitFor()
    assert.equal(await button(ownerPanel,'Capture current source reconciliation').count(),0)

    sql(`delete from sectalk_private.st_v7_search_document where (kind,object_id)=('channel','${id}');`)
    await button(ownerPanel,'Refresh source reconciliation').click()
    await ownerPanel.getByText('A previous archive finding invalidated this review. Capture and confirm a fresh reconciliation.',{exact:true}).waitFor()
    await ownerPanel.getByLabel('Confirm reconciliation workspace ID').fill(workspace)
    await button(ownerPanel,'Capture current source reconciliation').click()
    await ownerPanel.getByText('Current reconciliation awaits independent review.',{exact:true}).waitFor()
    await button(reviewPanel,'Refresh source reconciliation').click()
    await reviewPanel.getByLabel('Confirm reconciliation workspace ID').fill(workspace)
    await button(reviewPanel,'Confirm exact source reconciliation').click()
    await reviewPanel.getByText('Current reconciliation independently confirmed.',{exact:true}).waitFor()
  }
  console.log('PASS exact archived '+kind+' custody and final independent source reconciliation')
}

async function verifyRootReconciliation(requester,judge,workspace,owner) {
  const quote=randomUUID()
  const privateTerms='Synthetic quoted terms for disposable source reconciliation.'
  sql(`insert into sectalk_private.st_v8_enterprise_orders(id,workspace,reference,currency,committed_seats,annual_total,
    starts_on,ends_on,expires_on,terms,quoted_by) values('${quote}','${workspace}','Disposable quote','USD',1,100,
      current_date+1,current_date+365,current_date,'${privateTerms}','${owner}');`)
  const title='Source erasure reconciliation'
  for (const view of [requester,judge]) await view.panel.locator('summary').filter({hasText:/^Source erasure reconciliation$/}).click()
  const section=view=>view.panel.getByRole('region',{name:title,exact:true})
  const ownerPanel=section(requester),reviewPanel=section(judge)
  const value=(panel,label)=>panel.getByText(label,{exact:true}).locator('xpath=following-sibling::dd[1]')
  await ownerPanel.getByText('Workspace record removal preflight',{exact:true}).click()
  const actions=ownerPanel.getByRole('region',{name:'Effect of removing the workspace record',exact:true})
  const families=ownerPanel.getByRole('region',{name:'Direct references by data family',exact:true})
  assert.equal(await value(actions,'Prevent workspace record removal').textContent(),'2')
  assert.ok(Number(await value(actions,'Would be removed automatically').textContent())>0)
  assert.ok(Number(await value(families,'Audit and preservation').textContent())>0)
  assert.equal(await value(families,'Billing and orders').textContent(),'1')
  assert.equal(await ownerPanel.getByText(privateTerms,{exact:true}).count(),0)
  await ownerPanel.getByText('Provider bytes, backups, and full tenant erasure are unverified.',{exact:true}).waitFor()

  async function captureAndReview() {
    await ownerPanel.getByLabel('Confirm reconciliation workspace ID').fill(workspace)
    await button(ownerPanel,'Capture current source reconciliation').click()
    await ownerPanel.getByText('Current reconciliation awaits independent review.',{exact:true}).waitFor()
    const digest=await ownerPanel.locator('p').filter({hasText:/^Captured digest /}).locator('code').textContent()
    await button(reviewPanel,'Refresh source reconciliation').click()
    await reviewPanel.getByLabel('Confirm reconciliation workspace ID').fill(workspace)
    await button(reviewPanel,'Confirm exact source reconciliation').click()
    await reviewPanel.getByText('Current reconciliation independently confirmed.',{exact:true}).waitFor()
    return digest
  }
  const initial=await captureAndReview()
  sql(`update sectalk_private.st_v8_enterprise_orders set terms='Updated synthetic quote terms, same record count.' where id='${quote}';`)
  await button(reviewPanel,'Refresh source reconciliation').click()
  await reviewPanel.getByText('Reconciliation changed, expired, or is blocked.',{exact:true}).waitFor()
  assert.equal(await button(reviewPanel,'Confirm exact source reconciliation').count(),0)
  await button(ownerPanel,'Refresh source reconciliation').click()
  await ownerPanel.getByText('Reconciliation changed, expired, or is blocked.',{exact:true}).waitFor()
  assert.equal(await value(actions,'Prevent workspace record removal').textContent(),'2')
  assert.notEqual(await captureAndReview(),initial)
  assert.equal(sql(`select count(*) from sectalk_private.st_v8_enterprise_orders where id='${quote}' and workspace='${workspace}';`),'1')
  console.log('PASS exact workspace root preflight, same-count residual drift, fresh independent browser review and restrictive record preserved')
}

async function verifyAuditCustody(requester,judge,workspace,hold,owner) {
  const title='Workspace audit custody'
  for (const view of [requester,judge]) {
    await view.panel.locator('summary').filter({hasText:new RegExp('^'+title+'$')}).click()
  }
  const ownerPanel=requester.panel.getByRole('region',{name:title,exact:true})
  const reviewPanel=judge.panel.getByRole('region',{name:title,exact:true})
  const digest=await ownerPanel.locator('dd code').first().textContent()
  assert.match(digest,/^[a-f0-9]{64}$/)
  const nativeDigest=()=>sql(`select sha256 from sectalk_private.st_v8_offboarding_audit_custody_manifest('${workspace}') where valid;`)
  assert.equal(nativeDigest(),digest)
  const read=async()=>{
    const report=data(await requester.native.rpc('st_v8_offboarding_reconciliation',{p_workspace:workspace}))
    return report.summary.workspaceRootDependencies.deleteActions.restrict
  }
  const restrictions=await read()
  const confirmation=panel=>panel.getByLabel('Confirm audit custody workspace ID',{exact:true})
  await confirmation(ownerPanel).fill(workspace)
  await button(ownerPanel,'Capture audit custody plan').click()
  await ownerPanel.getByText('Awaiting independent audit review.',{exact:true}).waitFor()
  assert.equal(await button(ownerPanel,'Release approved audit link').count(),0)
  assert.equal(await button(ownerPanel,'Approve exact audit custody').count(),0)
  const planDigest=await ownerPanel.locator('dd code').last().textContent()
  assert.match(planDigest,/^[a-f0-9]{64}$/)
  assert.notEqual(planDigest,digest)
  await button(reviewPanel,'Refresh audit custody status').click()
  await reviewPanel.getByText(planDigest,{exact:true}).waitFor()
  await confirmation(reviewPanel).fill(workspace)
  await button(reviewPanel,'Approve exact audit custody').click()
  await reviewPanel.getByText('Audit custody independently approved.',{exact:true}).waitFor()
  assert.equal(await button(reviewPanel,'Release approved audit link').count(),0)
  await button(ownerPanel,'Refresh audit custody status').click()
  await confirmation(ownerPanel).fill(randomUUID())
  await ownerPanel.getByRole('checkbox',{name:'I confirm the original audit events and chain will be retained.'}).check()
  await button(ownerPanel,'Release approved audit link').click()
  await ownerPanel.getByRole('alert').getByText('Enter the exact workspace ID.').waitFor()
  await confirmation(ownerPanel).fill(workspace)
  await button(ownerPanel,'Release approved audit link').click()
  await ownerPanel.getByText('Audit retained independently of the live workspace.',{exact:true}).waitFor()
  assert.equal(nativeDigest(),digest)
  assert.equal(await read(),restrictions-1)
  if (!hold) return
  data(await requester.native.rpc('st_v6_place_workspace_hold',{p_workspace:workspace,p_id:hold,p_room:null,
    p_member:owner,p_from:null,p_until:null,p_reason:'Exercise native custody reattachment during a disposable legal hold.'}))
  await button(ownerPanel,'Refresh audit custody status').click()
  await ownerPanel.getByText('Active preservation holds block release of the audit link.',{exact:true}).waitFor()
  await ownerPanel.getByText('Audit remains linked to the live workspace.',{exact:true}).waitFor()
  assert.equal(await button(ownerPanel,'Release approved audit link').count(),0)
  assert.equal(await read(),restrictions)
  assert.notEqual(nativeDigest(),digest)
  console.log('PASS workspace audit custody exact independent approval, preserved audit digest, released root constraint, and native hold relink')
}

async function reviewSourceReconciliation(requester,judge,workspace) {
  const title='Source erasure reconciliation'
  const scope=view=>view.panel.locator('summary').filter({hasText:new RegExp('^'+title+'$')})
  for (const view of [requester,judge]) await scope(view).click()
  const sourceOwner=requester.panel.getByRole('region',{name:title,exact:true})
  const sourceReviewer=judge.panel.getByRole('region',{name:title,exact:true})
  await sourceOwner.getByLabel('Confirm reconciliation workspace ID').fill(workspace)
  await button(sourceOwner,'Capture current source reconciliation').click()
  await sourceOwner.getByText('Current reconciliation awaits independent review.',{exact:true}).waitFor()
  await button(sourceReviewer,'Refresh source reconciliation').click()
  await sourceReviewer.getByLabel('Confirm reconciliation workspace ID').fill(workspace)
  await button(sourceReviewer,'Confirm exact source reconciliation').click()
  await sourceReviewer.getByText('Current reconciliation independently confirmed.',{exact:true}).waitFor()
  for (const view of [requester,judge]) await scope(view).click()
}

async function verifyProviderKeyRetirement(requester,judge,workspace,request,reviewer,pins) {
  const title='External key records retirement'
  const blocked='Verify every provider key receipt and confirm the latest source reconciliation before continuing.'
  for (const view of [requester,judge]) await view.panel.locator('summary').filter({hasText:new RegExp('^'+title+'$')}).click()
  const ownerPanel=requester.panel.getByRole('region',{name:title,exact:true})
  const reviewPanel=judge.panel.getByRole('region',{name:title,exact:true})
  const capture='Capture external key retirement plan'
  const approve='Approve exact external key retirement'
  const retire='Retire approved external key records'
  const reload=panel=>button(panel,'Refresh external key retirement status').click()
  const confirm=panel=>panel.getByLabel('Confirm external key retirement workspace ID',{exact:true})
  const value=(panel,label)=>panel.getByText(label,{exact:true}).locator('xpath=following-sibling::dd[1]')
  await ownerPanel.getByText(blocked,{exact:true}).waitFor()
  assert.equal(await value(ownerPanel,'Native tenant key versions').textContent(),'2')
  assert.equal(await button(ownerPanel,capture).count(),0)
  for(const version of [1,2]) {
    const ticket=data(await judge.native.rpc('st_v8_begin_tenant_provider_erasure',{
      p_workspace:workspace,p_version:version,p_confirmation:workspace}))
    assert.ok(ticket.ticket)
    assert.equal(data(await service.rpc('st_v8_commit_tenant_provider_erasure',{
      p_ticket:ticket.ticket,p_actor:reviewer,p_event:randomUUID(),
      p_event_time:new Date().toISOString(),p_sha256:createHash('sha256').update(randomUUID()).digest('hex')})),true)
    await reload(ownerPanel)
    await value(ownerPanel,'Matched provider receipts').filter({hasText:new RegExp('^'+version+'$')}).waitFor()
    await ownerPanel.getByText(blocked,{exact:true}).waitFor()
    assert.equal(await button(ownerPanel,capture).count(),0)
  }
  await reviewSourceReconciliation(requester,judge,workspace)
  await reload(ownerPanel)
  await confirm(ownerPanel).fill(workspace)
  await button(ownerPanel,capture).click()
  await ownerPanel.getByText('Awaiting independent external key retirement review.',{exact:true}).waitFor()
  assert.equal(await button(ownerPanel,approve).count(),0)
  assert.equal(await button(ownerPanel,retire).count(),0)
  const digest=await value(ownerPanel,'Review plan SHA-256').textContent()
  assert.match(digest,/^[a-f0-9]{64}$/)
  await reload(reviewPanel)
  await value(reviewPanel,'Review plan SHA-256').getByText(digest,{exact:true}).waitFor()
  assert.equal(await button(reviewPanel,capture).count(),0)
  await confirm(reviewPanel).fill(workspace)
  await button(reviewPanel,approve).click()
  await reviewPanel.getByText('External key record retirement independently approved.',{exact:true}).waitFor()
  assert.equal(await button(reviewPanel,retire).count(),0)
  await reload(ownerPanel)
  await button(ownerPanel,retire).waitFor()
  await confirm(ownerPanel).fill(randomUUID())
  await ownerPanel.getByRole('checkbox',{name:'I confirm the reviewed key references will be permanently removed from the database and the provider receipts will be retained.'}).check()
  await button(ownerPanel,retire).click()
  await ownerPanel.getByRole('alert').getByText('Enter the exact workspace ID.').waitFor()
  await confirm(ownerPanel).fill(workspace)
  await button(ownerPanel,retire).click()
  await ownerPanel.getByText('External key references retired. The provider receipts and key audit are retained.',{exact:true}).waitFor()
  await ownerPanel.getByText('Physical Storage erasure, backup erasure, and full workspace deletion remain unverified.',{exact:true}).waitFor()
  assert.equal(await value(ownerPanel,'Native tenant key versions').textContent(),'0')
  assert.equal(await value(ownerPanel,'Retired external key versions').textContent(),'2')
  assert.equal(await value(ownerPanel,'Matched provider receipts').textContent(),'2')
  assert.match(await value(ownerPanel,'Retirement receipt SHA-256').textContent(),/^[a-f0-9]{64}$/)
  const text=await ownerPanel.textContent()
  assert.ok(pins.every(pin=>!text.includes(pin)))
  assert.equal(sql(`select count(*) from sectalk_private.st_v7_tenant_key_versions where workspace='${workspace}';`),'0')
  assert.equal(sql(`select count(*) from sectalk_private.st_v8_provider_erasure_receipts where (workspace,request)=('${workspace}','${request}');`),'2')
  assert.equal(sql(`select count(*) from sectalk_private.st_v7_tenant_key_state where workspace='${workspace}' and destroyed_at is not null;`),'1')
  const reconciliation=data(await requester.native.rpc('st_v8_offboarding_reconciliation',{p_workspace:workspace}))
  assert.equal(reconciliation.summary.providerKeyDisposition.state,'native-markers-retired')
  assert.equal(reconciliation.summary.providerKeyDisposition.retiredVersions,2)
  assert.equal(reconciliation.current,false)
  assert.equal(reconciliation.fullTenantErasure,'unverified')
  console.log('PASS external key retirement through exact provider evidence and independent browser review, protected receipts, and pending Storage/backup scope')
}

async function verifyWorkflowCustody(requester,judge,workspace,request,caseId) {
  const title='Offboarding records custody'
  const blocked='Complete current workspace audit custody and independent source reconciliation with a valid downloaded inventory.'
  for (const view of [requester,judge]) {
    await view.panel.locator('summary').filter({hasText:new RegExp('^'+title+'$')}).click()
  }
  const ownerPanel=requester.panel.getByRole('region',{name:title,exact:true})
  const reviewerPanel=judge.panel.getByRole('region',{name:title,exact:true})
  const ready=panel=>button(panel,'Capture offboarding records plan')
  const release=panel=>button(panel,'Release approved offboarding record links')
  const confirmation=panel=>panel.getByLabel('Confirm offboarding records workspace ID',{exact:true})
  const reload=panel=>button(panel,'Refresh offboarding records custody').click()
  const reviewedPlan=data(await requester.native.rpc('st_v8_offboarding_storage_plan',{
    p_workspace:workspace,p_confirmation:workspace,p_action:'capture'}))
  data(await judge.native.rpc('st_v8_offboarding_storage_plan',{p_workspace:workspace,p_confirmation:workspace,
    p_action:'confirm',p_plan:reviewedPlan.plan,p_sha256:reviewedPlan.sha256}))
  await ownerPanel.getByText(blocked,{exact:true}).waitFor()
  assert.equal(await ready(ownerPanel).count(),0)
  await verifyAuditCustody(requester,judge,workspace)
  await reviewSourceReconciliation(requester,judge,workspace)
  for (const view of [requester,judge]) {
    await view.panel.locator('summary').filter({hasText:/^Workspace audit custody$/}).click()
  }
  const exactRows=()=>sql(`select jsonb_build_array(to_jsonb(r)-'live_workspace',to_jsonb(c)-'live_workspace')
    from sectalk_private.st_v8_offboarding_requests r join sectalk_private.st_v7_compliance_cases c on c.id=r.case_id
    where (r.id,c.id)=('${request}','${caseId}');`)
  const originals=exactRows()
  assert.ok(originals)
  await reload(ownerPanel)
  await confirmation(ownerPanel).fill(workspace)
  await ready(ownerPanel).click()
  await ownerPanel.getByText('Awaiting independent offboarding records review.',{exact:true}).waitFor()
  assert.equal(await release(ownerPanel).count(),0)
  const approval='Approve exact offboarding records custody'
  assert.equal(await button(ownerPanel,approval).count(),0)
  const digests=await ownerPanel.locator('dd code').allTextContents()
  assert.equal(digests.length,3)
  assert.ok(digests.every(hash=>/^[a-f0-9]{64}$/.test(hash)))
  await reload(reviewerPanel)
  await reviewerPanel.getByText(digests.at(-1),{exact:true}).waitFor()
  assert.deepEqual(await reviewerPanel.locator('dd code').allTextContents(),digests)
  await confirmation(reviewerPanel).fill(workspace)
  await button(reviewerPanel,approval).click()
  await reviewerPanel.getByText('Offboarding records custody independently approved.',{exact:true}).waitFor()
  assert.equal(await release(reviewerPanel).count(),0)
  await reload(ownerPanel)
  const retained=ownerPanel.getByRole('checkbox',{
    name:'I confirm the original offboarding request and approved inventory case will be retained.'})
  await confirmation(ownerPanel).fill(randomUUID())
  await retained.check()
  await release(ownerPanel).click()
  await ownerPanel.getByRole('alert').getByText('Enter the exact workspace ID.').waitFor()
  await confirmation(ownerPanel).fill(workspace)
  await release(ownerPanel).click()
  await ownerPanel.getByText('Offboarding records retained independently of the live workspace.',{exact:true}).waitFor()
  assert.equal(exactRows(),originals)
  assert.equal(sql(`select count(*) from sectalk_private.st_v8_offboarding_requests r
    join sectalk_private.st_v7_compliance_cases c on c.id=r.case_id
    join sectalk_private.st_v8_offboarding_storage_plans p on p.request=r.id
    where (r.id,c.id,p.id)=('${request}','${caseId}','${reviewedPlan.plan}')
      and r.live_workspace is null and c.live_workspace is null and p.reviewed_at is not null;`),'1')
  sql(`update sectalk_private.st_v7_compliance_cases set case_reference='Late disposable workflow reference' where id='${caseId}';`)
  await reload(ownerPanel)
  await ownerPanel.getByText('Offboarding records remain linked to the live workspace.',{exact:true}).waitFor()
  await ownerPanel.getByText(blocked,{exact:true}).waitFor()
  assert.equal(await release(ownerPanel).count(),0)
  console.log('PASS offboarding records custody through audit and reconciliation prerequisites, exact independent workflow review, Storage lineage, and reattachment')
}

async function verifyReviewedRemoval(requester,judge,workspace,record,protectedRecord,hold,owner,kind,context) {
  const settings={
    webhook:{name:'webhook',title:'Retire revoked webhooks',selection:'Revoked webhook',qualifier:'revoked',file:'retired-webhook',field:'endpoint',category:'integrations'},
    'api-key':{name:'API key',title:'Retire revoked API keys',selection:'Revoked API key',qualifier:'revoked',file:'retired-api-key',field:'key',category:'integrations'},
    invitation:{name:'invitation',title:'Remove declined invitations',selection:'Declined invitation',qualifier:'declined',file:'declined-invitation',field:'invitation',category:'access'},
    link:{name:'invitation link',title:'Remove expired invitation links',selection:'Expired invitation link',qualifier:'expired',file:'expired-invitation-link',field:'link',category:'access'},
    group:{name:'group',title:'Remove empty archived groups',selection:'Empty archived group',qualifier:'archived',file:'archived-workspace-group',field:'group',category:'access'},
    order:{name:'quote',title:'Retain withdrawn enterprise quotes',selection:'Withdrawn quote',qualifier:'withdrawn',file:'withdrawn-enterprise-quote',field:'order',category:'billing'},
    change:{name:'seat change',title:'Retire rejected seat changes',selection:'Rejected seat change',qualifier:'rejected',file:'rejected-seat-change',field:'change',category:'billing'},
    member:{name:'membership',title:'Retire suspended memberships',selection:'Suspended membership',qualifier:'suspended',file:'suspended-membership',field:'membership',category:'access'}
  }[kind]
  const {name,title,selection:selectionName,qualifier,file,field,category}=settings
  const precise=qualifier+' '+name
  const detaching=kind==='order'
  const operation=detaching?'detachment':'removal'
  const terminal=detaching?'Detach this '+precise:'Permanently remove this '+precise
  const confirmButton=detaching?'Detach approved quote':'Permanently remove approved '+name
  const read=async()=>data(await requester.native.rpc('st_v8_offboarding_reconciliation',{p_workspace:workspace}))
  const rootCount=report=>detaching?report.summary.workspaceRootDependencies.deleteActions.restrict
    :report.summary.workspaceRootDependencies.categories[category]
  const before=rootCount(await read())
  for (const view of [requester,judge]) await view.panel.locator('summary').filter({hasText:new RegExp('^'+title+'$')}).click()
  const section=view=>view.panel.getByRole('region',{name:title,exact:true})
  const ownerPanel=section(requester), reviewPanel=section(judge)
  const selection=ownerPanel.getByLabel(selectionName,{exact:true})
  await selection.selectOption(record)
  assert.equal(await selection.locator('option[value="'+protectedRecord+'"]').count(),0)
  await ownerPanel.getByLabel('Confirm '+precise+' workspace ID').fill(workspace)
  const downloadEvent=requester.page.waitForEvent('download')
  await button(ownerPanel,'Download '+precise+' copy').click()
  const download=await downloadEvent
  assert.equal(download.suggestedFilename(),'sectalk-approved-'+file+'-'+record+'.json')
  const copy=JSON.parse(await readFile(await download.path(),'utf8'))
  const source=JSON.parse(copy.json)
  assert.equal(createHash('sha256').update(copy.json).digest('hex'),copy.sha256)
  assert.equal(kind==='member'?source.membership.user_id:source[field].id,record)
  if (detaching) {
    assert.equal(source.order.state,'withdrawn')
    assert.deepEqual(source.billingEvents.map(event=>event.action),['quote','withdraw'])
  } else if (kind==='change') {
    assert.equal(source.change.outcome,'rejected')
    assert.equal(source.change.quantity,3)
  } else if (kind==='member') {
    assert.equal(source.membership.role,'member')
    assert.ok(source.membership.suspended_at)
    assert.equal(source.acceptedInvitation,context.invite)
    assert.deepEqual(source.workspaceAudit.map(event=>event.event),['member.invited','member.joined','member.suspend'])
  } else if (kind==='group') {
    assert.ok(source.group.archived_at)
    assert.deepEqual(source.workspaceAudit.map(event=>event.event),['group.created','group.archive'])
  } else if (kind==='link') {
    assert.equal(source.link.state,'expired-unused')
    assert.ok(Date.parse(source.link.expiresAt)<Date.now())
  } else if (kind==='invitation') {
    assert.equal(source.invitation.status,'declined')
    assert.equal(source.invitation.recipient,context.recipient)
    assert.equal(source.workspaceAudit.event,'member.invited')
  } else {
    assert.equal(source.revocation,'offboarding')
    assert.equal(source.workspaceAudit[0].event,'integration.'+(kind==='webhook'?'webhook':'key')+'_created')
  }
  assert.ok(context.privateValues.every(value=>!copy.json.includes(value)))
  await ownerPanel.getByLabel('Confirm '+precise+' workspace ID').fill(workspace)
  await button(ownerPanel,'Prepare exact '+name+' '+operation+' plan').click()
  await ownerPanel.getByText('Awaiting independent review',{exact:true}).waitFor()
  assert.equal(await ownerPanel.getByText(terminal,{exact:true}).count(),0)
  await button(reviewPanel,'Refresh '+precise+' status').click()
  await reviewPanel.getByText(copy.sha256,{exact:true}).waitFor()
  assert.equal(await reviewPanel.getByLabel(selectionName,{exact:true}).count(),0)
  await reviewPanel.getByLabel('Confirm '+name+' review workspace ID').fill(workspace)
  await button(reviewPanel,'Approve exact '+precise+' '+operation).click()
  await reviewPanel.getByText(detaching?'Detachment independently approved':'Removal independently approved',{exact:true}).waitFor()

  sql(`insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values('${hold}','${workspace}','${owner}','Retain disposable integration evidence.','${owner}');`)
  await button(ownerPanel,'Refresh '+precise+' status').click()
  await ownerPanel.getByText('Active preservation holds block '+precise+' '+operation+'.',{exact:true}).waitFor()
  assert.equal(await ownerPanel.getByText(terminal,{exact:true}).count(),0)
  sql(`update sectalk_private.st_v6_workspace_holds set released_at=now(),released_by='${owner}',
    release_reason='Release disposable integration evidence hold.' where id='${hold}';`)
  await button(ownerPanel,'Refresh '+precise+' status').click()
  await ownerPanel.getByText(terminal,{exact:true}).click()
  await ownerPanel.getByLabel('Confirm '+name+' '+operation+' workspace ID').fill(workspace)
  await ownerPanel.getByLabel('Confirm exact '+precise+' ID').fill(protectedRecord)
  await ownerPanel.getByRole('checkbox',{name:new RegExp('I retained the approved '+name+' copy')}).check()
  await button(ownerPanel,confirmButton).click()
  await ownerPanel.getByRole('alert').getByText('Enter the exact '+precise+' ID.').waitFor()
  await ownerPanel.getByLabel('Confirm exact '+precise+' ID').fill(record)
  await button(ownerPanel,confirmButton).click()
  await ownerPanel.getByText(detaching?'Quote retained in billing custody':'Removed from the live workspace',{exact:true}).waitFor()
  assert.equal(rootCount(await read()),before-1)
  if (detaching) {
    assert.equal(sql(`select count(*) from sectalk_private.st_v8_enterprise_orders
      where (id,workspace,state)=('${record}','${workspace}','withdrawn') and live_workspace is null;`),'1')
    assert.equal(sql(`select count(*) from sectalk_private.st_v8_enterprise_orders
      where (id,live_workspace,state)=('${protectedRecord}','${workspace}','accepted');`),'1')
    assert.equal(sql(`select count(*) from sectalk_private.st_v8_enterprise_order_events where order_id='${record}';`),'2')
    const billing=data(await requester.native.rpc('st_v8_enterprise_billing_view',{p_workspace:workspace}))
    assert.ok(billing.orders.some(order=>order.id===record && order.state==='withdrawn' && !('live_workspace' in order)))
  } else if (kind==='change') {
    assert.equal(sql(`select count(*) from sectalk_private.st_v8_workspace_seat_changes where id='${record}';`),'0')
    assert.equal(sql(`select count(*) from sectalk_private.st_v8_workspace_seat_changes
      where (id,workspace,outcome)=('${protectedRecord}','${workspace}','settled');`),'1')
    assert.deepEqual(data(await service.rpc('st_v8_workspace_seat_command',{
      p_workspace:workspace,p_actor:owner,p_action:'status'})),context.originalAllocation)
    assert.equal(sql(`select count(*) from sectalk_private.st_v8_offboarding_retired_rejected_seat_change
      where change_id='${record}' and custody->>'outcome'='rejected' and not (custody ? 'lease_token');`),'1')
  } else if (kind==='member') {
    assert.equal(sql(`select count(*) from public.st_v2_members
      where (workspace_id,user_id)=('${workspace}','${record}');`),'0')
    assert.equal(sql(`select count(*) from public.st_v2_members
      where (workspace_id,user_id)=('${workspace}','${protectedRecord}') and suspended_at is null;`),'1')
    assert.equal(sql(`select count(*) from auth.users where id='${record}';`),'1')
    assert.equal(sql(`select count(*) from public.st_v2_invites where id='${context.invite}' and status='accepted';`),'1')
  } else if (kind==='group') {
    assert.equal(sql(`select count(*) from public.st_v6_workspace_groups where (workspace_id,id)=('${workspace}','${record}');`),'0')
    assert.equal(sql(`select count(*) from public.st_v6_workspace_group_members
      where (workspace_id,group_id)=('${workspace}','${protectedRecord}');`),'1')
  } else if (kind==='link') {
    assert.equal(sql(`select count(*) from sectalk_private.st_v6_workspace_link_invites where retirement_id='${record}';`),'0')
    assert.equal(sql(`select count(*) from sectalk_private.st_v6_workspace_link_invites
      where retirement_id='${protectedRecord}' and expires_at>now() and consumed_at is null;`),'1')
  } else if (kind==='invitation') {
    assert.equal(sql(`select count(*) from public.st_v2_invites where id='${record}';`),'0')
    assert.equal(sql(`select count(*) from public.st_v2_invites i join public.st_v2_members m
      on (m.workspace_id,m.user_id)=(i.workspace_id,i.invitee)
      where (i.id,i.status)=('${protectedRecord}','accepted');`),'1')
  } else if (kind==='webhook') {
    assert.equal(sql(`select count(*) from sectalk_private.st_v6_webhooks where id='${record}';`),'0')
    assert.equal(sql(`select count(*) from sectalk_private.st_v6_webhook_jobs
      where (endpoint_id,state)=('${protectedRecord}','cancelled');`),'1')
  } else {
    assert.equal(sql(`select count(*) from sectalk_private.st_v6_integration_keys where id='${record}';`),'0')
    assert.equal(sql(`select count(*) from sectalk_private.st_v6_api_rate where key_id='${protectedRecord}';`),'1')
  }
  if (detaching) {
    console.log('PASS withdrawn quote exact independent custody, holds, native quote and events preserved, restrictive reference reduced')
    return
  }
  if (kind==='change') {
    console.log('PASS rejected seat change exact redacted review, native billing evidence and allocation preserved, root dependency count reduced')
    return
  }
  if (kind==='member') {
    assert.equal(sql(`select count(*) from public.st_v2_workspace_audit where (workspace_id,target)=('${workspace}','${record}')
      and event in ('member.invited','member.joined','member.suspend');`),'3')
  } else if (kind==='group') {
    assert.equal(sql(`select count(*) from public.st_v2_workspace_audit where (workspace_id,target)=('${workspace}','${record}')
      and event in ('group.created','group.archive');`),'2')
  } else if (kind==='link') {
    assert.equal(sql(`select count(*) from public.st_v2_workspace_audit where (workspace_id,actor,event)=
      ('${workspace}','${owner}','workspace.link_invited');`),'2')
  } else {
    const auditTarget=kind==='invitation'?context.recipient:record
    const auditEvent=kind==='invitation'?'member.invited':'integration.'+(kind==='webhook'?'webhook':'key')+'_created'
    assert.equal(sql(`select count(*) from public.st_v2_workspace_audit where (workspace_id,target,event)=
      ('${workspace}','${auditTarget}','${auditEvent}');`),'1')
  }
  console.log('PASS '+precise+' exact copy, independent review, hold, native removal, protected evidence, and root dependency count reduced')
}

try {
  const [owner,reviewer]=await Promise.all([account('owner'),account('reviewer')])
  const workspace=data(await owner.client.rpc('st_v2_create_workspace',{p_name:'Disposable workspace source '+suffix}))
  let source=randomUUID(), control=randomUUID()
  let primaryRecipient, linkPrivateValues, membershipContext
  const request=randomUUID(), approval=randomUUID(), hold=randomUUID()
  const historyPosts=sourceKind==='archivedChannelHistory'?[randomUUID(),randomUUID()]:[]
  const replies=sourceKind==='thread'?[randomUUID(),randomUUID()]:[], controlReply=randomUUID()
  const batchPost=batchMode ? randomUUID() : null, batchPostBody='Batch channel source '+suffix
  const container=randomUUID(), title='Exact offboarding source '+suffix, detail='Disposable source body '+suffix
  sql(`insert into public.st_v2_members(workspace_id,user_id,role) values('${workspace}','${reviewer.id}','admin');
    insert into sectalk_private.st_v8_offboarding_reviewers values('${workspace}','${reviewer.id}');`)
  if (membershipSource) {
    const [member,active]=await Promise.all([account('member'),account('active')])
    const invite=async recipient=>{
      assert.equal(data(await owner.client.rpc('st_v2_invite',{
        p_workspace:workspace,p_handle:recipient.email.split('@')[0]})),true)
      const id=sql(`select id from public.st_v2_invites where (workspace_id,invitee)=('${workspace}','${recipient.id}');`)
      assert.equal(data(await recipient.client.rpc('st_v2_reply_invite',{p_invite:id,p_accept:true})),workspace)
      return id
    }
    const targetInvite=await invite(member)
    await invite(active)
    source=member.id
    control=active.id
    membershipContext={invite:targetInvite,privateValues:[member.email]}
  } else if (invitationSource) {
    const [recipient,accepted]=await Promise.all([account('declined'),account('accepted')])
    primaryRecipient=recipient
    for (const invited of [recipient,accepted]) {
      assert.equal(data(await owner.client.rpc('st_v2_invite',{p_workspace:workspace,p_handle:invited.email.split('@')[0]})),true)
    }
    source=sql(`select id from public.st_v2_invites where (workspace_id,invitee)=('${workspace}','${recipient.id}');`)
    control=sql(`select id from public.st_v2_invites where (workspace_id,invitee)=('${workspace}','${accepted.id}');`)
    data(await recipient.client.rpc('st_v2_reply_invite',{p_invite:source,p_accept:false}))
    data(await accepted.client.rpc('st_v2_reply_invite',{p_invite:control,p_accept:true}))
  } else if (expiredLinkSource) {
    const expiredAddress='expired-link-'+suffix+'@example.invalid'
    const issue=async email=>data(await owner.client.rpc('st_v6_workspace_link_create',{
      p_workspace:workspace,p_email:email,p_hours:1}))
    const expired=await issue(expiredAddress), active=await issue('active-link-'+suffix+'@example.invalid')
    const digest=value=>createHash('sha256').update(value).digest('hex')
    const expiredHash=digest(expired.token), activeHash=digest(active.token)
    source=sql(`update sectalk_private.st_v6_workspace_link_invites set expires_at=now()-interval '5 minutes'
      where (workspace_id,token_hash)=('${workspace}',decode('${expiredHash}','hex')) returning retirement_id;`).split(/\r?\n/)[0]
    control=sql(`select retirement_id from sectalk_private.st_v6_workspace_link_invites
      where (workspace_id,token_hash)=('${workspace}',decode('${activeHash}','hex'));`)
    assert.match(source,/^[a-f0-9-]{36}$/)
    linkPrivateValues=[expiredAddress,expired.token,expiredHash]
  } else if (sourceKind === 'archivedRoom') {
    data(await owner.client.rpc('st_v6_room_create',{p_id:source,p_workspace:workspace,p_name:'Disposable archive candidate',p_kind:'public',p_template:'blank'}))
    data(await owner.client.rpc('st_v6_room_create',{p_id:control,p_workspace:workspace,p_name:'Disposable archive with history',p_kind:'public',p_template:'blank'}))
    data(await owner.client.rpc('st_v6_room_post',{p_room:control,p_id:randomUUID(),p_body:'Preserve this archived post.'}))
    for (const room of [source,control]) {
      data(await owner.client.rpc('st_v6_manage_room',{p_room:room,p_action:'archive'}))
    }
  } else if (sourceKind === 'archivedChannel' || sourceKind === 'archivedChannelHistory') {
    source=data(await owner.client.rpc('st_v2_create_channel',{p_workspace:workspace,p_name:'archive-candidate'}))
    control=data(await owner.client.rpc('st_v2_create_channel',{p_workspace:workspace,p_name:'archive-with-history'}))
    sql(`insert into public.st_v2_posts(id,channel_id,sender,body)
      values('${randomUUID()}','${control}','${reviewer.id}','Preserve this archived post.');`)
    for (const id of historyPosts) {
      data(await owner.client.rpc('st_v2_post',{p_channel:source,p_id:id,p_body:'Original archived message '+id}))
      sql(`insert into sectalk_private.st_v7_search_document(kind,object_id,fingerprint,first_terms,second_terms)
        values('channel','${id}',decode(repeat('0',64),'hex'),to_tsvector('synthetic'),to_tsvector('archive'))
        on conflict(kind,object_id) do nothing;`)
    }
    for (const channel of [source,control]) {
      data(await owner.client.rpc('st_v6_manage_channel',{p_channel:channel,p_action:'archive'}))
    }
  } else if (sourceKind === 'post') {
    sql(`insert into public.st_v2_channels(id,workspace_id,name) values('${container}','${workspace}','disposable-posts');
      insert into public.st_v2_posts(id,channel_id,sender,body) values
        ('${source}','${container}','${owner.id}','${detail}'),('${control}','${container}','${owner.id}','Retained fixture');`)
    data(await reviewer.client.rpc('st_v7_submit_channel_report',{p_channel:container,p_post:control,p_category:'spam',
      p_details:'Disposable evidence fixture',p_share_with_safety:true,p_share_with_workspace:true}))
  } else if (roomSource) {
    sql(`insert into public.st_v6_rooms(id,workspace_id,name,kind,template,creator)
        values('${container}','${workspace}','Disposable room','public','blank','${owner.id}');
      insert into public.st_v6_room_members(room_id,user_id,role)
        values('${container}','${owner.id}','owner'),('${container}','${reviewer.id}','moderator');`)
    if (sourceKind === 'roomTask') {
      data(await owner.client.rpc('st_v6_task_create',{p_id:source,p_room:container,p_chat:null,p_title:title}))
      data(await owner.client.rpc('st_v6_task_create',{p_id:control,p_room:container,p_chat:null,p_title:'Retained assignment'}))
      sql(`insert into public.st_v6_task_people(task_id,user_id,kind) values('${control}','${reviewer.id}','assignee');`)
    } else if (sourceKind==='thread') {
      for (const [id,parent] of [[source,null],...replies.map(reply=>[reply,source]),[control,null],[controlReply,control]]) {
        data(await owner.client.rpc('st_v6_room_post',{p_room:container,p_id:id,p_body:'Disposable thread fixture',p_parent:parent}))
      }
      data(await reviewer.client.rpc('st_v6_submit_room_report',{p_room:container,p_post:controlReply,p_category:'spam',
        p_details:'Protected synthetic thread reply',p_share:true}))
    } else {
      sql(`insert into public.st_v6_room_posts(id,room_id,sender,body,kind) values
        ('${source}','${container}','${owner.id}','${detail}','message'),
        ('${control}','${container}','${owner.id}','Retained fixture','message');`)
      data(await reviewer.client.rpc('st_v6_submit_room_report',{p_room:container,p_post:control,p_category:'spam',
        p_details:'Disposable room evidence fixture',p_share:true}))
    }
  } else if (!integrationSource && !groupSource && !quoteSource && !seatChangeSource && !auditCustodySource && !workflowCustodySource && !providerKeySource) {
    sql(`insert into public.st_v2_items(id,workspace_id,kind,created_by,title,details) values
        ('${source}','${workspace}','task','${owner.id}','${title}','${detail}'),
        ('${control}','${workspace}','task','${owner.id}','Control with a checklist','Retained fixture');
      insert into public.st_v4_checklist(task_id,label) values('${control}','Keep this dependency');`)
    if (batchPost) {
      sql(`insert into public.st_v2_channels(id,workspace_id,name) values('${container}','${workspace}','disposable-batch');
        insert into public.st_v2_posts(id,channel_id,sender,body) values ('${batchPost}','${container}','${owner.id}','${batchPostBody}');`)
    }
  }
  if (providerKeySource) {
    sql(`insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values
      ('${owner.id}','enterprise','active',now()+interval '1 day');
      insert into sectalk_private.st_v7_tenant_destroy_reviewers values('${workspace}','${reviewer.id}');`)
  } else {
    sql(`insert into sectalk_private.st_v7_tenant_key_state(workspace,current_version) values('${workspace}',1);
      insert into sectalk_private.st_v7_tenant_key_versions(workspace,version,custody,wrapped) values
      ('${workspace}',1,'managed',repeat('a',80));`)
  }
  const seatCustomer='cus_offboarding_'+suffix
  const seatBase='sub_offboarding_'+suffix
  if (seatChangeSource) {
    sql(`insert into public.st_v2_subscriptions(user_id,plan,status,period_end,customer_id,subscription_id)
      values('${owner.id}','enterprise','active',now()+interval '1 day','${seatCustomer}','${seatBase}');`)
  } else if (quoteSource) {
    sql(`insert into public.st_v2_subscriptions(user_id,plan,status,period_end)
      values('${owner.id}','enterprise','active',now()+interval '1 day');
      insert into sectalk_private.st_v8_enterprise_billing_operators values('${workspace}','${reviewer.id}');`)
  }
  const [requester,judge]=await Promise.all([open(owner,'Organization settings'),open(reviewer,'Compliance exports')])
  let seatContext
  const pins=[]
  if (providerKeySource) {
    for(const version of [1,2]) {
      const pin=randomBytes(32).toString('base64url')
      pins.push(pin)
      const rotation=data(await requester.native.rpc('st_v7_begin_tenant_key_rotation',{
        p_workspace:workspace,p_custody:'byok',p_reason:'Disposable external key marker registration.'}))
      assert.equal(rotation.version,version)
      assert.equal(data(await service.rpc('st_v7_commit_tenant_key_rotation',{p_ticket:rotation.ticket,p_actor:owner.id,
        p_wrapped:'external_v2_'+pin+'_'+randomBytes(32).toString('base64url'),p_ref:'qa_key_'+suffix+'_'+version})),true)
    }
  }
  if (membershipSource) {
    data(await requester.native.rpc('st_v2_set_member',{p_workspace:workspace,p_member:source,p_role:'suspend'}))
  }
  if (seatChangeSource) {
    data(await requester.native.rpc('st_v7_billing_admin_manage',{p_workspace:workspace,p_account:reviewer.id,p_enabled:true}))
    const price='price_offboarding_'+suffix
    const command=async(p_action,p_data)=>data(await service.rpc('st_v8_workspace_seat_command',{
      p_workspace:workspace,p_actor:owner.id,p_action,p_data}))
    const claim=quantity=>command('claim',{quantity,intent:'manual',price})
    const rejected=await claim(3)
    assert.equal(await command('finish',{...rejected,result:'rejected'}),true)
    const settled=await claim(4)
    assert.equal(await command('finish',{...settled,result:'settled',subscription:seatBase+'_seat',
      until:Math.floor(Date.now()/1000)+86400}),true)
    await claim(5)
    source=rejected.id
    control=settled.id
    sql(`update sectalk_private.st_v8_workspace_seat_changes set created_at=now()-interval '10 minutes',
      finished_at=now()-interval '9 minutes',lease_until=now()-interval '8 minutes' where id='${source}';`)
    seatContext={privateValues:[seatCustomer,price,rejected.lease],originalAllocation:await command('status',null)}
  }
  if (quoteSource) {
    const today=new Date().toISOString().slice(0,10)
    const tomorrow=new Date(Date.now()+24*60*60*1000).toISOString().slice(0,10)
    const command=async(actor,id,action,p_data)=>data(await actor.native.rpc('st_v8_enterprise_billing_command',{
      p_workspace:workspace,p_order:id,p_action:action,p_data}))
    for (const [id,reference] of [[source,'Disposable withdrawn quote'],[control,'Disposable accepted control']]) {
      await command(judge,id,'quote',{reference,currency:'USD',seats:3,total:1000,starts:tomorrow,expires:today,
        terms:'Synthetic exact retained quote terms.'})
    }
    await command(judge,source,'withdraw',{reason:'Synthetic withdrawn quote before any acceptance.'})
    await command(requester,control,'accept',{po:'Synthetic active purchase order'})
  }
  if (groupSource) {
    for (const [id,name] of [[source,'Disposable empty group'],[control,'Disposable group with roster']]) {
      data(await requester.native.rpc('st_v6_workspace_group_create',{
        p_workspace:workspace,p_id:id,p_kind:'team',p_name:name,p_description:'Synthetic fixture for archived group cleanup'}))
    }
    data(await requester.native.rpc('st_v6_workspace_group_change',{
      p_workspace:workspace,p_id:control,p_action:'member_added',p_user:reviewer.id}))
    for (const id of [source,control]) {
      data(await requester.native.rpc('st_v6_workspace_group_change',{p_workspace:workspace,p_id:id,p_action:'archive'}))
    }
  }
  let privateValues
  if (integrationSource) {
    sql(`insert into public.st_v2_subscriptions(user_id,plan,status,period_end)
      values('${owner.id}','enterprise','active',now()+interval '1 day');`)
    if (sourceKind==='revokedWebhook') {
      const destination='https://webhook-retirement.example.invalid/private-route'
      const wrapped='q'.repeat(80)
      for (const [id,label] of [[source,'Synthetic staged webhook'],[control,'Synthetic webhook with delivery']]) {
        data(await requester.native.rpc('st_v6_register_webhook',{
          p_workspace:workspace,p_endpoint:id,p_label:label,p_destination:destination,p_wrapped:wrapped,p_topics:['room.created']}))
      }
      sql(`insert into sectalk_private.st_v6_webhook_jobs(endpoint_id,event_id,payload)
        values('${control}','${randomUUID()}','{"type":"synthetic-retained-delivery"}');`)
      privateValues=[destination,wrapped]
    } else {
      const verifier=createHash('sha256').update(randomUUID()).digest('hex')
      const create=async(label,prefix,digest)=>data(await requester.native.rpc('st_v6_create_integration_key',{
        p_workspace:workspace,p_label:label,p_prefix:prefix,p_digest:digest,p_scopes:['workspace:read'],p_lifetime_days:7}))
      source=await create('Synthetic staged API key','retire0000',verifier)
      control=await create('Synthetic key with usage','retain0000',createHash('sha256').update(randomUUID()).digest('hex'))
      sql(`insert into sectalk_private.st_v6_api_rate(key_id,minute,requests)
        values('${control}',date_trunc('minute',now()),1);`)
      privateValues=[verifier,'retire0000']
    }
  }
  const scope={p_workspace:workspace,p_confirmation:workspace}
  const metadata={...scope,p_id:request}
  const content={...scope,p_id:approval}
  data(await requester.native.rpc('st_v8_workspace_offboarding_change',{...metadata,p_action:'requested',p_reason:'Dispose of an exact source in local QA.'}))
  data(await judge.native.rpc('st_v8_workspace_offboarding_change',{...metadata,p_action:'approved'}))
  data(await requester.native.rpc('st_v8_offboarding_content',{...content,p_action:'export_content'}))
  data(await judge.native.rpc('st_v8_offboarding_content',{...content,p_action:'approve'}))
  const caseId=data(await requester.native.rpc('st_v8_workspace_offboarding',{p_workspace:workspace})).request.case
  // The existing offboarding fixture covers actual metadata export downloads. Seed that prerequisite here.
  sql(`insert into sectalk_private.st_v7_compliance_audit(case_id,workspace_id,actor,action)
    values('${caseId}','${workspace}','${owner.id}','downloaded');`)
  data(await requester.native.rpc('st_v8_workspace_offboarding_change',{...metadata,p_action:'read_only'}))
  for (const view of [requester,judge]) await button(view.panel,'Refresh offboarding status').click()
  if (reconciliationMode) await verifyReconciliation(requester,judge,workspace)
  else if (rootReconciliationMode) await verifyRootReconciliation(requester,judge,workspace,owner.id)
  else if (auditCustodySource) await verifyAuditCustody(requester,judge,workspace,hold,owner.id)
  else if (workflowCustodySource) await verifyWorkflowCustody(requester,judge,workspace,request,caseId)
  else if (providerKeySource) await verifyProviderKeyRetirement(requester,judge,workspace,request,reviewer.id,pins)
  else if (membershipSource) {
    const direct=await requester.native.rpc('st_v2_set_member',{p_workspace:workspace,p_member:control,p_role:'remove'})
    assert.equal(direct.error?.code,'PT423')
    await verifyReviewedRemoval(requester,judge,workspace,source,control,hold,owner.id,'member',membershipContext)
  }
  else if (seatChangeSource) await verifyReviewedRemoval(requester,judge,workspace,source,control,hold,owner.id,'change',seatContext)
  else if (quoteSource) await verifyReviewedRemoval(requester,judge,workspace,source,control,hold,owner.id,'order',{privateValues:[]})
  else if (groupSource) await verifyReviewedRemoval(requester,judge,workspace,source,control,hold,owner.id,'group',{privateValues:[]})
  else if (expiredLinkSource) await verifyReviewedRemoval(requester,judge,workspace,source,control,hold,owner.id,'link',
    {privateValues:linkPrivateValues})
  else if (integrationSource || invitationSource) {
    const kind=invitationSource?'invitation':sourceKind==='revokedWebhook'?'webhook':'api-key'
    const context=invitationSource?{recipient:primaryRecipient.id,privateValues:[primaryRecipient.email]}:{privateValues}
    await verifyReviewedRemoval(requester,judge,workspace,source,control,hold,owner.id,kind,context)
  }
  else if (sourceKind==='archivedChannel' || sourceKind==='archivedChannelHistory' || sourceKind==='archivedRoom') {
    const kind=sourceKind==='archivedRoom'?'room':'channel'
    await verifyArchivedStructure(requester,judge,workspace,source,control,hold,owner.id,kind,historyPosts)
    if (archiveReconciliationMode) await verifyArchiveReconciliation(requester,judge,workspace,kind,historyPosts)
  }
  else if (sourceKind==='thread') await verifyThread(requester,judge,{workspace,root:source,replies,control,controlReply,hold,owner:owner.id})
  else {
    const ownerPanel=requester.sourcePanel, reviewerPanel=judge.sourcePanel
    const selection=ownerPanel.getByLabel('Approved '+sourceLabel,{exact:true})
    await selection.selectOption(source)
    assert.equal(await selection.locator('option[value="'+control+'"]').count(),0)
    const downloadEvent=requester.page.waitForEvent('download')
    await ownerPanel.getByLabel('Confirm '+sourceLabel+' offboarding workspace ID').fill(workspace)
    await button(ownerPanel,'Download approved '+sourceLabel+' copy').click()
    const download=await downloadEvent
    assert.equal(download.suggestedFilename(),'sectalk-approved-'+sourceLabel.replace(' ','-')+'-'+source+'.json')
    const copy=JSON.parse(await readFile(await download.path(),'utf8'))
    assert.equal(JSON.parse(copy.json)[archiveField],sourceKind === 'roomTask' ? title : detail)
    if (roomSource) assert.equal(JSON.parse(copy.json).room,container)
    assert.equal(createHash('sha256').update(copy.json).digest('hex'),copy.sha256)
    if (sourceKind === 'roomTask') {
      assert.equal(JSON.parse(copy.sourceJson).id,source)
      assert.equal(JSON.parse(copy.creationAuditJson).task_id,source)
      assert.equal(createHash('sha256').update(copy.sourceJson).digest('hex'),copy.sourceSha256)
      assert.equal(createHash('sha256').update(copy.creationAuditJson).digest('hex'),copy.creationAuditSha256)
    }
    if (batchPost) await verifyBatch(requester,judge,workspace,source,batchPost,control,batchPostBody)
    else {
      await button(ownerPanel,'Prepare exact '+sourceLabel+' deletion plan').waitFor()
      await ownerPanel.getByLabel('Confirm '+sourceLabel+' offboarding workspace ID').fill(workspace)
      await button(ownerPanel,'Prepare exact '+sourceLabel+' deletion plan').click()
      await ownerPanel.getByText('Awaiting independent deletion approval',{exact:true}).waitFor()
      assert.equal(await button(ownerPanel,'Permanently delete approved '+sourceLabel).count(),0)
      await button(reviewerPanel,'Refresh '+sourceLabel+' deletion status').click()
      if (roomSource) await reviewerPanel.getByText('Room ID '+container,{exact:true}).waitFor()
      await reviewerPanel.getByLabel('Confirm review workspace ID').fill(workspace)
      await button(reviewerPanel,'Approve exact '+sourceLabel+' deletion').click()
      await reviewerPanel.getByText('Exact '+sourceLabel+' deletion plan approved.',{exact:true}).waitFor()
      await button(ownerPanel,'Refresh '+sourceLabel+' deletion status').click()
      await ownerPanel.getByText('Independently approved',{exact:true}).waitFor()

      sql(`insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
        values('${hold}','${workspace}','${owner.id}','Preserve disposable records for scoped verification.','${owner.id}');`)
      await button(ownerPanel,'Refresh '+sourceLabel+' deletion status').click()
      await ownerPanel.getByText('Active preservation holds block '+sourceLabel+' deletion.',{exact:true}).waitFor()
      assert.equal(await ownerPanel.getByText('Permanently delete this workspace '+sourceLabel,{exact:true}).count(),0)
      sql(`update sectalk_private.st_v6_workspace_holds set released_at=now(),released_by='${owner.id}',
        release_reason='Release the disposable hold for the deletion fixture.' where id='${hold}';`)
      await button(ownerPanel,'Refresh '+sourceLabel+' deletion status').click()
      await ownerPanel.getByText('Permanently delete this workspace '+sourceLabel,{exact:true}).click()
      await ownerPanel.getByLabel('Confirm deletion workspace ID').fill(workspace)
      await ownerPanel.getByLabel('Confirm deletion '+sourceLabel+' ID').fill(control)
      await ownerPanel.getByRole('checkbox',{name:/I retained the approved copy/}).check()
      await button(ownerPanel,'Permanently delete approved '+sourceLabel).click()
      await ownerPanel.getByRole('alert').getByText('Enter the exact '+sourceLabel+' ID to confirm permanent deletion.').waitFor()
      await ownerPanel.getByLabel('Confirm deletion '+sourceLabel+' ID').fill(source)
      await button(ownerPanel,'Permanently delete approved '+sourceLabel).click()
      await ownerPanel.getByText('Permanently deleted from the live source',{exact:true}).waitFor()
      const sourceScope=roomSource ? ` and room_id='${container}'` : ''
      assert.equal(sql(`select id from public.${sourceTable} where id in ('${source}','${control}')${sourceScope};`),control)
      const sourceKey=sourceKind === 'task' || sourceKind === 'roomTask' ? 'task' : 'post'
      assert.equal(sql(`select count(*) from sectalk_private.st_v8_offboarding_${auditScope}_decisions d
        join sectalk_private.st_v8_offboarding_${auditScope}_deletions p on p.id=d.deletion where p.${sourceKey}='${source}';`),'2')
      if (sourceKind === 'roomTask') {
        assert.equal(sql(`select a.sha256 from sectalk_private.st_v8_offboarding_retained_task_creation a
          join sectalk_private.st_v8_offboarding_room_task_deletions p on p.id=a.deletion where p.task='${source}';`),
        copy.creationAuditSha256)
        assert.equal(sql(`select count(*) from public.st_v6_task_people where task_id='${control}' and user_id='${reviewer.id}';`),'1')
      }
      console.log('PASS offboarding '+sourceLabel+' copy download, independent approval, hold pause, exact terminal confirmation and live deletion')
    }
  }
} finally {await browser.close()}
