import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { setTimeout } from 'node:timers/promises'
import { createClient } from '@supabase/supabase-js'
import { fixtureAuthenticator, verifyStaffPanel } from './workspace-admin-fixture.mjs'

const origin = new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
const app = new URL(process.env.SECTALK_STORAGE_TEST_APP).origin
assert.equal(origin,'http://127.0.0.1:55321')
assert.equal(new URL(app).hostname,'127.0.0.1')
const key = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const options = { auth:{persistSession:false,autoRefreshToken:false} }
const service = createClient(origin,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const run = randomUUID().slice(0,8)
const password = randomUUID() + '!1A'
const users = []
const rules = []
const file = randomUUID()
let browser,chat
function data(result) {
  if (result.error) throw result.error
  return result.data
}
function sql(statement) {
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true}).trim()
}
async function account(role) {
  const handle = 'tq_' + role + '_' + run
  const email = handle + '@example.invalid'
  const { user } = data(await service.auth.admin.createUser({email,password,email_confirm:true}))
  users.push(user.id)
  const client = createClient(origin,key,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:'Threat QA ' + role}))
  return {id:user.id,email,handle,client}
}
async function poll(check) {
  for (let attempt=0;attempt<24;attempt++) {
    const result = await check()
    if (result) return result
    await setTimeout(150)
  }
  assert.fail('The live source did not reach the threat queue')
}
function observedCount() {
  return Number(sql("select coalesce(sum(client_errors),0) from sectalk_private.st_v6_operation_rollups where operation='call_ice';"))
}
async function realSignal() {
  const before = observedCount()
  assert.equal((await fetch(app + '/api/ice?call=' + randomUUID(),{signal:AbortSignal.timeout(10000)})).status,401)
  await poll(() => observedCount()>before)
}
const nav = page => page.getByRole('navigation',{name:'SecTalk features'})
const panel = page => page.getByRole('region',{name:'Threat triage',exact:true})
const item = (page,id) => panel(page).locator('[data-threat-id="' + id + '"]')
async function open(page,actor) {
  await page.goto(app)
  await page.getByLabel('Email address',{exact:true}).fill(actor.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await nav(page).getByRole('button',{name:'Safety',exact:true}).click()
  await page.getByRole('group',{name:'Safety center sections'}).getByRole('button',{name:'Threat triage',exact:true}).click()
  await verifyStaffPanel(page)
  await panel(page).waitFor()
  const token = await page.evaluate(() => {
    const localKey = Object.keys(localStorage).find(key => /^sb-.+-auth-token$/.test(key))
    return JSON.parse(localStorage.getItem(localKey)).access_token
  })
  return createClient(origin,key,{...options,global:{headers:{Authorization:'Bearer ' + token}}})
}
async function filters(page,values) {
  const form = panel(page).getByRole('form',{name:'Threat filters',exact:true})
  for (const [label,value] of Object.entries(values)) await form.getByLabel(label,{exact:true}).selectOption(value)
  await form.getByRole('button',{name:'Apply threat filters',exact:true}).click()
}
async function triage(page,ids,action,reason) {
  for (const id of ids) await item(page,id).getByRole('checkbox',{name:'Select for triage',exact:true}).check()
  const form = panel(page).getByRole('form',{name:'Bulk triage',exact:true})
  await form.getByLabel('Bulk decision',{exact:true}).selectOption(action)
  await form.getByLabel('Triage reason',{exact:true}).fill(reason)
  await form.getByRole('button',{name:'Apply bulk triage',exact:true}).click()
  await panel(page).getByText(ids.length===1 ? 'Triage decision applied to 1 item.' :
    'Triage decision applied to ' + ids.length + ' items.',{exact:true}).waitFor()
}

try {
  const [operator,reviewer,inspection,ordinary] = await Promise.all(['operator','reviewer','inspection','ordinary'].map(account))
  sql("insert into sectalk_private.st_v7_detection_operators values('" + operator.id + "');"
    + "insert into sectalk_private.st_v7_threat_reviewers values('" + reviewer.id + "','detection'),('"
    + inspection.id + "','attachment_inspection'); insert into sectalk_private.staff values('" + ordinary.id + "');")
  assert.deepEqual(data(await reviewer.client.rpc('st_v7_threat_triage_access')),{status:'mfa'})
  assert.deepEqual(data(await ordinary.client.rpc('st_v7_threat_triage_access')),{status:'none'})
  assert.equal((await ordinary.client.rpc('st_v7_threat_queue')).error?.code,'42501')
  await fixtureAuthenticator(operator.client)
  assert.deepEqual(data(await operator.client.rpc('st_v7_threat_triage_access')),{status:'none'})
  for (const suffix of ['first','second']) {
    const id = data(await operator.client.rpc('st_v7_save_detection_rule',{
      p_rule:null,p_expected:null,p_label:'Triage integration ' + run + ' ' + suffix,
      p_source:'operations',p_scope:'call_ice',p_metric:'client_errors',p_threshold:1,
    }))
    rules.push(id)
    data(await operator.client.rpc('st_v7_test_detection_rule',{p_rule:id,p_version:1}))
    data(await operator.client.rpc('st_v7_deploy_detection_rule',{
      p_rule:id,p_version:1,p_action:'shadow',p_reason:'QA sandbox preview for deterministic operation counters.',
    }))
  }
  const ids = rules.map(id => "'" + id + "'").join(',')
  const detectedItems = () => sql("select q.id from sectalk_private.st_v7_threat_items q join sectalk_private.st_v7_detection_matches m"
    + " on q.signal_type='detection' and q.source_key=m.id::text where m.rule_id in (" + ids + ") order by q.id;").split(/\r?\n/).filter(Boolean)
  await realSignal()
  await poll(() => Number(sql("select count(*) from sectalk_private.st_v7_detection_matches where rule_id in ("+ids+") and mode='shadow';"))===2)
  assert.deepEqual(detectedItems(),[])
  for (const id of rules) data(await operator.client.rpc('st_v7_deploy_detection_rule',{
    p_rule:id,p_version:1,p_action:'enabled',p_reason:'QA enable after live test of scoped shadow behavior.',
  }))

  chat = data(await ordinary.client.rpc('st_request',{p_handle:reviewer.handle}))
  data(await reviewer.client.rpc('st_respond',{p_chat:chat,p_accept:true}))
  const bytes = Buffer.from('A literal <script> marker printed as text in a harmless QA attachment.')
  data(await ordinary.client.rpc('st_v5_stage_file',{p_chat:chat,p_id:file,p_filename:'fixture.txt',p_bytes:bytes.length}))
  const bearer = data(await ordinary.client.auth.getSession()).session.access_token
  const fileHeaders = {Authorization:'Bearer ' + bearer}
  const uploaded = await fetch(app+'/api/files/upload?file='+file,{method:'POST',
    headers:{...fileHeaders,'Content-Type':'text/plain'},body:bytes,signal:AbortSignal.timeout(10000)})
  assert.equal(uploaded.status,200,uploaded.ok?'':await uploaded.text())
  const published = await fetch(app+'/api/files/publish',{method:'POST',headers:{...fileHeaders,'Content-Type':'application/json'},
    body:JSON.stringify({file,caption:'Benign QA fixture',mime:'text/plain'}),signal:AbortSignal.timeout(10000)})
  assert.equal(published.status,423,await published.text())
  const scanId = sql("select id from sectalk_private.st_v7_threat_items where signal_type='attachment_inspection' and source_key='" + file + "';")
  assert.match(scanId,/^[0-9a-f-]{36}$/)
  browser = await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const [reviewPage,scanPage] = await Promise.all([browser.newPage(),browser.newPage()])
  const [reviewApi,scanApi] = await Promise.all([open(reviewPage,reviewer),open(scanPage,inspection)])
  await filters(reviewPage,{'Signal type':'detection','Severity':'medium','Signal confidence':'supported','Triage status':'open'})
  await filters(scanPage,{'Signal type':'attachment_inspection','Severity':'medium','Signal confidence':'heuristic'})
  await item(scanPage,scanId).getByText('Script marker',{exact:true}).waitFor()
  assert.deepEqual(data(await scanApi.from('st_v5_files').select('id').eq('id',file)),[])
  assert.equal(await panel(reviewPage).getByRole('option',{name:'Attachment inspection',exact:true}).count(),0)
  await realSignal()
  const classified = await poll(() => {const current=detectedItems();return current.length===2 ? current : false})
  for (const id of classified) await item(reviewPage,id).getByText(/Direct call networking.*Client errors/).waitFor()
  const ownRows = data(await reviewApi.rpc('st_v7_threat_queue'))
  assert.ok(ownRows.every(row => row.signal_type==='detection' && !('source_key' in row)))
  assert.equal(data(await scanApi.rpc('st_v7_threat_triage_history',{p_item:classified[0]})).length,0)
  const sourceRow = data(await scanApi.rpc('st_v7_threat_queue')).find(row => row.id===scanId)
  assert.deepEqual(sourceRow.details,{signal:'script_marker'})
  assert.ok(!JSON.stringify(sourceRow).includes(file))
  assert.equal((await reviewApi.rpc('st_v7_apply_threat_triage',{
    p_items:[{id:classified[0],revision:1},{id:scanId,revision:1}],p_action:'dismissed',
    p_reason:'Check atomic rollback for an off-scope mixed selection.',
  })).error?.code,'42501')
  assert.equal(sql("select revision from sectalk_private.st_v7_threat_items where id='" + classified[0] + "';"),'1')
  const reviewReason = 'Two scoped signals were checked against the actual operation counter.'
  await triage(reviewPage,classified,'reviewing',reviewReason)
  await filters(reviewPage,{'Triage status':'reviewing'})
  await item(reviewPage,classified[0]).getByText('Triage history',{exact:true}).click()
  await item(reviewPage,classified[0]).getByText(reviewReason,{exact:true}).waitFor()
  assert.equal((await reviewApi.rpc('st_v7_apply_threat_triage',{
    p_items:[{id:classified[0],revision:1}],p_action:'dismissed',p_reason:'Check stale queue revision rejection.',
  })).error?.code,'PT409')
  await triage(reviewPage,classified,'confirmed','Both observed alerts were confirmed during the human review.')
  await triage(scanPage,[scanId],'dismissed','This literal marker in harmless plain text does not merit further triage.')
  assert.equal(sql("select state from sectalk_private.st_v6_attachment_scans where file_id='" + file + "';"),'quarantined')
  assert.equal(sql("select message_id is null from public.st_v5_files where id='" + file + "';"),'t')
  assert.equal(sql("select count(distinct batch_id) from sectalk_private.st_v7_threat_triage_audit where action='reviewing'"
    + " and item_id in ('" + classified.join("','") + "');"),'1')
} finally {
  await browser?.close()
  await service.storage.from('sectalk-chat-files').remove([file])
  const owned = rules.length ? rules.map(id => "'" + id + "'").join(',') : 'null'
  const fixtureItems = "select q.id from sectalk_private.st_v7_threat_items q where q.source_key='"+file+"' or"
    + " (q.signal_type='detection' and q.source_key in (select m.id::text from sectalk_private.st_v7_detection_matches m where m.rule_id in ("+owned+")))"
  sql("begin; set local session_replication_role=replica; delete from sectalk_private.st_v7_threat_triage_audit where item_id in ("+fixtureItems+");"
    + " delete from sectalk_private.st_v7_threat_items where id in ("+fixtureItems+");"
    + " delete from sectalk_private.st_v7_detection_matches where rule_id in ("+owned+");"
    + " delete from sectalk_private.st_v7_detection_audit where rule_id in ("+owned+");"
    + " delete from sectalk_private.st_v7_detection_versions where rule_id in ("+owned+");"
    + " delete from sectalk_private.st_v7_detection_rules where id in ("+owned+"); commit;")
  if (chat) sql("delete from public.st_v5_files where id='"+file+"'; delete from public.st_chats where id='"+chat+"';")
  for (const id of users) sql("delete from sectalk_private.staff where user_id='"+id+"'; delete from auth.users where id='"+id+"';")
}
console.log('Passed live enabled detections and actual attachment inspection, scoped reviewer views, filters, reasoned bulk actions, stale/foreign rejection and durable audit.')
