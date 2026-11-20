import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { setTimeout } from 'node:timers/promises'
import { createClient } from '@supabase/supabase-js'
import { verifyStaffPanel } from './workspace-admin-fixture.mjs'

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
let browser,rule
function data(result) {
  if (result.error) throw result.error
  return result.data
}
function sql(statement) {
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true}).trim()
}
async function account(role) {
  const handle = 'pb_' + role + '_' + run
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
const playback = page => page.getByRole('region',{name:'Threat playbooks',exact:true})
const workflowName = 'Review routine ' + run
const evidence = 'Reviewed the bounded workflow and signal metadata.'
let playbook,signalId,requestId

try {
  const [author,approver,outsider] = await Promise.all(['author','approver','outside'].map(account))
  sql(`insert into sectalk_private.st_v7_detection_operators values('${author.id}');
    insert into sectalk_private.st_v7_threat_reviewers values
      ('${author.id}','detection'),('${approver.id}','detection'),('${outsider.id}','attachment_inspection');
    insert into sectalk_private.st_v7_playbook_grants values
      ('${author.id}','detection','author'),('${author.id}','detection','approver'),
      ('${approver.id}','detection','approver'),('${outsider.id}','attachment_inspection','approver');`)
  browser = await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const authorPage = await browser.newPage()
  const approverPage = await browser.newPage()
  const outsidePage = await browser.newPage()
  const authorApi = await open(authorPage,author)
  rule = data(await authorApi.rpc('st_v7_save_detection_rule',{
    p_rule:null,p_expected:null,p_label:'Playbook signal ' + run,
    p_source:'operations',p_scope:'call_ice',p_metric:'client_errors',p_threshold:1,
  }))
  data(await authorApi.rpc('st_v7_test_detection_rule',{p_rule:rule,p_version:1}))
  for (const mode of ['shadow','enabled']) data(await authorApi.rpc('st_v7_deploy_detection_rule',{
    p_rule:rule,p_version:1,p_action:mode,p_reason:evidence,
  }))
  await realSignal()
  signalId = await poll(() => sql(`select q.id from sectalk_private.st_v7_threat_items q
    join sectalk_private.st_v7_detection_matches m on q.signal_type='detection' and q.source_key=m.id::text
    where m.rule_id='${rule}' and m.mode='enabled' order by q.detected_at desc limit 1;`))

  await item(authorPage,signalId).waitFor()
  const authorPanel = playback(authorPage)
  await authorPanel.getByLabel('Playbook name',{exact:true}).fill(workflowName)
  await authorPanel.getByLabel('Move the signal to Reviewing',{exact:true}).check()
  await authorPanel.getByLabel('Verify the signal',{exact:true}).check()
  await authorPanel.getByRole('button',{name:'Save playbook version',exact:true}).click()
  await authorPanel.getByText('Playbook version saved.',{exact:true}).waitFor()
  playbook = await authorPanel.getByLabel('Playbook version to edit').inputValue()
  assert.match(playbook,/^[a-f0-9-]{36}$/)
  await authorPanel.getByLabel('Playbook to simulate').selectOption(playbook)
  await authorPanel.getByLabel('Signal to simulate').selectOption(signalId)
  await authorPanel.getByRole('button',{name:'Simulate on signal',exact:true}).click()
  await authorPanel.getByRole('heading',{name:workflowName + ' · Version 1 simulation',exact:true}).waitFor()
  assert.equal(sql(`select count(*) from sectalk_private.st_v7_playbook_runs where playbook='${playbook}';`),'0')
  await authorPanel.getByRole('button',{name:'Request playbook approval',exact:true}).click()
  await authorPanel.getByText('Approval requested.',{exact:true}).waitFor()
  requestId = sql(`select id from sectalk_private.st_v7_playbook_runs where playbook='${playbook}';`)
  const runCard = page => playback(page).locator('[data-playbook-run="' + requestId + '"]')
  await runCard(authorPage).getByText(/Awaiting approval/).waitFor()
  assert.equal(await runCard(authorPage).getByRole('button',{name:'Apply playbook decision'}).count(),0)
  assert.equal((await authorApi.rpc('st_v7_decide_playbook',{p_run:requestId,p_approve:true,p_reason:evidence})).error?.code,'42501')
  assert.equal(sql(`select state from sectalk_private.st_v7_threat_items where id='${signalId}';`),'open')

  await authorPanel.getByLabel('Verify the signal',{exact:true}).uncheck()
  await authorPanel.getByLabel('Document the review findings',{exact:true}).check()
  await authorPanel.getByRole('button',{name:'Save playbook version',exact:true}).click()
  await authorPanel.getByRole('option',{name:workflowName + ' · version 2',exact:true}).first().waitFor({state:'attached'})

  const approverApi = await open(approverPage,approver)
  const outsiderApi = await open(outsidePage,outsider)
  await playback(outsidePage).getByRole('button',{name:'Refresh playbook requests'}).waitFor()
  assert.equal(await runCard(outsidePage).count(),0)
  assert.deepEqual(data(await outsiderApi.rpc('st_v7_playbook_runs',{p_item:signalId})),[])
  assert.equal((await outsiderApi.rpc('st_v7_decide_playbook',{p_run:requestId,p_approve:true,p_reason:evidence})).error?.code,'42501')

  const pending = runCard(approverPage)
  await pending.getByRole('heading',{name:workflowName + ' · Version 1',exact:true}).waitFor()
  await pending.getByText('Verify the signal',{exact:true}).waitFor()
  assert.equal(await pending.getByText('Document the review findings',{exact:true}).count(),0)
  await pending.getByLabel('Playbook decision',{exact:true}).selectOption('approve')
  await pending.getByLabel('Playbook decision reason',{exact:true}).fill(evidence)
  await pending.getByRole('button',{name:'Apply playbook decision',exact:true}).click()
  await pending.getByText(/Executed/).waitFor()
  const complete = pending.getByRole('button',{name:'Complete verify the signal',exact:true})
  await complete.click()
  await pending.getByText('Verify the signal · Completed',{exact:true}).waitFor()
  assert.equal(data(await approverApi.rpc('st_v7_decide_playbook',{p_run:requestId,p_approve:true,p_reason:evidence})),'executed')
  const status = panel(approverPage).getByLabel('Triage status')
  await status.selectOption('reviewing')
  await panel(approverPage).getByRole('button',{name:'Apply threat filters'}).click()
  await item(approverPage,signalId).getByText(/Reviewing/).waitFor()
  await item(approverPage,signalId).getByText('Triage history',{exact:true}).click()
  await item(approverPage,signalId).getByText(evidence,{exact:true}).waitFor()
  assert.equal(sql(`select count(*) from sectalk_private.st_v7_playbook_effects where run='${requestId}' and actor='${approver.id}';`),'2')
  assert.equal(sql(`select count(*) from sectalk_private.st_v7_playbook_checklist_status where run='${requestId}' and actor='${approver.id}';`),'1')
} finally {
  await browser?.close()
  const checks = []
  if (playbook) checks.push(`
    delete from sectalk_private.st_v7_playbook_checklist_status where run in (select id from sectalk_private.st_v7_playbook_runs where playbook='${playbook}');
    delete from sectalk_private.st_v7_playbook_effects where run in (select id from sectalk_private.st_v7_playbook_runs where playbook='${playbook}');
    delete from sectalk_private.st_v7_playbook_runs where playbook='${playbook}';
    delete from sectalk_private.st_v7_playbook_versions where playbook='${playbook}';
    delete from sectalk_private.st_v7_playbooks where id='${playbook}';`)
  if (rule) {
    const matched = `select id::text from sectalk_private.st_v7_detection_matches where rule_id='${rule}'`
    checks.push(`
      delete from sectalk_private.st_v7_threat_triage_audit where item_id in
        (select id from sectalk_private.st_v7_threat_items where signal_type='detection' and source_key in (${matched}));
      delete from sectalk_private.st_v7_threat_items where signal_type='detection' and source_key in (${matched});
      delete from sectalk_private.st_v7_detection_matches where rule_id='${rule}';
      delete from sectalk_private.st_v7_detection_audit where rule_id='${rule}';
      delete from sectalk_private.st_v7_detection_versions where rule_id='${rule}';
      delete from sectalk_private.st_v7_detection_rules where id='${rule}';`)
  }
  if (checks.length) sql('begin; set local session_replication_role=replica;' + checks.join('') + 'commit;')
  for (const id of users) data(await service.auth.admin.deleteUser(id))
}
console.log('Passed live signal, browser simulation, immutable version review, independent approval, scoped denial and idempotent workflow effects.')
