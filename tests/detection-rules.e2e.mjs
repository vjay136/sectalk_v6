import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { setTimeout } from 'node:timers/promises'
import { createClient } from '@supabase/supabase-js'
import { verifyStaffPanel } from './workspace-admin-fixture.mjs'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP).origin
const origin = new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
assert.equal(new URL(app).hostname,'127.0.0.1')
assert.equal(origin,'http://127.0.0.1:55321')
const key = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const opts = { auth:{ persistSession:false,autoRefreshToken:false } }
const admin = createClient(origin,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,opts)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const password = randomUUID() + '!1Q'
const suffix = randomUUID().slice(0,8)
const label = 'Detection QA ' + suffix
const users = []
let browser
function data(result) {
  if (result.error) throw result.error
  return result.data
}
function sql(statement) {
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true}).trim()
}
async function account(role) {
  const handle = 'dr_' + role + '_' + suffix
  const email = handle + '@example.invalid'
  const { user } = data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  users.push(user.id)
  const client = createClient(origin,key,opts)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:'Detection QA ' + role}))
  return {id:user.id,email,client}
}
function countErrors() {
  return Number(sql("select coalesce(sum(client_errors),0) from sectalk_private.st_v6_operation_rollups"
    + " where operation='call_ice';"))
}
async function realSignal() {
  const prior = countErrors()
  const response = await fetch(app + '/api/ice?call=' + randomUUID(),{signal:AbortSignal.timeout(10000)})
  assert.equal(response.status,401)
  for (let attempt=0;attempt<25;attempt++) {
    if (countErrors()>prior) return
    await setTimeout(150)
  }
  assert.fail('Actual call-setup request was not recorded by the production metric producer')
}
async function action(card,name) {
  await card.getByRole('button',{name,exact:true}).click()
  await card.getByLabel('Deployment reason',{exact:true}).fill('QA reviewed scope and version for the ' + name + ' action.')
  const result = card.page().waitForResponse(response => response.url().endsWith('/rpc/st_v7_deploy_detection_rule'))
  await card.getByRole('button',{name:'Confirm ' + name.toLowerCase(),exact:true}).click()
  const response = await result
  assert.ok(response.ok(),response.ok() ? '' : await response.text())
}
async function test(card) {
  await card.getByRole('button',{name:'Test against recent windows',exact:true}).click()
  await card.getByText(/Recorded windows \d+ · Matched windows \d+/).waitFor()
}

try {
  const [operator,outsider] = await Promise.all([account('operator'),account('other')])
  sql("insert into sectalk_private.st_v7_detection_operators values('" + operator.id + "');"
    + "insert into sectalk_private.staff values('" + outsider.id + "');")
  assert.equal(data(await operator.client.rpc('st_v7_detection_rule_access')),'mfa')
  assert.equal(data(await outsider.client.rpc('st_v7_detection_rule_access')),'none')
  assert.equal((await outsider.client.rpc('st_v7_detection_rules')).error?.code,'42501')
  assert.ok((await outsider.client.rpc('st_v6_record_operational_metrics',{p_samples:[]})).error)
  await realSignal()

  browser = await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const page = await browser.newPage()
  await page.goto(app)
  await page.getByLabel('Email address',{exact:true}).fill(operator.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Safety',exact:true}).click()
  await page.getByRole('group',{name:'Safety center sections'}).getByRole('button',{name:'Detection rules',exact:true}).click()
  await verifyStaffPanel(page)
  const panel = page.getByRole('region',{name:'Detection rules',exact:true})
  await panel.getByText('Create a detection rule',{exact:true}).click()
  const create = panel.getByRole('form',{name:'New detection rule',exact:true})
  await create.getByLabel('Rule name',{exact:true}).fill(label)
  await create.getByLabel('Operation',{exact:true}).selectOption('call_ice')
  await create.getByLabel('Metric',{exact:true}).selectOption('client_errors')
  await create.getByLabel('Threshold per 5 minutes',{exact:true}).fill('1')
  await create.getByRole('button',{name:'Create rule',exact:true}).click()
  const card = panel.getByRole('article').filter({has:page.getByRole('heading',{name:label,exact:true})})
  await card.getByText('No active version',{exact:true}).waitFor()
  assert.equal(await card.getByRole('button',{name:'Enable version',exact:true}).count(),0)
  await test(card)
  await card.getByText(/Matched windows [1-9]/).waitFor()
  await action(card,'Run in shadow')
  await card.getByText('Shadow · Version 1',{exact:true}).waitFor()
  const hits = card.getByRole('region',{name:'Detection matches'})
  assert.equal(await hits.getByText('Shadow match',{exact:true}).count(),0)
  await realSignal()
  await hits.getByText('Shadow match',{exact:true}).waitFor()
  await action(card,'Enable version')
  await card.getByText('Enabled · Version 1',{exact:true}).waitFor()
  assert.equal(await hits.getByText('Enabled match',{exact:true}).count(),0)
  await realSignal()
  await hits.getByText('Enabled match',{exact:true}).waitFor()

  await card.getByText('Draft a new version',{exact:true}).click()
  const draft = card.getByRole('form',{name:'New detection version',exact:true})
  await draft.getByLabel('Threshold per 5 minutes',{exact:true}).fill('1000000')
  await draft.getByRole('button',{name:'Save draft version',exact:true}).click()
  const version = card.getByLabel('Rule version',{exact:true})
  await version.getByRole('option',{name:'Version 2',exact:true}).waitFor({state:'attached'})
  assert.equal(await version.inputValue(),'2')
  await card.getByText('Enabled · Version 1',{exact:true}).waitFor()
  await test(card)
  await card.getByText(/Matched windows 0/).waitFor()
  await action(card,'Run in shadow')
  await card.getByText('Shadow · Version 2',{exact:true}).waitFor()
  await version.selectOption('1')
  await action(card,'Restore previous version')
  await card.getByText('Enabled · Version 1',{exact:true}).waitFor()
  await realSignal()
  await hits.getByText('Enabled match',{exact:true}).nth(1).waitFor()
  await action(card,'Pause detection')
  await card.getByText('No active version',{exact:true}).waitFor()
  await realSignal()
  await card.getByText('Rule history',{exact:true}).click()
  await card.getByText(/rollback · Version 1/).waitFor()
  const activity = sql("select string_agg(a.action,',' order by a.id) from sectalk_private.st_v7_detection_audit a"
    + " join sectalk_private.st_v7_detection_rules r on r.id=a.rule_id where r.label='" + label + "';")
  assert.equal(activity,'created,tested,shadow,enabled,revised,tested,shadow,rollback,paused')
  assert.equal(sql("select count(*) from sectalk_private.st_v7_detection_matches m join sectalk_private.st_v7_detection_rules r"
    + " on r.id=m.rule_id where r.label='" + label + "' and m.version=2;"),'0')
} finally {
  await browser?.close()
  sql("begin; set local session_replication_role=replica;"
    + " delete from sectalk_private.st_v7_detection_matches where rule_id in (select id from sectalk_private.st_v7_detection_rules where label='" + label + "');"
    + " delete from sectalk_private.st_v7_detection_audit where rule_id in (select id from sectalk_private.st_v7_detection_rules where label='" + label + "');"
    + " delete from sectalk_private.st_v7_detection_versions where rule_id in (select id from sectalk_private.st_v7_detection_rules where label='" + label + "');"
    + " delete from sectalk_private.st_v7_detection_rules where label='" + label + "'; commit;")
  for (const user of users) sql("delete from sectalk_private.staff where user_id='" + user + "'; delete from auth.users where id='" + user + "';")
}
console.log('Passed Edge rule creation, immutable draft, historical test, live app metrics shadow and enable, rollback, pause and durable history.')
