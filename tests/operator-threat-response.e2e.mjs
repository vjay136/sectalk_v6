import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { fixtureAuthenticator, totpCode } from './workspace-admin-fixture.mjs'

const app=new URL(process.env.SECTALK_STORAGE_TEST_APP)
const db=new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname,'127.0.0.1')
assert.equal(db.origin,'http://127.0.0.1:55321')
const options={auth:{persistSession:false,autoRefreshToken:false}}
const service=createClient(db.origin,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const key=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const suffix=randomUUID().slice(0,8), password=randomUUID()+'!5Qa'
const domain='synthetic-policy-'+suffix+'.example.invalid'
const actors=[]
let browser, detection, inspection, responder

function data(result) {if (result.error) throw result.error; return result.data}
const sql=statement=>execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
  '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true}).trim()
const tab=(page,name)=>page.getByRole('group',{name:'Operator sections'}).getByRole('button',{name,exact:true})

async function account(label) {
  const handle='ot_'+label+'_'+suffix, email=handle+'@example.invalid'
  const {user}=data(await service.auth.admin.createUser({email,password,email_confirm:true}))
  assert.match(user.id,/^[a-f0-9-]{36}$/)
  actors.push(user.id)
  const client=createClient(db.origin,key,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:'Disposable SOC '+label}))
  return {id:user.id,email,client,factor:await fixtureAuthenticator(client)}
}

async function signIn(actor) {
  const page=await browser.newPage()
  await page.goto(app.href)
  await page.getByLabel('Email',{exact:true}).fill(actor.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.getByRole('button',{name:'Sign in',exact:true}).click()
  await page.getByRole('heading',{name:'Verify your authenticator'}).waitFor()
  assert.equal(await tab(page,'Threat triage').count(),0)
  assert.equal(await tab(page,'Response actions').count(),0)
  await page.getByLabel('Authenticator code',{exact:true}).fill(await totpCode(actor.factor.secret))
  await page.getByRole('button',{name:'Verify code',exact:true}).click()
  return page
}

try {
  const [requester,approver,moderator]=await Promise.all([account('request'),account('approve'),account('moderator')])
  responder=requester.id
  sql(`insert into sectalk_private.staff values('${moderator.id}');
    insert into sectalk_private.st_v7_threat_reviewers values('${requester.id}','detection');
    insert into sectalk_private.st_v7_abuse_blocklist_operators values('${requester.id}'),('${approver.id}');
    insert into sectalk_private.st_v7_soc_response_grants(actor,action,role) values
      ('${requester.id}','block_domain','requester'),('${approver.id}','block_domain','approver');
    select sectalk_private.st_v7_enqueue_threat('detection','disp-det-${suffix}','high','supported',
      '{"source":"operations","scope":"file_upload","metric":"client_errors","version":1,"threshold":4,"observed":7}',now());
    select sectalk_private.st_v7_enqueue_threat('attachment_inspection','disp-ins-${suffix}','medium','heuristic',
      '{"signal":"script_marker"}',now());`)
  detection=sql(`select id from sectalk_private.st_v7_threat_items where signal_type='detection' and source_key='disp-det-${suffix}';`)
  inspection=sql(`select id from sectalk_private.st_v7_threat_items where signal_type='attachment_inspection' and source_key='disp-ins-${suffix}';`)
  for (const id of [detection,inspection]) assert.match(id,/^[a-f0-9-]{36}$/)
  const triageReason='Verify synthetic enabled signal '+suffix
  assert.equal((await moderator.client.rpc('st_v7_threat_queue')).error?.code,'42501')
  assert.equal((await requester.client.rpc('st_v7_apply_threat_triage',{p_items:[{id:inspection,revision:1}],
    p_action:'confirmed',p_reason:triageReason})).error?.code,'42501')
  assert.deepEqual(data(await moderator.client.rpc('st_v7_soc_response_catalog')),[])

  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const [worker,reviewer,outsider]=await Promise.all([signIn(requester),signIn(approver),signIn(moderator)])
  await tab(outsider,'Moderation').waitFor()
  assert.equal(await tab(outsider,'Threat triage').count(),0)
  assert.equal(await tab(outsider,'Response actions').count(),0)
  await tab(worker,'Threat triage').click()
  const threats=worker.getByRole('region',{name:'Threat triage',exact:true})
  const item=threats.locator('[data-threat-id="'+detection+'"]')
  await item.getByText('Observed 7 · Threshold 4',{exact:true}).waitFor()
  assert.equal(await tab(worker,'Moderation').count(),0)
  assert.equal(await threats.locator('[data-threat-id="'+inspection+'"]').count(),0)
  assert.ok(!(await item.textContent()).includes('disp-det-'+suffix))
  await item.getByRole('checkbox',{name:'Select for triage'}).check()
  await threats.getByLabel('Bulk decision',{exact:true}).selectOption('confirmed')
  await threats.getByLabel('Triage reason',{exact:true}).fill(triageReason)
  await threats.getByRole('button',{name:'Apply bulk triage'}).click()
  await threats.getByText('Triage decision applied to 1 item.',{exact:true}).waitFor()
  await threats.getByLabel('Triage status',{exact:true}).selectOption('confirmed')
  await threats.getByRole('button',{name:'Apply threat filters'}).click()
  await item.getByText('Triage history',{exact:true}).click()
  await item.getByText(triageReason,{exact:true}).waitFor()
  assert.equal(sql(`select actor from sectalk_private.st_v7_threat_triage_audit where item_id='${detection}' and action='confirmed';`),requester.id)

  await tab(worker,'Response actions').click()
  await tab(reviewer,'Response actions').click()
  assert.equal(await tab(reviewer,'Threat triage').count(),0)
  const request=worker.getByRole('region',{name:'SOC response requests',exact:true})
  const approval=reviewer.getByRole('region',{name:'SOC response requests',exact:true})
  await request.getByLabel('Response action',{exact:true}).selectOption('block_domain:')
  await request.getByLabel('Domain to block',{exact:true}).fill(domain)
  await request.getByLabel('Request reason',{exact:true}).fill('Synthetic policy enforcement request '+suffix)
  await request.getByRole('button',{name:'Request SOC response'}).click()
  await request.getByText('Response sent for separate approval.',{exact:true}).waitFor()
  const id=sql(`select id from sectalk_private.st_v7_soc_responses where requester='${requester.id}' and domain='${domain}';`)
  assert.match(id,/^[a-f0-9-]{36}$/)
  assert.equal(sql(`select sectalk_private.st_v7_domain_blocked('${domain}');`),'f')
  for (const user of [requester,moderator]) {
    assert.equal((await user.client.rpc('st_v7_decide_soc_response',{p_id:id,p_approve:true,p_reason:'Synthetic denied approval '+suffix})).error?.code,'42501')
  }
  await approval.getByRole('button',{name:'Refresh response requests'}).click()
  const row=approval.locator('[data-soc-response="'+id+'"]')
  await row.getByLabel('Response decision',{exact:true}).selectOption('approve')
  await row.getByLabel('Decision reason',{exact:true}).fill('Independent QA approval '+suffix)
  await row.getByRole('button',{name:'Apply response decision'}).click()
  await row.getByText(/^Executed/).waitFor()
  assert.equal(sql(`select sectalk_private.st_v7_domain_blocked('${domain}');`),'t')
  assert.equal(sql(`select decider from sectalk_private.st_v7_soc_responses where id='${id}';`),approver.id)

  sql(`delete from sectalk_private.st_v7_threat_reviewers where user_id='${requester.id}';`)
  await tab(worker,'Threat triage').waitFor({state:'hidden',timeout:20000})
  await tab(worker,'Response actions').waitFor()
  console.log('PASS standalone scoped triage, audited confirmation, independent enforcement approval, live policy, and revocation')
} finally {
  await browser?.close()
  if (responder) sql(`update sectalk_private.st_v7_abuse_blocks set revoked_at=now(),revoked_by='${responder}',
    revocation_reason='Retire the disposable policy test.' where kind='domain' and value='${domain}' and revoked_at is null;`)
  if (detection && inspection) sql(`delete from sectalk_private.st_v7_threat_items where id in ('${detection}','${inspection}');`)
  for (const id of actors) {
    sql(`delete from sectalk_private.staff where user_id='${id}';`)
    data(await service.auth.admin.deleteUser(id))
  }
}
