// Test only on the dedicated loopback Supabase project with TOTP enabled.
import assert from 'node:assert/strict'
import { randomUUID, createHmac } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { createClient } from '@supabase/supabase-js'

const app=new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase=new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname,'127.0.0.1')
assert.equal(supabase.origin,'http://127.0.0.1:55321')
const options={auth:{persistSession:false,autoRefreshToken:false}}
const admin=createClient(supabase.origin,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const client=createClient(supabase.origin,process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY,options)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const handle='metrics_'+randomUUID().slice(0,8)
const email=handle+'@example.org'
const reviewerEmail='review_'+handle+'@example.org'
const password=randomUUID()+'1!Q'

function data(result){
  if(result.error)throw result.error
  return result.data
}

function totp(secret){
  const base32='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bits=[...secret.toUpperCase().replace(/=+$/,'')].map(character=>{
    const index=base32.indexOf(character)
    if(index<0)throw new Error('Invalid synthetic authenticator key')
    return index.toString(2).padStart(5,'0')
  }).join('')
  const key=Buffer.from((bits.match(/.{8}/g)||[]).map(part=>Number.parseInt(part,2)))
  const counter=Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30_000)))
  const mac=createHmac('sha1',key).update(counter).digest()
  return String((mac.readUInt32BE(mac.at(-1)&15)&0x7fffffff)%1_000_000).padStart(6,'0')
}

const {user}=data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
const {user:reviewer}=data(await admin.auth.admin.createUser({email:reviewerEmail,password,email_confirm:true}))
data(await client.auth.signInWithPassword({email,password}))
data(await client.rpc('st_save_profile',{p_handle:handle,p_name:'Delivery Metrics Tester'}))
const reviewerClient=createClient(supabase.origin,process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY,options)
data(await reviewerClient.auth.signInWithPassword({email:reviewerEmail,password}))
data(await reviewerClient.rpc('st_save_profile',{p_handle:'review_'+handle,p_name:'Warning Proposal Reviewer'}))
assert.match(user.id,/^[0-9a-f-]{36}$/)
assert.match(reviewer.id,/^[0-9a-f-]{36}$/)
const sql=`
insert into sectalk_private.staff(user_id) values('${user.id}'),('${reviewer.id}');
insert into sectalk_private.st_v6_flag_operators(account_id) values('${user.id}');
with people as (
  insert into auth.users(id,email)
    select gen_random_uuid(),gen_random_uuid()||'@example.invalid' from generate_series(1,5)
    returning id
), profiles as (
  insert into public.st_profiles(id,handle,name)
    select id,'qaf_'||left(replace(id::text,'-',''),16),'Synthetic reviewer cohort' from people returning id
), chats as (
  insert into public.st_chats(member_a,member_b,requester,status)
    select least(id,'${user.id}'::uuid),greatest(id,'${user.id}'::uuid),'${user.id}','accepted' from profiles
    returning id,member_a,member_b
), messages as (
  insert into public.st_messages(id,chat_id,sender,body)
    select gen_random_uuid(),id,'${user.id}','Synthetic warning feedback browser fixture' from chats
    returning id,chat_id,created_at
)
insert into sectalk_private.st_v6_risk_feedback(recipient,message_id,revision,rule_version,category)
  select case when c.member_a='${user.id}' then c.member_b else c.member_a end,
    m.id,m.created_at,'message-rules-1','harassment' from messages m join chats c on c.id=m.chat_id;
`
const seed=spawnSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres'],
  {input:sql,encoding:'utf8',windowsHide:true})
assert.equal(seed.status,0,seed.stderr)
assert.equal((await client.rpc('st_v6_delivery_latency',{p_window:'24h'})).error?.code,'42501')
assert.equal((await client.rpc('st_v6_usage_metrics',{p_window:'7d'})).error?.code,'42501')
assert.equal(data(await client.rpc('st_v6_can_manage_flags')),false)
const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
let releaseRuleChanged=false
async function signInAsStaff(page,address){
  await page.goto(app.href)
  await page.getByLabel('Email address',{exact:true}).fill(address)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Safety',exact:true}).click()
}
async function verifyStaff(page){
  await page.getByRole('button',{name:'Staff console',exact:true}).click()
  await page.getByRole('button',{name:'Set up authenticator',exact:true}).click()
  const secret=(await page.locator('.mfa-setup code').textContent()).trim()
  await page.getByLabel('Authenticator code',{exact:true}).fill(totp(secret))
  await page.getByRole('button',{name:'Verify access',exact:true}).click()
}
try{
  const page=await browser.newPage()
  await signInAsStaff(page,email)
  const metrics=page.getByRole('button',{name:'Delivery metrics',exact:true})
  const release=page.getByRole('button',{name:'Release controls',exact:true})
  const feedback=page.getByRole('button',{name:'Warning feedback',exact:true})
  assert.equal(await metrics.count(),0)
  assert.equal(await release.count(),0)
  assert.equal(await feedback.count(),0)
  await verifyStaff(page)
  const request=page.waitForResponse(response=>response.url().includes('/rpc/st_v6_delivery_latency'))
  await metrics.click()
  const response=await request
  assert.equal(response.status(),200)
  const result=await response.json()
  const region=page.getByRole('region',{name:'Message delivery latency',exact:true})
  await region.waitFor()
  if(result.available){
    await region.getByText('p99',{exact:true}).waitFor()
    assert.ok(result.p99>=result.p95&&result.p95>=result.p50)
  }else await region.getByText('More acknowledged conversations are needed to show delivery metrics.',{exact:true}).waitFor()
  const usage=page.waitForResponse(response=>response.url().includes('/rpc/st_v6_usage_metrics'))
  await page.getByRole('button',{name:'Usage metrics',exact:true}).click()
  const usageResponse=await usage
  assert.equal(usageResponse.status(),200)
  const aggregate=await usageResponse.json()
  assert.deepEqual(Object.keys(aggregate).sort(),['metrics','through'])
  assert.ok(Object.values(aggregate.metrics).every(count=>count>=10&&count%10===0))
  await page.getByRole('region',{name:'Product usage',exact:true}).getByText('Active accounts',{exact:true}).waitFor()
  const warningFeedback=page.waitForResponse(response=>response.url().endsWith('/rpc/st_v6_risk_feedback_summary'))
  await feedback.click()
  const feedbackResponse=await warningFeedback
  assert.equal(feedbackResponse.status(),200)
  for(const row of await feedbackResponse.json()){
    assert.deepEqual(Object.keys(row).sort(),['accounts','category','reviewed','rule_version'])
    assert.ok(row.accounts>=5&&row.accounts%5===0)
  }
  await page.getByRole('region',{name:'Warning feedback',exact:true}).waitFor()
  await page.getByRole('button',{name:'Rule proposals',exact:true}).click()
  const proposals=page.getByRole('region',{name:'Rule and threshold proposals',exact:true})
  await proposals.getByLabel('Feedback cohort',{exact:true}).selectOption('harassment:message-rules-1')
  await proposals.getByLabel('Proposed change',{exact:true}).selectOption('threshold_review')
  await proposals.getByLabel('Minimum rule confidence (%)',{exact:true}).fill('75')
  await proposals.getByRole('button',{name:'Submit proposal',exact:true}).click()
  await proposals.getByText('Awaiting independent review',{exact:true}).waitFor()
  assert.equal(await proposals.getByRole('button',{name:'Approve for evaluation',exact:true}).count(),0)

  const reviewerPage=await browser.newPage()
  await signInAsStaff(reviewerPage,reviewerEmail)
  await verifyStaff(reviewerPage)
  await reviewerPage.getByRole('button',{name:'Warning feedback',exact:true}).click()
  await reviewerPage.getByRole('button',{name:'Rule proposals',exact:true}).click()
  const pending=reviewerPage.locator('article').filter({hasText:'75% minimum confidence'})
  await pending.getByRole('button',{name:'Approve for evaluation',exact:true}).click()
  await pending.getByText('Approved for evaluation',{exact:true}).waitFor()
  await proposals.getByRole('button',{name:'Refresh proposals',exact:true}).click()
  await proposals.getByText('Approved for evaluation',{exact:true}).waitFor()

  await release.click()
  const controls=page.getByRole('region',{name:'Release controls',exact:true})
  const rollout=controls.getByLabel('Rollout percentage',{exact:true})
  const stop=controls.getByLabel('Emergency stop for all scopes',{exact:true})
  const save=controls.getByRole('button',{name:'Save release rule',exact:true})
  const evaluate=async()=>data(await client.rpc('st_v6_feature_available',{p_feature:'task_creation'}))
  assert.equal(await evaluate(),true)
  releaseRuleChanged=true
  await rollout.fill('0')
  await save.click()
  await controls.getByText('0% enabled',{exact:true}).waitFor()
  assert.equal(await evaluate(),false)
  await rollout.fill('100')
  await stop.check()
  await save.click()
  await controls.getByText('Emergency stop',{exact:true}).waitFor()
  assert.equal(await evaluate(),false)
  await stop.uncheck()
  await save.click()
  await controls.getByText('Emergency stop',{exact:true}).waitFor({state:'detached'})
  assert.equal(await evaluate(),true)
  releaseRuleChanged=false
  console.log('Passed authenticator step-up, warning feedback, staff analytics, staged feature rollout and the emergency stop.')
}finally{
  await browser.close()
  const cleanup=spawnSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres'],{
    input:`delete from sectalk_private.st_v6_warning_proposals where submitted_by='${user.id}';
      delete from sectalk_private.st_v6_risk_feedback f using public.st_messages m
      where f.message_id=m.id and m.sender='${user.id}';`,encoding:'utf8',windowsHide:true,
  })
  assert.equal(cleanup.status,0,cleanup.stderr)
  if(releaseRuleChanged){
    const restored=spawnSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres'],{
      input:"update sectalk_private.st_v6_flag_rules set enabled=true, rollout=100, killed=false where feature='task_creation' and scope='global';",
      encoding:'utf8',windowsHide:true,
    })
    assert.equal(restored.status,0,restored.stderr)
  }
}
