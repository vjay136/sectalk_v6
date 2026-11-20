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
data(await client.auth.signInWithPassword({email,password}))
data(await client.rpc('st_save_profile',{p_handle:handle,p_name:'Delivery Metrics Tester'}))
assert.match(user.id,/^[0-9a-f-]{36}$/)
const sql="insert into sectalk_private.staff(user_id) values('"+user.id+"');"
const seed=spawnSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres'],
  {input:sql,encoding:'utf8',windowsHide:true})
assert.equal(seed.status,0,seed.stderr)
assert.equal((await client.rpc('st_v6_delivery_latency',{p_window:'24h'})).error?.code,'42501')
assert.equal((await client.rpc('st_v6_usage_metrics',{p_window:'7d'})).error?.code,'42501')
const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
try{
  const page=await browser.newPage()
  await page.goto(app.href)
  await page.getByLabel('Email address',{exact:true}).fill(email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Safety',exact:true}).click()
  const metrics=page.getByRole('button',{name:'Delivery metrics',exact:true})
  assert.equal(await metrics.count(),0)
  await page.getByRole('button',{name:'Staff console',exact:true}).click()
  await page.getByRole('button',{name:'Set up authenticator',exact:true}).click()
  const secret=(await page.locator('.mfa-setup code').textContent()).trim()
  await page.getByLabel('Authenticator code',{exact:true}).fill(totp(secret))
  await page.getByRole('button',{name:'Verify access',exact:true}).click()
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
  console.log('Passed authenticator step-up and aggregate-only delivery metrics in the local app.')
}finally{await browser.close()}
