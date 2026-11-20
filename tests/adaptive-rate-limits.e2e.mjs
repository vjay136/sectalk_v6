import assert from 'node:assert/strict'
import {randomBytes,randomUUID} from 'node:crypto'
import {execFileSync} from 'node:child_process'
import {createClient} from '@supabase/supabase-js'

const origin=new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
const app=new URL(process.env.SECTALK_STORAGE_TEST_APP).origin
assert.equal(origin,'http://127.0.0.1:55321')
assert.equal(new URL(app).hostname,'127.0.0.1')
const key=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const options={auth:{persistSession:false,autoRefreshToken:false}}
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const admin=createClient(origin,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const native=createClient(origin,key,options)
const suffix=randomUUID().slice(0,8)
const handle='ratelimit_'+suffix
const email=handle+'@example.org'
const nonexistent='ratelimit_missing_'+suffix+'@example.org'
const password=randomUUID()+'!zQ'
function data(result) {if(result.error)throw new Error(result.error.message);return result.data}
function sql(input) {
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'],{input,encoding:'utf8'}).trim()
}
function signIn(target,secret,forwarded) {
  return fetch(app+'/api/auth/sign-in',{method:'POST',
    headers:{Origin:app,'Content-Type':'application/json','X-Forwarded-For':forwarded},
    body:JSON.stringify({email:target,password:secret})})
}
let browser,owner,workspace
try {
  owner=data(await admin.auth.admin.createUser({email,password,email_confirm:true})).user
  data(await native.auth.signInWithPassword({email,password}))
  data(await native.rpc('st_save_profile',{p_handle:handle,p_name:'Adaptive quota test'}))
  workspace=data(await native.rpc('st_v2_create_workspace',{p_name:'Adaptive quota QA'}))

  const identifier=randomBytes(32).toString('hex')
  const parallel=await Promise.all(Array.from({length:13},()=>admin.rpc('st_v7_admit_password_request',{
    p_identifier:identifier,p_ip:'192.0.2.213',
  })))
  assert.equal(parallel.map(data).filter(seconds=>seconds===0).length,10)
  const admitted=[]
  for(let i=0;i<14;i++){
    const response=await signIn(nonexistent,'incorrect-'+password,'198.51.100.'+(10+i))
    admitted.push(response.status)
    if(response.status===429){
      assert.deepEqual(await response.json(),{error:'try_again_later'})
      assert.ok(Number(response.headers.get('Retry-After'))>=1)
      break
    }
    assert.equal(response.status,401)
    assert.deepEqual(await response.json(),{error:'invalid_credentials'})
  }
  assert.equal(admitted.at(-1),429)
  assert.ok(admitted.includes(401))

  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const page=await browser.newPage()
  await page.goto(app+'/#account')
  await page.getByLabel('Email address',{exact:true}).fill(nonexistent)
  await page.getByLabel('Password',{exact:true}).fill(password)
  const denied=page.waitForResponse(response=>response.url().endsWith('/api/auth/sign-in'))
  await page.locator('.submit-auth').click()
  assert.equal((await denied).status(),429)
  await page.getByRole('alert').getByText(/Too many|try again/i).waitFor()
  await page.getByLabel('Email address',{exact:true}).fill(email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('.submit-auth').click()
  await page.getByRole('navigation',{name:'SecTalk features'}).waitFor()
  function list() {
    return page.evaluate(async id=>{
      const saved=Object.keys(localStorage).find(name=>name.endsWith('-auth-token'))
      const token=JSON.parse(localStorage.getItem(saved)).access_token
      const response=await fetch('/api/workspace-files?workspace='+id,{headers:{Authorization:'Bearer '+token}})
      return {status:response.status,retry:Number(response.headers.get('Retry-After'))}
    },workspace)
  }
  assert.equal((await list()).status,200)
  const actor="sectalk_private.st_v7_rate_bucket('account','"+owner.id+"')"
  assert.equal(sql("select count(*) from sectalk_private.st_v7_rate_buckets where action='file_read' and bucket="+actor+";"),'1')
  sql("update sectalk_private.st_v7_rate_buckets set tokens=0,measured_at=clock_timestamp()+interval '20 seconds' where action='file_read' and bucket="+actor+";")
  const limited=await list()
  assert.equal(limited.status,429)
  assert.ok(limited.retry>=1)
  sql("update sectalk_private.st_v7_rate_buckets set measured_at=clock_timestamp()-interval '60 seconds' where action='file_read' and bucket="+actor+";")
  assert.equal((await list()).status,200)
  console.log('Atomic multi-request quota, generic password rejection and throttling, browser feedback, and file budget refill passed.')
} finally {
  await browser?.close()
  if(workspace) sql("delete from public.st_v2_workspaces where id='"+workspace+"';")
  if(owner) await admin.auth.admin.deleteUser(owner.id)
}
