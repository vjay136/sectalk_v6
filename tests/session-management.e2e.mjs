// Isolated GoTrue and Edge coverage. Tokens stay in process memory.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { setTimeout } from 'node:timers/promises'
import { createClient } from '@supabase/supabase-js'

const origin = new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
const app = new URL(process.env.SECTALK_STORAGE_TEST_APP).origin
const hardenedAuth = process.env.SECTALK_AUTH_ROTATION_V2_URL
assert.equal(origin,'http://127.0.0.1:55321')
assert.equal(new URL(app).hostname,'127.0.0.1')
if (hardenedAuth) assert.equal(new URL(hardenedAuth).origin,'http://127.0.0.1:55458')
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const publicKey=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const options={auth:{persistSession:false,autoRefreshToken:false}}
const admin=createClient(origin,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const client=()=>createClient(origin,publicKey,options)
const password=randomUUID()+'1!Q'
const suffix=randomUUID().slice(0,8)
function data(result) {
  if(result.error) throw new Error(result.error.message)
  return result.data
}
async function account(role) {
  const handle='sessions_'+role+'_'+suffix
  const email=handle+'@example.org'
  const {user}=data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  const api=client()
  data(await api.auth.signInWithPassword({email,password}))
  data(await api.rpc('st_save_profile',{p_handle:handle,p_name:'Session fixture '+role}))
  return {user,api,email}
}
function sessionId(value) {
  const decoded=JSON.parse(Buffer.from(value.access_token.split('.')[1],'base64url'))
  assert.match(decoded.session_id,/^[a-f0-9-]{36}$/)
  return decoded.session_id
}
function sql(input) {
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'],{input,encoding:'utf8'}).trim()
}
async function tokenRequest(endpoint, grant, fields) {
  const response=await fetch(endpoint+'/token?grant_type='+grant,{
    method:'POST',headers:{apikey:publicKey,'content-type':'application/json'},
    body:JSON.stringify(fields),
  })
  return {status:response.status,data:await response.json()}
}
const refresh=(token,endpoint=origin+'/auth/v1')=>tokenRequest(endpoint,'refresh_token',{refresh_token:token})
const [owner,other]=await Promise.all([account('owner'),account('other')])
const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})

try {
  async function open(person) {
    const page=await browser.newPage()
    await page.goto(app+'/#account')
    await page.getByLabel('Email address',{exact:true}).fill(person.email)
    await page.getByLabel('Password',{exact:true}).fill(password)
    await page.locator('button.submit-auth').click()
    const nav=page.getByRole('navigation',{name:'SecTalk features'})
    await nav.getByRole('button',{name:'Profile',exact:true}).click()
    await page.getByRole('button',{name:'Devices and sessions',exact:true}).click()
    await page.getByRole('region',{name:'Devices and sessions'}).getByText('This device',{exact:true}).waitFor()
    return page
  }
  const [controller,device,stranger]=await Promise.all([open(owner),open(owner),open(other)])
  const getRows=page=>page.getByRole('region',{name:'Devices and sessions'})
  const listing=getRows(controller)
  await listing.getByRole('button',{name:'Refresh devices',exact:true}).click()
  const ownRows=data(await owner.api.rpc('st_v7_list_sessions'))
  const foreignRows=data(await other.api.rpc('st_v7_list_sessions'))
  assert.equal(ownRows.length,3)
  assert.equal(foreignRows.length,2)
  assert.deepEqual(Object.keys(ownRows[0]).sort(),['current_device','device','expires_at','id','refreshed_at','started_at'])
  assert.equal(ownRows[0].current_device,true)
  assert.equal(data(await owner.api.rpc('st_v7_revoke_session',{p_session:foreignRows[0].id})),false)
  const intended=await device.evaluate(() => {
    const key=Object.keys(localStorage).find(key=>key.endsWith('-auth-token'))
    if (!key) return null
    const token=JSON.parse(localStorage.getItem(key)).access_token
    const payload=token.split('.')[1].replaceAll('-','+').replaceAll('_','/')
    return JSON.parse(atob(payload)).session_id
  })
  assert.ok(ownRows.some(row=>row.id===intended))
  const label=ownRows.find(row=>row.id===intended).device
  const candidate=listing.getByRole('article').filter({hasText:label}).filter({
    has:controller.getByRole('button',{name:'End device session',exact:true}),
  })
  await candidate.getByRole('button',{name:'End device session',exact:true}).click()
  await candidate.getByRole('button',{name:'Confirm sign-out',exact:true}).click()
  await listing.getByText('Device session ended.',{exact:true}).waitFor()
  await device.getByLabel('Email address',{exact:true}).waitFor()
  assert.equal(await getRows(stranger).getByText('This device',{exact:true}).count(),1)
  assert.ok(!data(await owner.api.rpc('st_v7_list_sessions')).some(row=>row.id===intended))

  const bound=async kind=>{
    const record=data(await client().auth.signInWithPassword({email:owner.email,password})).session
    const id=sessionId(record)
    const input=kind==='idle'
      ? `update auth.sessions set created_at=now()-interval '8 days',refreshed_at=null where id='${id}';`
      : `update auth.sessions set created_at=now()-interval '31 days',not_after=now()-interval '1 minute',
        refreshed_at=now() at time zone 'UTC' where id='${id}';`
    sql(input)
    const rawClient=createClient(origin,publicKey,{...options,global:{headers:{Authorization:'Bearer '+record.access_token}}})
    assert.equal(data(await rawClient.rpc('st_v7_current_session_valid')),false)
    assert.ok((await refresh(record.refresh_token)).status>=400)
  }
  await bound('idle')
  await bound('absolute')

  async function checkRotation(endpoint, strictFamily) {
    const login=await tokenRequest(endpoint,'password',{email:owner.email,password})
    assert.equal(login.status,200)
    const original=login.data
    const first=await refresh(original.refresh_token,endpoint)
    assert.equal(first.status,200)
    assert.notEqual(first.data.refresh_token,original.refresh_token)
    assert.equal(sessionId(first.data),sessionId(original))
    const grace=await refresh(original.refresh_token,endpoint)
    assert.equal(grace.status,200)
    const second=await refresh(grace.data.refresh_token,endpoint)
    assert.equal(second.status,200)
    assert.notEqual(second.data.refresh_token,grace.data.refresh_token)
    await setTimeout(11_500)
    const stale=await refresh(original.refresh_token,endpoint)
    assert.equal(stale.data.error_code,'refresh_token_already_used')
    const descendant=await refresh(second.data.refresh_token,endpoint)
    if (strictFamily) assert.ok(descendant.status>=400)
    console.log(strictFamily ? 'V2 replay rejected and entire session family revoked.'
      : 'Default provider replay rejected. Descendant HTTP status: '+descendant.status)
  }
  await checkRotation(origin+'/auth/v1',false)
  if (hardenedAuth) await checkRotation(new URL(hardenedAuth).origin,true)

  await listing.getByRole('button',{name:'Sign out this device',exact:true}).click()
  await listing.getByRole('button',{name:'Confirm sign-out',exact:true}).click()
  await controller.getByLabel('Email address',{exact:true}).waitFor()
  console.log('Passed own-device list/revoke, live second Edge sign-out, cross-account isolation, native idle and absolute denial, rotation, grace, and stale reuse rejection.')
} finally {
  await browser.close()
  await Promise.allSettled([owner,other].map(person=>admin.auth.admin.deleteUser(person.user.id)))
}
