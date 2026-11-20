// Loopback native Auth, client Edge, HTTP and Mailpit.
import assert from 'node:assert/strict'
import { createHmac,randomUUID } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { setTimeout } from 'node:timers/promises'
import { createClient } from '@supabase/supabase-js'

const origin=new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
const app=new URL(process.env.SECTALK_STORAGE_TEST_APP).origin
const mail=new URL(process.env.SECTALK_AUTH_TEST_MAIL||'http://127.0.0.1:55324')
assert.equal(origin,'http://127.0.0.1:55321')
assert.equal(new URL(app).hostname,'127.0.0.1')
assert.equal(mail.hostname,'127.0.0.1')
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const publicKey=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const options={auth:{persistSession:false,autoRefreshToken:false}}
const scoped=token=>createClient(origin,publicKey,token?{...options,global:{headers:{Authorization:'Bearer '+token}}}:options)
const admin=createClient(origin,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const secret=randomUUID()+'2!Q'
const suffix=randomUUID().slice(0,8)
function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}
async function account(type,confirmed) {
  const handle='signin_'+type+'_'+suffix
  const email=handle+'@example.org'
  const {user}=data(await admin.auth.admin.createUser({email,password:secret,email_confirm:confirmed}))
  assert.match(user.id,/^[a-f0-9-]{36}$/)
  if (confirmed) {
    const client=scoped()
    data(await client.auth.signInWithPassword({email,password:secret}))
    data(await client.rpc('st_save_profile',{p_handle:handle,p_name:'Sign-in fixture'}))
  }
  return {user,email}
}
const [owner,unconfirmed]=await Promise.all([account('owner',true),account('pending',false)])
const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
const nav=page=>page.getByRole('navigation',{name:'SecTalk features'})
async function login(page,email,password=secret) {
  await page.getByLabel('Email address',{exact:true}).fill(email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  const response=page.waitForResponse(result=>result.url().endsWith('/api/auth/sign-in'))
  await page.locator('button.submit-auth').click()
  return response
}
async function access(page) {
  return page.evaluate(()=>{
    const key=Object.keys(localStorage).find(item=>item.endsWith('-auth-token'))
    return JSON.parse(localStorage.getItem(key)).access_token
  })
}
function alterTrustedHistory() {
  execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'],{input:`update auth.sessions s set ip='192.0.2.22',user_agent='Firefox/118'
      from sectalk_private.st_v7_device_sessions b join sectalk_private.st_v7_devices d on d.id=b.device_id
      where s.id=b.session_id and s.user_id='${owner.user.id}' and d.state='trusted';`})
}
async function mailboxValue() {
  for(let attempt=0;attempt<30;attempt++){
    const results=await (await fetch(new URL('/api/v1/search?query='+encodeURIComponent('to:'+owner.email),mail))).json()
    const message=results.messages?.find(candidate=>/sign.in|magic|login/i.test(candidate.Subject))
    if(message) {
      const body=await (await fetch(new URL('/api/v1/message/'+message.ID,mail))).json()
      const number=body.HTML.match(/>\s*(\d{6})\s*</)?.[1]
      if(number) return number
      const url=body.HTML.match(/href="([^"]*\/auth\/v1\/verify[^"]+)"/)?.[1]
      assert.ok(url,'Expected a provider-issued email OTP or magic link')
      return url.replaceAll('&amp;','&')
    }
    await setTimeout(500)
  }
  throw new Error('Native local sign-in verification mail was not delivered')
}
function currentTotp(secret,step) {
  const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bits=[...secret].map(character=>alphabet.indexOf(character).toString(2).padStart(5,'0')).join('')
  const key=Buffer.from(bits.match(/.{8}/g).map(part=>parseInt(part,2)))
  const count=Buffer.alloc(8)
  count.writeBigUInt64BE(BigInt(step))
  const hmac=createHmac('sha1',key).update(count).digest()
  return String((hmac.readUInt32BE(hmac.at(-1)&15)&0x7fffffff)%1_000_000).padStart(6,'0')
}
const profile=(jwt)=>scoped(jwt).from('st_profiles').select('id').eq('id',owner.user.id).single()

try {
  const [controller,failed,normal,risky,mfa]=await Promise.all(
    Array.from({length:5},()=>browser.newPage()),
  )
  await Promise.all([controller,failed,normal,risky,mfa].map(page=>page.goto(app+'/#account')))
  let previous
  for(const [email,password] of [[owner.email,'incorrect-'+secret],['missing_'+suffix+'@example.org',secret],[unconfirmed.email,secret]]) {
    const response=await fetch(app+'/api/auth/sign-in',{method:'POST',headers:{'content-type':'application/json'},
      body:JSON.stringify({email,password})})
    const result={status:response.status,body:await response.json()}
    assert.deepEqual(result,{status:401,body:{error:'invalid_credentials'}})
    if(previous) assert.deepEqual(result,previous)
    previous=result
  }
  assert.equal((await login(failed,unconfirmed.email)).status(),401)
  await failed.getByText('Check your email and password, then try again.',{exact:true}).waitFor()

  assert.equal((await login(controller,owner.email)).status(),200)
  await nav(controller).getByRole('button',{name:'Profile',exact:true}).click()
  await controller.getByRole('button',{name:'Devices and sessions',exact:true}).click()
  const registry=controller.getByRole('region',{name:'Device trust',exact:true})
  await registry.getByRole('button',{name:'Register this device',exact:true}).click()
  await registry.getByRole('button',{name:'Trust device',exact:true}).click()
  await registry.getByLabel('Current password',{exact:true}).fill(secret)
  await registry.getByRole('button',{name:'Confirm trust device',exact:true}).click()
  await registry.getByText('Trusted',{exact:true}).waitFor()

  assert.equal((await login(normal,owner.email)).status(),200)
  await nav(normal).waitFor()
  assert.equal(data(await scoped(await access(normal)).rpc('st_v7_login_risk_status')),'clear')

  alterTrustedHistory()
  assert.equal((await login(risky,owner.email)).status(),200)
  const panel=risky.getByRole('region',{name:'Sign-in verification',exact:true})
  await panel.getByRole('heading',{name:'Verify this sign-in',exact:true}).waitFor()
  const raw=await access(risky)
  assert.equal(data(await scoped(raw).rpc('st_v7_login_risk_status')),'email')
  assert.equal((await profile(raw)).error?.code,'PT403')
  const denied=await fetch(app+'/api/ice',{headers:{Authorization:'Bearer '+raw}})
  assert.equal(denied.status,403)
  assert.deepEqual(await denied.json(),{error:'verification_required'})

  await panel.getByRole('button',{name:'Send verification code',exact:true}).click()
  const proof=panel.getByLabel('Email verification code or link',{exact:true})
  await proof.fill('000001')
  await panel.getByRole('button',{name:'Verify email code',exact:true}).click()
  await panel.getByRole('alert').waitFor()
  assert.equal((await profile(raw)).error?.code,'PT403')
  await proof.fill(await mailboxValue())
  await panel.getByRole('button',{name:'Verify email code',exact:true}).click()
  await nav(risky).waitFor()
  const upgraded=await access(risky)
  assert.notEqual(upgraded,raw)
  assert.equal(data(await scoped(upgraded).rpc('st_v7_login_risk_status')),'clear')
  assert.equal(data(await profile(upgraded)).id,owner.user.id)
  assert.equal((await profile(raw)).error?.code,'PT403')

  await nav(controller).getByRole('button',{name:'Sign out',exact:true}).press('Enter')
  assert.equal((await login(controller,owner.email)).status(),200)
  await controller.getByRole('region',{name:'Sign-in verification',exact:true})
    .getByRole('button',{name:'Verify this trusted device',exact:true}).click()
  await nav(controller).getByRole('button',{name:'Profile',exact:true}).click()
  await controller.getByRole('button',{name:'Security',exact:true}).click()
  await controller.getByRole('button',{name:'Set up authenticator',exact:true}).click()
  const totp=(await controller.locator('.mfa-setup code').textContent()).trim()
  while(Date.now()%30_000>28_000) await setTimeout(200)
  const step=Math.floor(Date.now()/30_000)
  await controller.getByLabel('Authenticator code',{exact:true}).fill(currentTotp(totp,step))
  await controller.getByRole('button',{name:'Verify authenticator',exact:true}).click()
  await controller.getByRole('heading',{name:'Recovery codes',exact:true}).waitFor()
  alterTrustedHistory()

  assert.equal((await login(mfa,owner.email)).status(),200)
  await mfa.getByRole('heading',{name:'Verify your sign-in',exact:true}).waitFor()
  const aal1=await access(mfa)
  assert.equal(data(await scoped(aal1).rpc('st_v7_login_risk_status')),'authenticator')
  assert.equal((await scoped(aal1).rpc('st_v7_request_signin_code')).error?.code,'42501')
  assert.equal((await profile(aal1)).error?.code,'PT403')
  while(Math.floor(Date.now()/30_000)===step||Date.now()%30_000>28_000) await setTimeout(200)
  await mfa.getByLabel('Authenticator code',{exact:true}).fill(currentTotp(totp,Math.floor(Date.now()/30_000)))
  await mfa.getByRole('button',{name:'Verify authenticator',exact:true}).click()
  await nav(mfa).waitFor()
  assert.equal(data(await profile(await access(mfa))).id,owner.user.id)
  assert.equal((await profile(aal1)).error?.code,'PT403')
  console.log('Passed generic HTTP/UI errors, native normal login, blocked API access, Mailpit step-up, true MFA and rejection of both original JWTs.')
} finally {
  await browser.close()
  await Promise.allSettled([owner,unconfirmed].map(account=>admin.auth.admin.deleteUser(account.user.id)))
}
