// Local native Auth, Edge and Mailpit evidence. Only fixture trusted histories are adjusted.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
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
const options={auth:{persistSession:false,autoRefreshToken:false}}
const publicKey=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const scoped=token=>createClient(origin,publicKey,token?{...options,global:{headers:{Authorization:'Bearer '+token}}}:options)
const admin=createClient(origin,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const initial=randomUUID()+'1!Q'
const replacement=randomUUID()+'1!R'
const suffix=randomUUID().slice(0,8)
function data(result) {
  if(result.error)throw new Error(result.error.message)
  return result.data
}
async function account(role) {
  const handle='anomaly_'+role+'_'+suffix
  const email=handle+'@example.org'
  const {user}=data(await admin.auth.admin.createUser({email,password:initial,email_confirm:true}))
  assert.match(user.id,/^[a-f0-9-]{36}$/)
  const api=scoped()
  data(await api.auth.signInWithPassword({email,password:initial}))
  data(await api.rpc('st_save_profile',{p_handle:handle,p_name:'Anomaly fixture'}))
  return {user,email,api}
}
function sql(input) {
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'],{input,encoding:'utf8'}).trim()
}
const [owner,outsider]=await Promise.all([account('owner'),account('other')])
const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
const nav=page=>page.getByRole('navigation',{name:'SecTalk features'})
const toast='Review an unusual sign-in in your account security settings.'
const security=async page=>{
  await nav(page).getByRole('button',{name:'Profile',exact:true}).click()
  await page.getByRole('button',{name:'Security',exact:true}).click()
  return page.getByRole('region',{name:'Sign-in alerts',exact:true})
}
async function login(page,person,password=initial) {
  await page.getByLabel('Email address',{exact:true}).fill(person.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
}
async function opening(person) {
  const page=await browser.newPage()
  await page.goto(app+'/#account')
  await login(page,person)
  await nav(page).waitFor()
  return page
}
async function token(page) {
  return page.evaluate(()=>{
    const key=Object.keys(localStorage).find(item=>item.endsWith('-auth-token'))
    return JSON.parse(localStorage.getItem(key)).access_token
  })
}
function runDetector() {
  sql(`update sectalk_private.st_v7_login_candidates c set ready_at=now()-interval '1 second'
    from auth.sessions s where s.id=c.session_id and s.user_id='${owner.user.id}';
    select sectalk_private.st_v7_detect_login_anomalies();`)
}
async function recoveryOtp(email) {
  for(let attempt=0;attempt<30;attempt++) {
    const found=await fetch(new URL('/api/v1/search?query='+encodeURIComponent('to:'+email),mail))
    assert.equal(found.status,200)
    const {messages}=await found.json()
    const candidate=messages?.find(item=>/reset password/i.test(item.Subject))
    if(candidate) {
      const body=await (await fetch(new URL('/api/v1/message/'+candidate.ID,mail))).json()
      const code=body.HTML.match(/>\s*(\d{6})\s*</)?.[1]
      assert.ok(code,'Expected a numeric recovery OTP')
      return code
    }
    await setTimeout(500)
  }
  throw new Error('Local password recovery was not delivered')
}

try {
  const [controller,unrelated]=await Promise.all([opening(owner),opening(outsider)])
  await nav(controller).getByRole('button',{name:'Profile',exact:true}).click()
  await controller.getByRole('button',{name:'Devices and sessions',exact:true}).click()
  const registry=controller.getByRole('region',{name:'Device trust',exact:true})
  await registry.getByRole('button',{name:'Register this device',exact:true}).click()
  const registered=registry.getByRole('article').filter({hasText:'This registered device'})
  await registered.getByRole('button',{name:'Trust device',exact:true}).click()
  await registered.getByLabel('Current password',{exact:true}).fill(initial)
  await registered.getByRole('button',{name:'Confirm trust device',exact:true}).click()
  await registered.getByText('Trusted',{exact:true}).waitFor()
  const alerts=await security(controller)
  await alerts.getByText('No unusual sign-ins to review.',{exact:true}).waitFor()
  const observer=await opening(owner)
  runDetector()
  assert.deepEqual(data(await owner.api.rpc('st_v7_list_login_anomalies')),[])
  assert.equal(await observer.getByText(toast,{exact:true}).count(),0)

  sql(`update auth.sessions s set ip='192.0.2.123',user_agent='Firefox/130.0'
      from sectalk_private.st_v7_device_sessions b join sectalk_private.st_v7_devices d on d.id=b.device_id
      where s.id=b.session_id and s.user_id='${owner.user.id}' and d.state='trusted';`)
  const unusual=await opening(owner)
  const oldBearer=await token(unusual)
  runDetector()
  await controller.getByText(toast,{exact:true}).waitFor()
  await observer.getByText(toast,{exact:true}).waitFor()
  assert.equal(await unrelated.getByText(toast,{exact:true}).count(),0)
  const projection=data(await owner.api.rpc('st_v7_list_login_anomalies'))
  assert.equal(projection.length,1)
  assert.deepEqual(Object.keys(projection[0]).sort(),['detected_at','id','observed_at','state'])
  assert.deepEqual(data(await outsider.api.rpc('st_v7_list_login_anomalies')),[])
  assert.equal((await scoped(oldBearer).rpc('st_v7_review_login_anomaly',{
    p_anomaly:projection[0].id,p_action:'recognize',
  })).error?.code,'42501')

  await alerts.getByRole('button',{name:'This wasn’t me',exact:true}).click()
  await alerts.getByLabel('Current password',{exact:true}).fill(initial)
  await alerts.getByRole('button',{name:'Verify and lock account',exact:true}).click()
  await controller.getByLabel('Email address',{exact:true}).waitFor()
  assert.equal((await scoped(oldBearer).from('st_profiles').select('id').eq('id',owner.user.id)).error?.code,'PT423')
  assert.ok((await scoped().auth.getUser(oldBearer)).error)
  await observer.evaluate(()=>window.dispatchEvent(new Event('online')))
  await observer.getByLabel('Email address',{exact:true}).waitFor()
  assert.equal(await nav(unrelated).count(),1)

  await login(controller,owner)
  const locked=controller.getByRole('region',{name:'Account lockdown',exact:true})
  await locked.getByRole('heading',{name:'Your account is locked',exact:true}).waitFor()
  const current=scoped(await token(controller))
  assert.equal(data(await current.rpc('st_v7_account_lock_status')).locked,true)
  assert.equal((await current.from('st_profiles').select('id')).error?.code,'PT423')
  assert.equal((await current.rpc('st_v7_begin_device_bundle',{
    p_device:randomUUID(),p_signing:'a'.repeat(87),p_agreement:'b'.repeat(87),
  })).error?.code,'42501')
  assert.equal(await locked.getByRole('button',{name:'Verify and restore account access',exact:true}).count(),0)

  await locked.getByRole('button',{name:'Start email password recovery',exact:true}).click()
  await controller.getByLabel('Email address',{exact:true}).fill(owner.email)
  await controller.getByRole('button',{name:'Send recovery code',exact:true}).click()
  await controller.getByLabel('Verification code').fill(await recoveryOtp(owner.email))
  await controller.getByRole('button',{name:'Verify code',exact:true}).click()
  await controller.getByLabel('Password',{exact:true}).fill(replacement)
  await controller.getByLabel('Confirm password',{exact:true}).fill(replacement)
  await controller.getByRole('button',{name:'Update password',exact:true}).click()
  await controller.getByText('Password updated. Sign in with your new password.').waitFor()
  await login(controller,owner,replacement)
  await locked.getByText('Password recovery verified.',{exact:true}).waitFor()
  const quarantine=await scoped().auth.signInWithPassword({email:owner.email,password:replacement})
  const quarantineToken=data(quarantine).session.access_token
  assert.equal((await scoped(quarantineToken).from('st_profiles').select('id')).error?.code,'PT423')
  assert.equal(await locked.getByRole('button',{name:'Verify and restore account access',exact:true}).count(),0)
  sql(`update sectalk_private.st_v7_account_lockdowns set ready_at=now()-interval '1 minute' where user_id='${owner.user.id}';`)
  await locked.getByRole('button',{name:'Refresh account recovery status',exact:true}).click()
  await locked.getByLabel('Current password',{exact:true}).fill(replacement)
  await locked.getByRole('button',{name:'Verify and restore account access',exact:true}).click()
  await nav(controller).waitFor()
  const final=await security(controller)
  await final.getByText(/Account recovered/).waitFor()
  assert.equal((await scoped(oldBearer).from('st_profiles').select('id')).error?.code,'PT401')
  assert.equal((await scoped(quarantineToken).from('st_profiles').select('id')).error?.code,'PT401')
  assert.equal(data(await scoped(await token(controller)).rpc('st_v7_account_lock_status')).locked,false)
  console.log('Passed normal native login, dual-signal anomaly and private device alerts, trusted lockdown, raw API denial, genuine Mailpit OTP, measured recovery and old JWT rejection.')
} finally {
  await browser.close()
  await Promise.allSettled([owner,outsider].map(person=>admin.auth.admin.deleteUser(person.user.id)))
}
