import assert from 'node:assert/strict'
import {spawn} from 'node:child_process'
import {generateKeyPairSync, randomUUID, sign} from 'node:crypto'
import {createServer} from 'node:http'
import {resolve} from 'node:path'
import {setTimeout} from 'node:timers/promises'
import {createClient} from '@supabase/supabase-js'

const origin = new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
const app = 'http://127.0.0.1:3489'
assert.equal(origin, 'http://127.0.0.1:55321')
const appDir = resolve('supabase/.temp/v4-auth-qa/device-commands-app')
const next = resolve('node_modules/next/dist/bin/next')
const {chromium} = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const options = {auth:{persistSession:false,autoRefreshToken:false}}
const publishable = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const serviceKey = process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
const admin = createClient(origin, serviceKey, options)
const {publicKey, privateKey} = generateKeyPairSync('ed25519')
const issuedAt = Date.now()
const entries = ['0.0.0.0/0','::/0'].map(cidr=>({
  cidr, asn:64513, reputation:'poor', tor:true, vpn:true,
  latitude:51.5, longitude:0.1, radiusKm:20, confidence:99,
}))
const payload = Buffer.from(JSON.stringify({issuedAt,expiresAt:issuedAt+600000,entries}))
let feedRequests = 0
const feed = createServer((request,response)=>{
  assert.ok(['/feed','/tampered','/expired','/specific'].includes(request.url))
  assert.equal(request.method,'GET')
  feedRequests++
  const signed = request.url==='/expired'
    ? Buffer.from(JSON.stringify({issuedAt:issuedAt-600000,expiresAt:issuedAt-1000,entries}))
    : request.url==='/specific'
      ? Buffer.from(JSON.stringify({issuedAt,expiresAt:issuedAt+600000,entries:[
        ...entries, {...entries[0],cidr:'192.0.2.0/24',reputation:'normal',tor:false,vpn:false},
      ]}))
      : payload
  const served = request.url==='/tampered' ? Buffer.concat([signed,Buffer.from(' ')]) : signed
  response.setHeader('Content-Type','application/json')
  response.end(JSON.stringify({payload:served.toString('base64url'), signature:sign(null,signed,privateKey).toString('base64url')}))
})
await new Promise((resolve,reject)=>feed.once('error',reject).listen(0,'127.0.0.1',resolve))

const child = spawn(process.execPath, [next,'dev','--hostname','127.0.0.1','--port','3489'], {
  cwd: appDir, stdio: 'inherit',
  env: {...process.env, NEXT_PUBLIC_SUPABASE_URL:origin, NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:publishable,
    SECTALK_AUTH_PASSWORD_UPSTREAM:origin, SECTALK_AUTH_RISK_SERVICE_KEY:serviceKey,
    SECTALK_AUTH_RISK_IDENTIFIER_SECRET:randomUUID(), SECTALK_DEVICE_BUNDLE_SERVICE_KEY:serviceKey,
    SECTALK_AUTH_RISK_FEED_URL:'http://127.0.0.1:'+feed.address().port+'/feed',
    SECTALK_AUTH_RISK_FEED_PUBLIC_KEY:publicKey.export({format:'der',type:'spki'}).toString('base64')},
})
function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}
const handle = 'sessionrisk_'+randomUUID().slice(0,8)
const email = handle+'@example.org'
const password = randomUUID()+'!zQ'
let browser, fixtureOwner
try {
  for (let i=0;i<40;i++) {
    if (child.exitCode!==null) throw new Error('Isolated local app server exited')
    const ready=await fetch(app,{signal:AbortSignal.timeout(2000)}).then(r=>r.ok).catch(()=>false)
    if (ready) break
    if (i===39) throw new Error('Isolated local app server unavailable')
    await setTimeout(1000)
  }
  fixtureOwner = data(await admin.auth.admin.createUser({email,password,email_confirm:true})).user
  const control = createClient(origin,publishable,options)
  data(await control.auth.signInWithPassword({email,password}))
  data(await control.rpc('st_save_profile',{p_handle:handle,p_name:'Session risk fixture'}))
  assert.equal(data(await control.rpc('st_v7_login_risk_status')),'clear')
  for (const identifier of [email,email,email,email,'missing_'+email]) {
    const response=await fetch(app+'/api/auth/sign-in',{
      method:'POST',headers:{'content-type':'application/json',Origin:app},
      body:JSON.stringify({email:identifier,password:'wrong-'+password}),
    })
    assert.equal(response.status,401)
    assert.deepEqual(await response.json(),{error:'invalid_credentials'})
  }
  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const page=await browser.newPage()
  await page.goto(app+'/#account')
  await page.getByLabel('Email address',{exact:true}).fill(email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  const login=page.waitForResponse(result=>result.url().endsWith('/api/auth/sign-in'))
  await page.locator('button.submit-auth').click()
  const verifiedTransport=await login
  assert.equal(verifiedTransport.status(),200)
  const content=await verifiedTransport.json()
  const result=await createClient(origin,publishable,{...options,global:{headers:{Authorization:'Bearer '+content.access_token}}})
    .from('st_profiles').select('id').eq('id',fixtureOwner.id).single()
  assert.equal(result.status,403)
  assert.equal(data(await createClient(origin,publishable,{...options,global:{headers:{Authorization:'Bearer '+content.access_token}}})
    .rpc('st_v7_login_risk_status')),'email')
  await page.getByText('Verify this sign-in',{exact:true}).waitFor()
  assert.ok(feedRequests>0)
  const rows=data(await control.rpc('st_v7_list_session_risk'))
  assert.equal(rows.length,1)
  assert.deepEqual(Object.keys(rows[0]).sort(),['band','provider','session_id','signals'])
  assert.equal(rows[0].band,'high')
  assert.equal(rows[0].provider,'matched')
  assert.deepEqual(rows[0].signals,['failed_sign_ins','asn_reputation','tor','vpn'])
  const ownerPage=await browser.newPage()
  await ownerPage.goto(app+'/#account')
  const {data:{session}}=await control.auth.getSession()
  await ownerPage.evaluate(({key,value})=>{
    localStorage.setItem(key,JSON.stringify(value))
  },{key:'sb-'+new URL(origin).hostname.split('.')[0]+'-auth-token',value:session})
  await ownerPage.reload()
  await ownerPage.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Profile',exact:true}).click()
  await ownerPage.getByRole('button',{name:'Devices and sessions',exact:true}).click()
  await ownerPage.getByText('Sign-in risk: high',{exact:true}).waitFor()
  const riskyCard=ownerPage.locator('article').filter({hasText:'Network reputation warning'})
  await riskyCard.getByRole('button',{name:'End device session',exact:true}).click()
  await riskyCard.getByRole('button',{name:'Confirm sign-out',exact:true}).click()
  await ownerPage.getByText('Device session ended.',{exact:true}).waitFor()
  assert.deepEqual(data(await control.rpc('st_v7_list_session_risk')),[])
  const {signedNetworkRisk}=await import('../apps/web/lib/session-risk-server.ts')
  process.env.SECTALK_AUTH_RISK_FEED_PUBLIC_KEY=publicKey.export({format:'der',type:'spki'}).toString('base64')
  const base='http://127.0.0.1:'+feed.address().port
  process.env.SECTALK_AUTH_RISK_FEED_URL=base+'/tampered'
  assert.equal(await signedNetworkRisk('192.0.2.7'),null)
  process.env.SECTALK_AUTH_RISK_FEED_URL=base+'/expired'
  assert.equal(await signedNetworkRisk('192.0.2.7'),null)
  process.env.SECTALK_AUTH_RISK_FEED_URL=base+'/specific'
  assert.equal((await signedNetworkRisk('192.0.2.7'))?.tor,false)
  assert.equal((await signedNetworkRisk('198.51.100.7'))?.tor,true)
  console.log('Signed network feed, invalid feed rejection, browser step-up, protected API denial, private risk projection and device sign-out passed.')
} finally {
  await browser?.close()
  if (fixtureOwner) await admin.auth.admin.deleteUser(fixtureOwner.id)
  feed.close()
  if(process.platform==='win32') {
    const cleanup=spawn('taskkill',['/pid',String(child.pid),'/t','/f'],{stdio:'ignore'})
    await new Promise(resolve=>cleanup.once('close',resolve).once('error',resolve))
  } else child.kill()
}
