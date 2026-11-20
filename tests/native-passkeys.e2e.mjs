// The QA Auth sidecar listens on loopback port 55329 with native passkeys enabled,
// RP ID localhost, and RP origin http://localhost:3489. The app copy stays isolated.
import assert from 'node:assert/strict'
import {spawn} from 'node:child_process'
import {randomUUID} from 'node:crypto'
import {createServer,request as call} from 'node:http'
import {resolve} from 'node:path'
import {setTimeout} from 'node:timers/promises'
import {createClient} from '@supabase/supabase-js'

const origin=new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
const provider='http://127.0.0.1:55329'
const app='http://localhost:3489'
const appDir=resolve('supabase/.temp/v4-auth-qa/device-commands-app')
const next=resolve('node_modules/next/dist/bin/next')
assert.equal(origin,'http://127.0.0.1:55321')
const key=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const service=process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
const options={auth:{persistSession:false,autoRefreshToken:false}}
const bridge=createServer((incoming,outgoing)=>{
  const path=incoming.url??''
  const passkeys=path.startsWith('/auth/v1/passkeys')
  const expected=passkeys?provider:origin
  const target=new URL(passkeys?path.slice('/auth/v1'.length):path,expected)
  if (!path.startsWith('/') || target.origin!==expected) {
    outgoing.writeHead(400).end()
    return
  }
  const headers={...incoming.headers,host:target.host}
  const upstream=call(target,{method:incoming.method,headers},reply=>{
    outgoing.writeHead(reply.statusCode,{...reply.headers,
      'access-control-allow-origin':app,'access-control-allow-headers':incoming.headers['access-control-request-headers']||'*',
      'access-control-allow-methods':'GET,POST,PATCH,DELETE,PUT,OPTIONS'})
    reply.pipe(outgoing)
  })
  upstream.on('error',()=>{outgoing.statusCode=502;outgoing.end()})
  incoming.pipe(upstream)
})
await new Promise((ready,fail)=>bridge.once('error',fail).listen(0,'127.0.0.1',ready))
const bridgeUrl='http://127.0.0.1:'+bridge.address().port
const child=spawn(process.execPath,[next,'dev','--hostname','127.0.0.1','--port','3489'],{
  cwd:appDir,stdio:'inherit',
  env:{...process.env,NEXT_PUBLIC_SUPABASE_URL:bridgeUrl,NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:key,
    SECTALK_AUTH_PASSWORD_UPSTREAM:origin,SECTALK_DEVICE_BUNDLE_SERVICE_KEY:service,
    NEXT_PUBLIC_SECTALK_PASSKEYS_ENABLED:'true'},
})
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const admin=createClient(origin,service,options)
const plain=createClient(origin,key,options)
function data(result) {if(result.error) throw new Error(result.error.message);return result.data}
const handle='pkqa_'+randomUUID().slice(0,8)
const email=handle+'@example.org'
const password=randomUUID()+'!qR'
let browser,user,highToken
try {
  for(let i=0;i<45;i++){
    if(child.exitCode!==null) throw new Error('Local app exited')
    const ready=await fetch('http://127.0.0.1:3489',{signal:AbortSignal.timeout(2000)}).then(r=>r.ok).catch(()=>false)
    if(ready) break
    if(i===44) throw new Error('Local passkey app not ready')
    await setTimeout(1000)
  }
  user=data(await admin.auth.admin.createUser({email,password,email_confirm:true})).user
  const initial=data(await plain.auth.signInWithPassword({email,password})).session
  data(await plain.rpc('st_save_profile',{p_handle:handle,p_name:'Passkey test'}))
  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const page=await browser.newPage()
  const cdp=await page.context().newCDPSession(page)
  await cdp.send('WebAuthn.enable')
  await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{
    protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,
    automaticPresenceSimulation:true,
  }})
  const button=(scope,name)=>scope.getByRole('button',{name,exact:true})
  const nav=page.getByRole('navigation',{name:'SecTalk features'})
  const panel=page.getByRole('region',{name:'Passkeys',exact:true})
  async function profile() {
    await button(nav,'Profile').click()
    await button(page,'Security').click()
    await panel.waitFor()
  }
  await page.goto(app+'/#account')
  await page.getByLabel('Email address',{exact:true}).fill(email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await profile()
  const registration=page.waitForResponse(r=>r.url().endsWith('/passkeys/registration/verify'))
  await button(panel,'Register a passkey').click()
  assert.equal((await registration).status(),200)
  await panel.getByText('Passkey registered.',{exact:true}).waitFor()
  await button(panel,'Rename passkey').click()
  await panel.getByLabel('Passkey name').fill('Loopback authenticator')
  await button(panel,'Save passkey name').click()
  await panel.getByText('Loopback authenticator',{exact:true}).waitFor()
  await button(panel,'Use passwordless-only sign-in').click()
  await button(panel,'Confirm passwordless-only sign-in').click()
  await panel.getByText('Sign out and sign in with a passkey before changing this setting.',{exact:true}).waitFor()

  await button(page,'Sign out').press('Enter')
  const authentication=page.waitForResponse(r=>r.url().endsWith('/passkeys/authentication/verify'))
  await button(page,'Sign in with a passkey').click()
  const signed=await authentication
  assert.equal(signed.status(),200)
  const replay=await fetch(provider+'/passkeys/authentication/verify',{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:signed.request().postData(),
  })
  assert.equal(replay.status,400)
  const native=await signed.json()
  highToken=native.access_token
  const jwt=JSON.parse(Buffer.from(highToken.split('.')[1],'base64url').toString())
  assert.ok(jwt.amr.some(method=>method.method==='passkey'))
  await profile()
  await button(panel,'Use passwordless-only sign-in').click()
  await button(panel,'Confirm passwordless-only sign-in').click()
  await panel.getByText('Passwordless-only sign-in enabled.',{exact:true}).waitFor()
  assert.ok(await button(panel,'Remove passkey').isDisabled())
  const raw=await createClient(origin,key,options).auth.signInWithPassword({email,password})
  assert.ok(raw.error)
  const appPassword=await fetch(app+'/api/auth/sign-in',{method:'POST',headers:{'Content-Type':'application/json',Origin:app},
    body:JSON.stringify({email,password})})
  assert.equal(appPassword.status,401)
  assert.deepEqual(await appPassword.json(),{error:'invalid_credentials'})
  const stale=await fetch(origin+'/rest/v1/st_profiles?select=id',{headers:{apikey:key,Authorization:'Bearer '+initial.access_token}})
  assert.equal(stale.status,401)
  const scoped={Authorization:'Bearer '+highToken,apikey:key}
  const list=await (await fetch(provider+'/passkeys',{headers:scoped})).json()
  assert.equal(list.length,1)
  const refused=await fetch(provider+'/passkeys/'+list[0].id,{method:'DELETE',headers:scoped})
  assert.ok(!refused.ok)
  assert.equal((await (await fetch(provider+'/passkeys',{headers:scoped})).json()).length,1)
  await button(page,'Sign out').press('Enter')
  const passwordlessLogin=page.waitForResponse(r=>r.url().endsWith('/passkeys/authentication/verify'))
  await button(page,'Sign in with a passkey').click()
  const passwordlessResponse=await passwordlessLogin
  assert.equal(passwordlessResponse.status(),200)
  highToken=(await passwordlessResponse.json()).access_token
  await profile()
  await button(panel,'Restore password sign-in').click()
  await button(panel,'Confirm password sign-in').click()
  await panel.getByText('Password sign-in restored.',{exact:true}).waitFor()
  await button(panel,'Remove passkey').click()
  await button(panel,'Confirm passkey removal').click()
  await panel.getByText('Passkey removed.',{exact:true}).waitFor()
  data(await createClient(origin,key,options).auth.signInWithPassword({email,password}))
  console.log('Native virtual WebAuthn enrollment, rename, login, passwordless-only native grant policy, last-key protection, restoration and removal passed.')
} finally {
  if (highToken) await fetch(origin+'/rest/v1/rpc/st_v7_passkey_only',{method:'POST',headers:{apikey:key,
    'Content-Type':'application/json',Authorization:'Bearer '+highToken},body:JSON.stringify({p_enabled:false})}).catch(()=>{})
  if(user) await admin.auth.admin.deleteUser(user.id)
  await browser?.close()
  bridge.close()
  if(process.platform==='win32'){
    const cleanup=spawn('taskkill',['/pid',String(child.pid),'/t','/f'],{stdio:'ignore'})
    await new Promise(resolve=>cleanup.once('close',resolve).once('error',resolve))
  } else child.kill()
}
