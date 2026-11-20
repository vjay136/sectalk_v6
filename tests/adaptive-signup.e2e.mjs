// Local GoTrue sidecar on port 55329 with st_v7_before_signup enabled and QA SMTP.
import assert from 'node:assert/strict'
import {spawn,execFileSync} from 'node:child_process'
import {randomUUID} from 'node:crypto'
import {createServer,request as relay} from 'node:http'
import {resolve} from 'node:path'
import {setTimeout} from 'node:timers/promises'
import {createClient} from '@supabase/supabase-js'

const origin=new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
const app='http://127.0.0.1:3489'
const provider='http://127.0.0.1:55329'
const mail=new URL(process.env.SECTALK_AUTH_TEST_MAIL||'http://127.0.0.1:55324')
assert.equal(origin,'http://127.0.0.1:55321')
assert.equal(mail.hostname,'127.0.0.1')
const key=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const service=process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
const admin=createClient(origin,service,{auth:{persistSession:false,autoRefreshToken:false}})
const bridge=createServer((incoming,outgoing)=>{
  if (/^\/range\/[A-F0-9]{5}$/.test(incoming.url??'')) return outgoing.writeHead(200,{'Content-Type':'text/plain'}).end('A'.repeat(35)+':1\r\n')
  if (!['/auth/v1/signup','/auth/v1/resend'].includes((incoming.url??'').split('?')[0])) return outgoing.writeHead(404).end()
  const address=new URL(incoming.url.slice('/auth/v1'.length),provider)
  const upstream=relay(address,{method:incoming.method,headers:{...incoming.headers,host:address.host}},response=>{
    outgoing.writeHead(response.statusCode,response.headers)
    response.pipe(outgoing)
  })
  upstream.on('error',()=>outgoing.writeHead(502).end())
  incoming.pipe(upstream)
})
await new Promise((ready,fail)=>bridge.once('error',fail).listen(0,'127.0.0.1',ready))
const child=spawn(process.execPath,[resolve('node_modules/next/dist/bin/next'),'dev','--hostname','127.0.0.1','--port','3489'],{
  cwd:resolve(process.env.SECTALK_ADAPTIVE_SIGNUP_TEST_APP_DIR||'supabase/.temp/v4-auth-qa/device-commands-app'),stdio:'inherit',
  env:{...process.env,NEXT_PUBLIC_SUPABASE_URL:origin,NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:key,
    SECTALK_APP_URL:app,SECTALK_SIGNUP_ADMISSION_SERVICE_KEY:service,
    SECTALK_AUTH_SIGNUP_UPSTREAM:'http://127.0.0.1:'+bridge.address().port,
    SECTALK_TEST_PASSWORD_RANGE_ORIGIN:'http://127.0.0.1:'+bridge.address().port},
})
const suffix=randomUUID().replace(/-/g,'').replace(/[0-9]/g,n=>String.fromCharCode(103+Number(n)))
const ordinary='human_'+suffix+'@example.org'
const elevated='invited_'+suffix+'@example.org'
const raw='direct_'+suffix+'@example.org'
const password=randomUUID()+'!aQ'
let browser
function sql(input) {
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres'],
    {input,encoding:'utf8'}).trim()
}
async function delivered(email) {
  for(let attempt=0;attempt<30;attempt++) {
    const results=await (await fetch(new URL('/api/v1/search?query='+encodeURIComponent('to:'+email),mail))).json()
    const message=results.messages?.find(item=>/verify email/i.test(item.Subject))
    if(message)return (await fetch(new URL('/api/v1/message/'+message.ID,mail))).json()
    await setTimeout(500)
  }
  throw new Error('Native verification email was not captured')
}
async function fill(page,email) {
  await page.getByRole('button',{name:'Create account',exact:true}).click()
  await page.getByLabel('Email address',{exact:true}).fill(email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.getByLabel('Confirm password',{exact:true}).fill(password)
}
async function submit(page) {
  const result=page.waitForResponse(response=>response.url().endsWith('/api/auth/sign-up'))
  await page.locator('.submit-auth').click()
  return result
}
function request(body) {
  return fetch(app+'/api/auth/sign-up',{method:'POST',headers:{Origin:app,'Content-Type':'application/json'},body:JSON.stringify(body)})
}
try {
  for(let attempt=0;attempt<45;attempt++) {
    if(child.exitCode!==null) throw new Error('Local app exited')
    if(await fetch(app,{signal:AbortSignal.timeout(2000)}).then(r=>r.ok).catch(()=>false))break
    if(attempt===44)throw new Error('Local app unavailable')
    await setTimeout(1000)
  }
  const rejected=await fetch(provider+'/signup',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({email:raw,password})})
  assert.equal(rejected.status,403)
  const directOtp=await fetch(provider+'/otp',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({email:raw,create_user:true})})
  assert.equal(directOtp.status,403)
  assert.equal(sql("select count(*) from auth.users where email='"+raw+"';"),'0')
  const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const low=await browser.newPage()
  await low.goto(app+'/#account')
  await fill(low,ordinary)
  assert.equal((await submit(low)).status(),200)
  await low.getByRole('heading',{name:'Check your email'}).waitFor()
  const mailProof=await delivered(ordinary)
  const link=mailProof.HTML.match(/href="([^"]*\/auth\/confirm#[^"]+)"/)?.[1]
  assert.ok(link)
  assert.equal(new URL(link).origin,app)
  await low.goto(link)
  await low.getByRole('button',{name:'Verify my email'}).click()
  await low.getByRole('heading',{name:'Your email is verified'}).waitFor()

  const risky=await browser.newPage()
  const invite='f'.repeat(48)
  await risky.goto(app+'/invite#link='+invite)
  await risky.waitForURL('**/#account')
  await fill(risky,elevated)
  const challenged=await submit(risky)
  assert.equal(challenged.status(),428)
  const {challenge}=await challenged.json()
  assert.match(challenge,/^[a-f0-9]{64}$/)
  assert.equal(sql("select count(*) from auth.users where email='"+elevated+"';"),'0')
  assert.equal((await request({action:'signup',email:elevated,password,invite,challenge,solution:-1})).status,400)
  const completed=risky.waitForResponse(response=>response.url().endsWith('/api/auth/sign-up'))
  await risky.getByRole('button',{name:'Complete signup check',exact:true}).click()
  const accepted=await completed
  assert.equal(accepted.status(),200)
  assert.equal((await request(accepted.request().postDataJSON())).status,400)
  assert.ok(await delivered(elevated))
  assert.equal(sql("select count(*) from auth.users where email in ('"+ordinary+"','"+elevated+"') and raw_user_meta_data ? 'sectalk_signup_gate';"),'0')
  assert.equal(sql("select count(*) from auth.identities i join auth.users u on u.id=i.user_id where u.email in ('"+
    ordinary+"','"+elevated+"') and i.identity_data ? 'sectalk_signup_gate';"),'0')
  console.log('Ordinary native confirmation, direct native bypass rejection, invite-triggered browser proof, replay denial, and metadata privacy passed.')
} finally {
  await browser?.close()
  for(const email of [ordinary,elevated,raw]) {
    const id=sql("select id from auth.users where email='"+email+"';")
    if(id)await admin.auth.admin.deleteUser(id)
  }
  bridge.close()
  if(process.platform==='win32') {
    const cleanup=spawn('taskkill',['/pid',String(child.pid),'/t','/f'],{stdio:'ignore'})
    await new Promise(resolve=>cleanup.once('close',resolve).once('error',resolve))
  } else child.kill()
}
