import assert from 'node:assert/strict'
import {createHmac,randomUUID} from 'node:crypto'
import {spawn,execFileSync} from 'node:child_process'
import {createServer} from 'node:http'
import {resolve} from 'node:path'
import {setTimeout} from 'node:timers/promises'
import {createClient} from '@supabase/supabase-js'
import {fixtureAuthenticator} from './workspace-admin-fixture.mjs'

const db=new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
assert.equal(db,'http://127.0.0.1:55321')
const app='http://127.0.0.1:3489'
const publicKey=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY,service=process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
const options={auth:{persistSession:false,autoRefreshToken:false}}
const admin=createClient(db,service,options)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const suffix=randomUUID().slice(0,8)
const version=40000000+parseInt(suffix.slice(0,6),16)
const key='rzp_test_'+suffix, apiSecret=randomUUID(), hook=randomUUID(), plan='plan_QA'+suffix
const subscription='sub_QA'+suffix, payment='pay_QA'+suffix, hosted='https://rzp.io/rzp/QA'+suffix
const now=Math.floor(Date.now()/1000)
const amount=89900
let browser,child,person,problem,providerPlanAmount=amount,providerPaymentAmount=amount,creates=0
let sub
const sql=statement=>execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
  '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true}).trim()
function value(result){if(result.error)throw result.error;return result.data}
const provider=createServer(async(req,res)=>{
  res.setHeader('Content-Type','application/json')
  try {
    assert.equal(req.headers.authorization,'Basic '+Buffer.from(key+':'+apiSecret).toString('base64'))
    let result
    if(req.method==='GET'&&req.url==='/v1/plans/'+plan){
      result={id:plan,entity:'plan',period:'monthly',interval:1,item:{amount:providerPlanAmount,currency:'INR'}}
    }else if(req.method==='GET'&&req.url==='/v1/subscriptions/'+subscription){
      result=sub
    }else if(req.method==='GET'&&req.url==='/v1/payments/'+payment){
      result={id:payment,entity:'payment',status:'captured',captured:true,currency:'INR',amount:providerPaymentAmount,amount_refunded:0}
    }else if(req.method==='POST'&&req.url==='/v1/subscriptions'){
      let text=''
      for await(const chunk of req)text+=chunk
      const input=JSON.parse(text)
      assert.equal(input.plan_id,plan)
      assert.equal(input.quantity,1)
      assert.equal(input.total_count,24)
      assert.equal(input.customer_notify,0)
      assert.ok(input.expire_by>now&&input.expire_by<=Math.floor(Date.now()/1000)+1800)
      assert.deepEqual(Object.keys(input.notes),['sectalk_checkout'])
      assert.match(input.notes.sectalk_checkout,/^[0-9a-f-]{36}$/)
      result=sub={id:subscription,plan_id:plan,entity:'subscription',status:'created',quantity:1,short_url:hosted,
        paid_count:0,notes:input.notes,current_start:null,current_end:null}
      creates++
    }
    if(!result)return res.writeHead(404).end(JSON.stringify({error:{description:'Unimplemented provider fixture'}}))
    res.end(JSON.stringify(result))
  } catch(error) {
    problem??=error
    res.writeHead(400).end(JSON.stringify({error:{description:'Provider fixture assertion failed'}}))
  }
})
const terms={action:'razorpay_checkout',plan:'professional',cadence:'monthly',version,currency:'INR'}
const call=(session,body)=>fetch(app+'/api/billing/action',{method:'POST',headers:{Authorization:'Bearer '+session.access_token,
  'Content-Type':'application/json'},body:JSON.stringify(body)})
function webhook(event,id,good=true) {
  const body=JSON.stringify(event)
  const signature=createHmac('sha256',good?hook:'wrong').update(body).digest('hex')
  return fetch(app+'/api/billing/webhook',{method:'POST',
    headers:{'X-Razorpay-Signature':signature,'X-Razorpay-Event-Id':id},body})
}
try {
  const email='razorpay_'+suffix+'@example.invalid',password=randomUUID()+'!4aS'
  person=value(await admin.auth.admin.createUser({email,password,email_confirm:true})).user
  const client=createClient(db,publicKey,options)
  value(await client.auth.signInWithPassword({email,password}))
  value(await client.rpc('st_save_profile',{p_handle:'razor_'+suffix,p_name:'Razorpay QA'}))
  const stale=value(await client.auth.getSession()).session
  await fixtureAuthenticator(client)
  const session=value(await client.auth.getSession()).session
  sql(`insert into sectalk_private.st_v6_plan_versions(plan,version,title,description,visible,active_from)
    values('professional',${version},'Pro','Local INR offer',true,now()-interval '1 minute');
    insert into sectalk_private.st_v6_plan_prices(plan,version,cadence,currency,amount,provider_price)
    values('professional',${version},'monthly','INR',${amount},'price_RazorpayQA${suffix}');`)
  await new Promise((ok,bad)=>provider.once('error',bad).listen(0,'127.0.0.1',ok))
  child=spawn(process.execPath,[resolve('node_modules/next/dist/bin/next'),'start','--hostname','127.0.0.1','--port','3489'],{
    cwd:resolve('supabase/.temp/v4-auth-qa/device-commands-app'),stdio:'inherit',env:{...process.env,
      NEXT_PUBLIC_SUPABASE_URL:db,NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:publicKey,SECTALK_BILLING_SUPABASE_KEY:service,
      SECTALK_APP_URL:app,STRIPE_SECRET_KEY:'',STRIPE_WEBHOOK_SECRET:'',RAZORPAY_KEY_ID:key,RAZORPAY_KEY_SECRET:apiSecret,
      RAZORPAY_WEBHOOK_SECRET:hook,RAZORPAY_PLAN_PROFESSIONAL_MONTHLY:plan,
      SECTALK_TEST_RAZORPAY_ORIGIN:'http://127.0.0.1:'+provider.address().port},
  })
  let ready=false
  for(let i=0;i<40&&child.exitCode===null;i++){
    ready=await fetch(app+'/api/health',{signal:AbortSignal.timeout(2000)}).then(r=>r.ok).catch(()=>false)
    if(ready)break
    await setTimeout(500)
  }
  assert(ready)
  assert.equal((await call(stale,terms)).status,403)
  assert.equal((await call(session,{...terms,version:1})).status,422)
  providerPlanAmount=amount+1
  assert.equal((await call(session,terms)).status,422)
  providerPlanAmount=amount
  assert.equal(creates,0)
  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const context=await browser.newContext()
  await context.route('https://rzp.io/**',route=>route.fulfill({contentType:'text/html',body:'<main>Hosted Razorpay fixture</main>'}))
  const page=await context.newPage()
  await page.addInitScript(({name,value})=>localStorage.setItem(name,JSON.stringify(value)),
    {name:'sb-'+new URL(db).hostname.split('.')[0]+'-auth-token',value:session})
  await page.goto(app+'/?billing=razorpay')
  await page.getByRole('button',{name:'Compare plans',exact:true}).click()
  await page.getByLabel('Currency').selectOption('INR')
  await page.getByRole('button',{name:'Continue with Razorpay'}).click()
  await page.waitForURL(hosted)
  await page.getByText('Hosted Razorpay fixture').waitFor()
  assert.equal(creates,1)
  assert.equal((await call(session,terms)).status,200)
  assert.equal(creates,1)
  const entitlement=async()=>value(await client.rpc('st_v7_my_entitlements')).plan
  assert.equal(await entitlement(),'free')

  sub.status='active'
  sub.current_start=now
  sub.current_end=now+30*86400
  sub.paid_count=1
  const event={event:'subscription.charged',created_at:now,payload:{subscription:{entity:sub},payment:{entity:{id:payment}}}}
  assert.equal((await webhook({...event,event:'subscription.authenticated'},'auth_'+suffix)).status,204)
  assert.equal((await webhook(event,'bad_'+suffix,false)).status,400)
  providerPaymentAmount=amount-1
  assert.equal((await webhook(event,'evt_'+suffix)).status,422)
  assert.equal(await entitlement(),'free')
  providerPaymentAmount=amount
  assert.equal((await webhook(event,'evt_'+suffix)).status,204)
  assert.equal((await webhook(event,'evt_'+suffix)).status,204)
  assert.equal(await entitlement(),'professional')
  assert.equal(sql(`select count(*) from sectalk_private.st_v8_razorpay_events where payment='${payment}';`),'1')
  await page.goto(app+'/?billing=razorpay')
  await page.getByText('Payment provider: Razorpay').waitFor()
  assert.ifError(problem)
  console.log('Razorpay hosted browser handoff, no Stripe required, approved INR pricing, fresh proof, HMAC capture, deduplication, and native entitlement passed')
} finally {
  await browser?.close()
  child?.kill()
  provider.closeAllConnections()
  await new Promise(ok=>provider.close(ok))
  if(person)await admin.auth.admin.deleteUser(person.id)
  sql(`delete from sectalk_private.st_v6_plan_prices where (plan,version)=('professional',${version});
    delete from sectalk_private.st_v7_plan_entitlements where (plan,version)=('professional',${version});
    delete from sectalk_private.st_v6_plan_versions where (plan,version)=('professional',${version});`)
}
