import assert from 'node:assert/strict'
import {spawn,execFileSync} from 'node:child_process'
import {createHmac,randomUUID} from 'node:crypto'
import {createServer} from 'node:http'
import {resolve} from 'node:path'
import {setTimeout} from 'node:timers/promises'
import {createClient} from '@supabase/supabase-js'

const db=new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
assert.equal(db,'http://127.0.0.1:55321')
const app='http://127.0.0.1:3489'
const inbox='http://127.0.0.1:55425'
const service=process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
const publicKey=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const opts={auth:{persistSession:false,autoRefreshToken:false}}
const admin=createClient(db,service,opts)
const actor=createClient(db,publicKey,opts)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const suffix=randomUUID().slice(0,8)
const key='sk_test_'+randomUUID().replaceAll('-','')
const hook=randomUUID()
const worker=randomUUID()
const smtp=randomUUID()
const customer='cus_Renewal'+suffix
const subscription='sub_Renewal'+suffix
const invoice='in_Renewal'+suffix
const price='price_Renewal'+suffix
const email='renewal_'+suffix+'@example.invalid'
const now=Math.floor(Date.now()/1000)
const next=now+43200
let actorId,child,browser,attempt=1,invoiceState='open',subscriptionState='past_due',reads=0
function data(value) {if(value.error) throw value.error;return value.data}
function sql(statement) {
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true}).trim()
}
const fixture=createServer((request,response)=>{
  response.setHeader('Content-Type','application/json')
  if(request.method==='GET'&&request.headers.authorization==='Bearer '+key){
    if(request.url==='/v1/invoices/'+invoice){
      reads++
      return response.end(JSON.stringify({id:invoice,object:'invoice',livemode:false,customer,
        parent:{type:'subscription_details',subscription_details:{subscription}},
        billing_reason:'subscription_cycle',status:invoiceState,collection_method:'charge_automatically',attempted:true,
        amount_remaining:invoiceState==='paid'?0:1900,attempt_count:attempt,next_payment_attempt:invoiceState==='paid'?null:next,
        status_transitions:{finalized_at:now-3600},customer_email:'must-not-send@example.invalid'}))
    }
    if(request.url==='/v1/subscriptions/'+subscription){
      return response.end(JSON.stringify({id:subscription,customer,metadata:{sectalk_user:actorId},status:subscriptionState,
        cancel_at_period_end:false,items:{data:[{current_period_end:subscriptionState==='active'?now+604800:now-10,
          price:{id:price,unit_amount:1900,currency:'usd'}}]}}))
    }
  }
  response.writeHead(404).end(JSON.stringify({error:{message:'Unknown local fixture record'}}))
})
function event(label,type='invoice.payment_failed') {
  return JSON.stringify({id:'evt_renewal_'+suffix+label,type,created:now,livemode:false,data:{object:{id:invoice}}})
}
function webhook(body) {
  const timestamp=Math.floor(Date.now()/1000)
  const signature=createHmac('sha256',hook).update(timestamp+'.'+body).digest('hex')
  return fetch(app+'/api/billing/webhook',{method:'POST',body,headers:{'Stripe-Signature':'t='+timestamp+',v1='+signature}})
}
function drain(path,bearer) {
  return fetch(app+'/api/billing/'+path,{method:'POST',headers:{Authorization:'Bearer '+bearer}})
}
async function messages() {
  const url=new URL('/api/v1/search',inbox)
  url.searchParams.set('query','to:'+email)
  return (await fetch(url).then(result=>result.json())).messages
}
try {
  const password=randomUUID()+'!5aA'
  actorId=data(await admin.auth.admin.createUser({email,password,email_confirm:true})).user.id
  const session=data(await actor.auth.signInWithPassword({email,password})).session
  data(await actor.rpc('st_save_profile',{p_handle:'renewal_'+suffix,p_name:'Renewal fixture'}))
  sql("select public.st_v2_sync_billing('evt_seed_renewal_"+suffix+"','"+actorId+"','"+customer+"','"+subscription+
    "','business','active',now()+interval '1 day',false,now());")
  await new Promise((resolve,reject)=>fixture.once('error',reject).listen(0,'127.0.0.1',resolve))
  child=spawn(process.execPath,[resolve('node_modules/next/dist/bin/next'),'start','--hostname','127.0.0.1','--port','3489'],{
    cwd:resolve('supabase/.temp/v4-auth-qa/device-commands-app'),stdio:'inherit',env:{...process.env,
      NEXT_PUBLIC_SUPABASE_URL:db,NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:publicKey,SECTALK_BILLING_SUPABASE_KEY:service,
      SECTALK_APP_URL:app,STRIPE_SECRET_KEY:key,STRIPE_WEBHOOK_SECRET:hook,STRIPE_PRICE_BUSINESS_MONTHLY:price,
      SECTALK_TEST_STRIPE_ORIGIN:'http://127.0.0.1:'+fixture.address().port,SECTALK_STRIPE_RECONCILE_SECRET:worker,
      SECTALK_RENEWAL_MAIL_SECRET:smtp,SECTALK_NOTIFICATION_SMTP_HOST:'127.0.0.1',SECTALK_NOTIFICATION_SMTP_PORT:'55426',
      SECTALK_NOTIFICATION_SMTP_FROM:'billing-qa@example.invalid'},
  })
  let ready=false
  for(let i=0;i<40&&child.exitCode===null;i++){
    ready=await fetch(app+'/api/health',{signal:AbortSignal.timeout(2000)}).then(r=>r.ok).catch(()=>false)
    if(ready)break
    await setTimeout(500)
  }
  assert(ready)
  assert.equal((await fetch(app+'/api/billing/webhook',{method:'POST',body:event('First')})).status,400)
  assert.equal((await webhook(event('First'))).status,204)
  assert.equal((await webhook(event('First'))).status,204)
  assert.equal(reads,1)
  assert.equal((await webhook(event('DuplicateAttempt'))).status,204)
  const status=()=>actor.rpc('st_v7_renewal_status').then(data)
  const grace=await status()
  assert.equal(grace.state,'grace')
  assert.equal(Date.parse(grace.retry_at),next*1000)
  assert.equal(grace.attempt,1)
  assert.equal((await drain('renewal-mail','wrong')).status,401)
  const response=await drain('renewal-mail',smtp)
  assert.equal(response.status,200)
  let captured=[]
  for(let i=0;i<20;i++){
    captured=await messages()
    if(captured.length)break
    await setTimeout(200)
  }
  assert.equal(captured.length,1)
  const full=await fetch(inbox+'/api/v1/message/'+captured[0].ID).then(r=>r.json())
  assert.match(full.Text,/grace period ends/)
  assert.match(full.Text,/currently schedules another attempt/)
  assert.match(full.Text,/127\.0\.0\.1:3489\/\?billing=renewal/)
  assert.doesNotMatch(full.Text,/must-not-send|cus_|sub_Renewal/)
  await drain('renewal-mail',smtp)
  assert.equal((await messages()).length,1)

  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const page=await browser.newPage()
  await page.addInitScript(({name,value})=>localStorage.setItem(name,JSON.stringify(value)),
    {name:'sb-'+new URL(db).hostname.split('.')[0]+'-auth-token',value:session})
  await page.goto(app+'/?billing=renewal')
  const panel=page.getByRole('region',{name:'Renewal payment'})
  await panel.getByText(/Grace period ends/).waitFor()
  await panel.getByText(/Stripe currently schedules another attempt/).waitFor()
  attempt=2
  assert.equal((await webhook(event('Retry'))).status,204)
  assert.equal((await status()).grace_until,grace.grace_until)
  assert.equal((await status()).attempt,2)
  invoiceState='paid'
  subscriptionState='active'
  sql("insert into sectalk_private.st_v7_stripe_reconcile(subscription, ready_at, observed_at, lease, lease_until) values ('"+
    subscription+"',now()+interval '1 hour',now(),gen_random_uuid(),'-infinity');")
  assert.equal((await drain('reconcile',worker)).status,200)
  assert.equal((await status()).state,'clear')
  assert.equal((await webhook(event('Paid','invoice.paid'))).status,204)
  await drain('renewal-mail',smtp)
  assert.equal((await messages()).length,1)
  await page.reload()
  await page.getByRole('heading',{name:'Billing',exact:true}).waitFor()
  assert.equal(await panel.count(),0)
  assert.equal(sql("select stage from sectalk_private.st_v7_renewal_cases where invoice='"+invoice+"';"),'paid')
  assert.equal(sql("select count(*) from sectalk_private.st_v7_renewal_mail where invoice='"+invoice+"' and state='closed';"),'1')
  console.log('Verified renewal grace and next attempt, single local SMTP notice, and paid recovery through reconciliation')
} finally {
  await browser?.close()
  child?.kill()
  fixture.closeAllConnections()
  await new Promise(resolve=>fixture.close(resolve))
  if(actorId) await admin.auth.admin.deleteUser(actorId)
  sql("delete from sectalk_private.st_v7_stripe_receipts where id like 'evt_renewal_"+suffix+"%';"+
    "delete from sectalk_private.st_v2_billing_events where event_id like 'renewal:evt_renewal_"+suffix+"%' "+
    "or event_id like 'renewal-probe:"+invoice+":%' or event_id='evt_seed_renewal_"+suffix+"' or event_id in (select 'reconcile:'||lease::text "+
    "from sectalk_private.st_v7_stripe_reconcile where subscription='"+subscription+"');"+
    "delete from sectalk_private.st_v7_stripe_reconcile where subscription='"+subscription+"';")
}
