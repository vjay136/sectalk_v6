import assert from 'node:assert/strict'
import {execFileSync,spawn} from 'node:child_process'
import {createHmac,randomUUID} from 'node:crypto'
import {createServer} from 'node:http'
import {resolve} from 'node:path'
import {setTimeout} from 'node:timers/promises'
import {createClient} from '@supabase/supabase-js'
import {fixtureAuthenticator} from './workspace-admin-fixture.mjs'

const db=new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
assert.equal(db,'http://127.0.0.1:55321')
const app='http://127.0.0.1:3489'
const service=process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
const publicKey=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const options={auth:{persistSession:false,autoRefreshToken:false}}
const supabase=createClient(db,service,options)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const suffix=randomUUID().slice(0,8)
const key='sk_test_coupon'+suffix
const hook=randomUUID()
const workerSecret=randomUUID()
const price='price_Coupon'+suffix
const pro='price_Pro'+suffix
const percent='DEAL-'+suffix.toUpperCase()
const fixed='LESS-'+suffix.toUpperCase()
const percentCoupon='coupon_percent_'+suffix
const fixedCoupon='coupon_fixed_'+suffix
const started=Date.now()
const set=new Map()
const users=[]
let browser,child,mismatch=false

function sql(statement){
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true}).trim()
}
function value(result){if(result.error)throw result.error;return result.data}
async function person(label){
  const handle='coupon_'+label+'_'+suffix
  const email=handle+'@example.invalid'
  const password=randomUUID()+'!4aS'
  const {user}=value(await supabase.auth.admin.createUser({email,password,email_confirm:true}))
  users.push(user.id)
  const client=createClient(db,publicKey,options)
  const {session}=value(await client.auth.signInWithPassword({email,password}))
  value(await client.rpc('st_save_profile',{p_handle:handle,p_name:'Coupon '+label}))
  return {id:user.id,client,session}
}
const stripe=createServer(async (request,response)=>{
  const url=new URL(request.url,'http://127.0.0.1')
  response.setHeader('Content-Type','application/json')
  const problem=()=>response.writeHead(404).end(JSON.stringify({error:{message:'Unknown Stripe fixture path'}}))
  if(request.headers.authorization!=='Bearer '+key)return problem()
  if(request.method==='GET'&&['/v1/prices/'+price,'/v1/prices/'+pro].includes(url.pathname)){
    return response.end(JSON.stringify({id:url.pathname.split('/').at(-1),active:true,currency:'usd',
      type:'recurring',billing_scheme:'per_unit',product:'prod_QA',unit_amount:2500,
      recurring:{interval_count:1,interval:'month',usage_type:'licensed'}}))
  }
  if(request.method==='GET'&&['/v1/coupons/'+percentCoupon,'/v1/coupons/'+fixedCoupon].includes(url.pathname)){
    const pct=url.pathname.endsWith(percentCoupon)
    return response.end(JSON.stringify({id:pct?percentCoupon:fixedCoupon,livemode:false,valid:true,
      duration:pct?'repeating':'once',duration_in_months:pct?3:null,max_redemptions:1,times_redeemed:0,
      percent_off:pct?(mismatch?17:15):null,amount_off:pct?null:425,currency:pct?null:'usd',redeem_by:null,
      applies_to:{products:['prod_QA']}}))
  }
  if(request.method==='POST'&&url.pathname==='/v1/checkout/sessions'){
    let body=''
    for await(const chunk of request)body+=chunk
    const form=new URLSearchParams(body)
    const id='cs_test_'+suffix+'_'+(set.size+1)
    const coupon=form.get('discounts[0][coupon]')
    const record={id,object:'checkout.session',mode:'subscription',status:'open',livemode:false,subscription:null,
      payment_status:'unpaid',url:'https://checkout.stripe.com/c/pay/'+id,customer:null,
      expires_at:Number(form.get('expires_at')),currency:form.get('currency'),
      client_reference_id:form.get('client_reference_id'),metadata:coupon?{sectalk_coupon:form.get('metadata[sectalk_coupon]'),
        sectalk_coupon_hold:form.get('metadata[sectalk_coupon_hold]')}:{},
      discounts:coupon?[{coupon,promotion_code:null}]:null,
      line_items:{has_more:false,data:[{price:{id:form.get('line_items[0][price]')},quantity:1}]}}
    assert.equal(form.get('allow_promotion_codes'),coupon?null:'false')
    assert.equal(form.get('payment_method_types[0]'),coupon?'card':null)
    if(coupon) assert.equal(request.headers['idempotency-key'],'sectalk-checkout-'+record.metadata.sectalk_coupon_hold)
    set.set(id,{record,form})
    return response.end(JSON.stringify(record))
  }
  if(request.method==='GET'&&url.pathname.startsWith('/v1/checkout/sessions/')){
    const entry=set.get(url.pathname.split('/').at(-1))
    if(entry)return response.end(JSON.stringify(entry.record))
  }
  return problem()
})
async function webEvent(entry,label,eventType){
  const stamp=Math.floor(Date.now()/1000)
  const body=JSON.stringify({id:'evt_coupon_'+suffix+label,type:eventType,livemode:false,created:stamp,
    data:{object:{id:entry.record.id,mode:'subscription',metadata:entry.record.metadata}}})
  const mac=createHmac('sha256',hook).update(stamp+'.'+body).digest('hex')
  return fetch(app+'/api/billing/webhook',{method:'POST',headers:{'Stripe-Signature':'t='+stamp+',v1='+mac},body})
}
function checkout(person,coupon,plan='business'){
  return fetch(app+'/api/billing/action',{method:'POST',headers:{Authorization:'Bearer '+person.session.access_token,'Content-Type':'application/json'},
    body:JSON.stringify({action:'checkout',plan,cadence:'monthly',currency:'USD',version:1,...(coupon?{coupon}:{})})})
}
try{
  const operator=await person('ops')
  const [a,b,c,d]=await Promise.all(['one','two','three','four'].map(person))
  sql("insert into sectalk_private.staff(user_id) values ('"+operator.id+"');"+
    "insert into sectalk_private.st_v7_coupon_operators values ('"+operator.id+"');")
  await fixtureAuthenticator(operator.client)
  const terms={enabled:true,plans:['business'],currencies:['USD'],max_redemptions:1,
    starts_at:new Date(started-60000).toISOString(),ends_at:new Date(started+86400000).toISOString()}
  value(await operator.client.rpc('st_v7_publish_coupon',{p_code:percent,p_revision:0,p_terms:{...terms,
    coupon:percentCoupon,percent_bps:1500,duration:'repeating',months:3}}))
  value(await operator.client.rpc('st_v7_publish_coupon',{p_code:fixed,p_revision:0,p_terms:{...terms,
    coupon:fixedCoupon,amount_off:425,duration:'once'}}))
  await new Promise((resolve,reject)=>stripe.once('error',reject).listen(0,'127.0.0.1',resolve))
  child=spawn(process.execPath,[resolve('node_modules/next/dist/bin/next'),'start','--hostname','127.0.0.1','--port','3489'],{
    cwd:resolve('supabase/.temp/v4-auth-qa/device-commands-app'),stdio:'inherit',env:{...process.env,
      NEXT_PUBLIC_SUPABASE_URL:db,NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:publicKey,SECTALK_BILLING_SUPABASE_KEY:service,
      SECTALK_APP_URL:app,STRIPE_SECRET_KEY:key,STRIPE_WEBHOOK_SECRET:hook,
      STRIPE_PRICE_BUSINESS_MONTHLY:price,STRIPE_PRICE_PROFESSIONAL_MONTHLY:pro,SECTALK_STRIPE_RECONCILE_SECRET:workerSecret,
      SECTALK_TEST_STRIPE_ORIGIN:'http://127.0.0.1:'+stripe.address().port},
  })
  let ready=false
  for(let i=0;i<40&&child.exitCode===null;i++){
    ready=await fetch(app+'/api/health',{signal:AbortSignal.timeout(2000)}).then(r=>r.ok).catch(()=>false)
    if(ready)break
    await setTimeout(500)
  }
  assert(ready)
  mismatch=true
  assert.equal((await checkout(a,percent)).status,422)
  mismatch=false
  assert.equal((await checkout(a,percent,'professional')).status,422)
  assert.equal(set.size,0)

  const calls=await Promise.all([checkout(a,percent),checkout(b,percent)])
  assert.deepEqual(calls.map(response=>response.status).sort(),[200,409])
  const chosen=calls[0].ok?a:b
  const rejected=calls[0].ok?b:a
  const original=[...set.values()][0]
  assert.equal(original.record.client_reference_id,chosen.id)
  assert.equal((await checkout(chosen)).status,409)
  assert.equal(set.size,1)
  original.record.status='expired'
  assert.equal((await webEvent(original,'Expired','checkout.session.expired')).status,204)
  assert.equal((await checkout(rejected,percent)).status,200)
  const final=[...set.values()][1]
  final.record.status='complete'
  assert.equal((await webEvent(final,'PendingPayment','checkout.session.completed')).status,204)
  assert.equal(sql("select state from sectalk_private.st_v7_coupon_holds where provider_session='"+final.record.id+"';"),'held')
  final.record.payment_status='paid'
  final.record.subscription='sub_CouponQA'
  const complete=await webEvent(final,'Completed','checkout.session.completed')
  assert.equal(complete.status,204)
  assert.equal(sql("select string_agg(state,',' order by state) from sectalk_private.st_v7_coupon_holds where code='"+percent+"';"),'expired,redeemed')
  assert.equal((await checkout(chosen,percent)).status,409)
  assert.equal((await checkout(d)).status,200)

  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const context=await browser.newContext()
  await context.route('https://checkout.stripe.com/**',route=>route.fulfill({contentType:'text/html',body:'<main>Loopback Stripe Checkout</main>'}))
  const page=await context.newPage()
  await page.addInitScript(({name,value})=>localStorage.setItem(name,JSON.stringify(value)),
    {name:'sb-'+new URL(db).hostname.split('.')[0]+'-auth-token',value:c.session})
  await page.goto(app+'/?billing=coupons')
  await page.getByRole('button',{name:'Compare plans',exact:true}).click()
  await page.getByLabel('Coupon code (optional)').fill(fixed.toLowerCase())
  const plan=page.getByRole('article').filter({has:page.getByRole('heading',{name:'Team',exact:true})})
  await plan.getByRole('button',{name:'Continue to checkout',exact:true}).click()
  await page.waitForURL(url=>url.origin==='https://checkout.stripe.com')
  await page.getByText('Loopback Stripe Checkout').waitFor()
  const bill=[...set.values()].at(-1)
  assert.equal(bill.record.discounts[0].coupon,fixedCoupon)
  assert.equal(bill.record.currency,'usd')
  assert.equal(sql("select count(*) from sectalk_private.st_v7_coupon_holds where code='"+fixed+"' and state='held';"),'1')
  const elapsedExpiry=Math.floor(Date.now()/1000)-1
  sql("update sectalk_private.st_v7_coupon_holds set expires_at=to_timestamp("+elapsedExpiry+") where code='"+fixed+"';")
  bill.record.expires_at=elapsedExpiry
  bill.record.status='expired'
  const reconciled=await fetch(app+'/api/billing/reconcile',{method:'POST',headers:{Authorization:'Bearer '+workerSecret}})
  assert.equal(reconciled.status,200)
  assert.equal(sql("select state from sectalk_private.st_v7_coupon_holds where code='"+fixed+"';"),'expired')
  console.log('Managed coupon browser, exact Stripe terms, atomic cap, signed expiry/completion, missed-expiry reconciliation, and ordinary Checkout passed')
} finally {
  await browser?.close()
  child?.kill()
  stripe.closeAllConnections()
  await new Promise(resolve=>stripe.close(resolve))
  sql("delete from sectalk_private.st_v7_coupon_holds where code in ('"+percent+"','"+fixed+"');"+
    "delete from sectalk_private.st_v7_coupon_versions where code in ('"+percent+"','"+fixed+"');"+
    "delete from sectalk_private.st_v7_coupon_campaigns where code in ('"+percent+"','"+fixed+"');"+
    "delete from sectalk_private.st_v7_stripe_receipts where id like 'evt_coupon_"+suffix+"%';")
  for(const id of users)await supabase.auth.admin.deleteUser(id)
}
