import assert from 'node:assert/strict'
import {execFileSync,spawn} from 'node:child_process'
import {createHmac,randomUUID} from 'node:crypto'
import {createServer} from 'node:http'
import {resolve} from 'node:path'
import {setTimeout} from 'node:timers/promises'
import {createClient} from '@supabase/supabase-js'

const db=new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
assert.equal(db,'http://127.0.0.1:55321')
const app='http://127.0.0.1:3489'
const publicKey=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const service=process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
const options={auth:{persistSession:false,autoRefreshToken:false}}
const supabase=createClient(db,service,options)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const suffix=randomUUID().slice(0,8)
const key='sk_test_portal'+suffix
const webhookSecret=randomUUID()
const configId='bpc_Portal'+suffix
const customer='cus_Portal'+suffix
const subscription='sub_Portal'+suffix
const price='price_Portal'+suffix
const dashboard='https://billing.stripe.com'
const returnUrl=app+'/?billing=portal-return'
const users=[]
const launches=[]
let owner,browser,child,cancelScheduled=false,misconfigure=false,unlinkedSubscription=false,unsafeRedirect=false,verifyCalls=0
const end=Math.floor(Date.now()/1000)+604800

function data(result){if(result.error)throw result.error;return result.data}
function sql(statement){
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true}).trim()
}
async function account(role){
  const email='portal_'+role+'_'+suffix+'@example.invalid'
  const password=randomUUID()+'!3Qz'
  const {user}=data(await supabase.auth.admin.createUser({email,password,email_confirm:true}))
  users.push(user.id)
  const client=createClient(db,publicKey,options)
  const {session}=data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:'portal_'+role+'_'+suffix,p_name:'Portal '+role}))
  return {id:user.id,session}
}
const stripe=createServer(async(request,response)=>{
  response.setHeader('Content-Type','application/json')
  const reject=()=>response.writeHead(404).end(JSON.stringify({error:{message:'Unbound local Stripe request'}}))
  if(request.headers.authorization!=='Bearer '+key)return reject()
  verifyCalls++
  if(request.method==='GET'&&request.url==='/v1/billing_portal/configurations/'+configId){
    return response.end(JSON.stringify({id:configId,active:true,livemode:false,application:null,login_page:{enabled:false},
      features:{payment_method_update:{enabled:true},invoice_history:{enabled:true},
        customer_update:{enabled:true,allowed_updates:['tax_id','address']},
        subscription_cancel:{enabled:true,mode:'at_period_end'},
        subscription_update:{enabled:true,default_allowed_updates:['price'],
          products:[{product:'prod_PortalQA',prices:[misconfigure?'price_unapprovedPortal':price]}]}}}))
  }
  if(request.method==='GET'&&request.url==='/v1/subscriptions/'+subscription){
    return response.end(JSON.stringify({id:subscription,customer:unlinkedSubscription?'cus_Foreign':customer,
      metadata:{sectalk_user:owner.id},status:'active',livemode:false,cancel_at_period_end:cancelScheduled,
      items:{data:[{current_period_end:end,price:{id:price,unit_amount:1900,currency:'usd'}}]}}))
  }
  if(request.method==='POST'&&request.url==='/v1/billing_portal/sessions'){
    let body=''
    for await(const chunk of request)body+=chunk
    const form=new URLSearchParams(body)
    launches.push(form)
    if(form.get('customer')!==customer||form.get('configuration')!==configId||form.get('return_url')!==returnUrl)return reject()
    const type=form.get('flow_data[type]')
    const flow=type ? {type,
      subscription_update:type==='subscription_update'?{subscription:form.get('flow_data[subscription_update][subscription]')}:null,
      subscription_cancel:type==='subscription_cancel'?{subscription:form.get('flow_data[subscription_cancel][subscription]')}:null} : null
    return response.end(JSON.stringify({customer,configuration:configId,return_url:returnUrl,livemode:false,flow,
      on_behalf_of:null,customer_account:null,url:(unsafeRedirect?'https://fake.example.invalid':dashboard)+'/p/session/test_'+suffix+'_'+launches.length}))
  }
  return reject()
})
function call(session,purpose,override={}){
  return fetch(app+'/api/billing/action',{method:'POST',headers:{Authorization:'Bearer '+session.access_token,'Content-Type':'application/json'},
    body:JSON.stringify({action:'portal',purpose,...override})})
}
async function reconcileCancellation(){
  const stamp=Math.floor(Date.now()/1000)
  const body=JSON.stringify({id:'evt_portal_'+suffix+'_scheduled',type:'customer.subscription.updated',created:stamp,
    livemode:false,data:{object:{id:subscription}}})
  const mac=createHmac('sha256',webhookSecret).update(stamp+'.'+body).digest('hex')
  const result=await fetch(app+'/api/billing/webhook',{method:'POST',body,headers:{'Stripe-Signature':'t='+stamp+',v1='+mac}})
  assert.equal(result.status,204,await result.text())
}

try{
  owner=await account('owner')
  const unrelated=await account('other')
  sql("select public.st_v2_sync_billing('evt_portal_"+suffix+"_seed','"+owner.id+"','"+customer+"','"+subscription+
    "','business','active',now()+interval '7 days',false,now());")
  await new Promise((resolve,reject)=>stripe.once('error',reject).listen(0,'127.0.0.1',resolve))
  child=spawn(process.execPath,[resolve('node_modules/next/dist/bin/next'),'start','--hostname','127.0.0.1','--port','3489'],{
    cwd:resolve('supabase/.temp/v4-auth-qa/device-commands-app'),stdio:'inherit',env:{...process.env,
      NEXT_PUBLIC_SUPABASE_URL:db,NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:publicKey,SECTALK_BILLING_SUPABASE_KEY:service,
      SECTALK_APP_URL:app,STRIPE_SECRET_KEY:key,STRIPE_WEBHOOK_SECRET:webhookSecret,
      STRIPE_PRICE_BUSINESS_MONTHLY:price,SECTALK_STRIPE_PORTAL_CONFIGURATION:configId,
      SECTALK_TEST_STRIPE_ORIGIN:'http://127.0.0.1:'+stripe.address().port},
  })
  let ready=false
  for(let i=0;i<40&&child.exitCode===null;i++){
    ready=await fetch(app+'/api/health',{signal:AbortSignal.timeout(2000)}).then(result=>result.ok).catch(()=>false)
    if(ready)break
    await setTimeout(500)
  }
  assert(ready)
  assert.equal((await call(unrelated.session,'overview',{customer,subscription})).status,404)
  const {session_id}=JSON.parse(Buffer.from(owner.session.access_token.split('.')[1],'base64url').toString())
  sql("update auth.mfa_amr_claims set updated_at=now()-interval '6 minutes' where session_id='"+session_id+"';")
  assert.equal((await call(owner.session,'overview')).status,403)
  assert.equal(verifyCalls,0)
  sql("update auth.mfa_amr_claims set updated_at=now() where session_id='"+session_id+"';")
  assert.equal((await call(owner.session,'reactivate')).status,409)
  misconfigure=true
  assert.equal((await call(owner.session,'overview')).status,503)
  misconfigure=false
  unlinkedSubscription=true
  assert.equal((await call(owner.session,'plan',{customer:'cus_Attacker'})).status,403)
  unlinkedSubscription=false
  assert.equal(launches.length,0)
  unsafeRedirect=true
  assert.equal((await call(owner.session,'overview')).status,502)
  unsafeRedirect=false
  assert.equal(sql("select count(*) from sectalk_private.st_v7_billing_portal_audit where account='"+owner.id+"';"),'0')

  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const context=await browser.newContext()
  await context.route('https://billing.stripe.com/**',route=>route.fulfill({contentType:'text/html',body:'<!doctype html><title>Synthetic Stripe portal</title><main>Local portal contract</main>'}))
  const page=await context.newPage()
  await page.addInitScript(({name,value})=>localStorage.setItem(name,JSON.stringify(value)),
    {name:'sb-'+new URL(db).hostname.split('.')[0]+'-auth-token',value:owner.session})
  async function launch(label,flow,field){
    await page.goto(returnUrl)
    await page.getByText('Stripe changes appear after the billing provider confirms them.',{exact:true}).waitFor()
    await page.getByText('Manage billing',{exact:true}).click()
    const external=page.waitForURL(url=>url.origin===dashboard)
    await page.getByRole('button',{name:label,exact:true}).click()
    await external
    await page.getByText('Local portal contract',{exact:true}).waitFor()
    const form=launches.at(-1)
    assert.equal(form.get('flow_data[type]'),flow)
    assert.equal(form.get('customer'),customer)
    assert.equal(form.get('return_url'),returnUrl)
    if(flow)assert.equal(form.get('flow_data[after_completion][redirect][return_url]'),returnUrl)
    if(field)assert.equal(form.get('flow_data['+field+'][subscription]'),subscription)
  }
  await launch('Update payment methods','payment_method_update')
  await launch('Change plan','subscription_update','subscription_update')
  await launch('View Stripe invoices',null)
  await launch('Manage tax IDs','customer_update')
  await launch('Schedule cancellation','subscription_cancel','subscription_cancel')
  cancelScheduled=true
  await reconcileCancellation()
  await launch('Keep subscription active',null)
  assert.equal(sql("select string_agg(purpose,',' order by purpose) from sectalk_private.st_v7_billing_portal_audit where account='"+owner.id+"';"),
    'cancel,invoices,payment_method,plan,reactivate,tax_ids')
  console.log('Scoped billing portal browser flows, provider configuration, cancellation/reactivation gates, and redacted audit passed')
} finally{
  await browser?.close()
  child?.kill()
  stripe.closeAllConnections()
  await new Promise(resolve=>stripe.close(resolve))
  sql("delete from sectalk_private.st_v7_stripe_receipts where id like 'evt_portal_"+suffix+"%';"+
    "delete from sectalk_private.st_v2_billing_events where event_id like 'evt_portal_"+suffix+"%';")
  for(const id of users)await supabase.auth.admin.deleteUser(id)
}
