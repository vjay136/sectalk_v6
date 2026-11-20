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
const service=process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
const publicKey=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const options={auth:{persistSession:false,autoRefreshToken:false}}
const admin=createClient(db,service,options)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const suffix=randomUUID().slice(0,8)
const revision=10000000+parseInt(suffix.slice(0,6),16)
const key='sk_test_plan'+suffix
const secret=randomUUID()
const ids={basic:'price_Basic'+suffix,professional:'price_Pro'+suffix,business:'price_Business'+suffix}
const amounts={basic:1000,professional:2000,business:3000}
const now=Math.floor(Date.now()/1000)
const end=now+140000
const start=now-140000
const subscriptions=new Map(),schedules=new Map(),creationKeys=new Map(),writes=[],users=[]
let browser,child,problem,failSchedule=true
function sql(statement){
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true}).trim()
}
function value(result){if(result.error)throw result.error;return result.data}
function price(plan){return {id:ids[plan],unit_amount:amounts[plan],active:true,livemode:false,currency:'usd',
  type:'recurring',billing_scheme:'per_unit',recurring:{interval:'month',interval_count:1,usage_type:'licensed'}}}
async function person(plan){
  const handle='plan_'+plan+'_'+suffix,email=handle+'@example.invalid',password=randomUUID()+'!4aS'
  const {user}=value(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  users.push(user.id)
  const client=createClient(db,publicKey,options)
  value(await client.auth.signInWithPassword({email,password}))
  value(await client.rpc('st_save_profile',{p_handle:handle,p_name:'Plan '+plan}))
  const stale=value(await client.auth.getSession()).session
  await fixtureAuthenticator(client)
  const session=value(await client.auth.getSession()).session
  const sub={object:'subscription',id:'sub_'+plan+suffix,customer:'cus_'+plan+suffix,metadata:{sectalk_user:user.id},
    status:'active',livemode:false,schedule:null,cancel_at_period_end:false,collection_method:'charge_automatically',items:{data:[{
      id:'si_'+plan+suffix,quantity:1,price:price(plan),current_period_start:start,current_period_end:end,
    }]}}
  subscriptions.set(sub.id,sub)
  sql(`insert into public.st_v2_subscriptions (user_id,customer_id,subscription_id,plan,status,period_end,catalog_version,
    billing_currency,billing_cadence,billing_amount) values ('${user.id}','${sub.customer}','${sub.id}','${plan}','active',
    to_timestamp(${end}),1,'USD','monthly',${amounts[plan]});`)
  return {sub,session,stale,id:user.id}
}
const provider=createServer(async(req,res)=>{
  res.setHeader('Content-Type','application/json')
  const url=new URL(req.url,'http://127.0.0.1')
  const [,,resource,id,subaction]=url.pathname.split('/')
  const read=()=>{const plan=Object.keys(ids).find(plan=>ids[plan]===id);return plan?price(plan):undefined}
  try {
    assert.equal(req.headers.authorization,'Bearer '+key)
    let result
    if(req.method==='GET'){
      result=resource==='subscriptions'?subscriptions.get(id):resource==='prices'?read():
        resource==='subscription_schedules'?schedules.get(id):undefined
    }else{
      let body=''
      for await(const chunk of req)body+=chunk
      const form=new URLSearchParams(body),requestKey=req.headers['idempotency-key']
      if(resource==='invoices'&&id==='create_preview'){
        assert.equal(form.get('subscription_details[items][0][price]'),ids.professional)
        assert.equal(form.get('subscription_details[proration_behavior]'),'always_invoice')
        result={currency:'usd',amount_due:2500,lines:{has_more:false,data:[
          {currency:'usd',amount:-500,parent:{subscription_item_details:{proration:true}}},
          {currency:'usd',amount:1000,parent:{subscription_item_details:{proration:true}}},
          {currency:'usd',amount:2000,parent:{subscription_item_details:{proration:false}}},
        ]}}
      }else if(resource==='subscriptions'){
        const sub=subscriptions.get(id)
        assert.match(requestKey,/^sectalk-plan-upgrade-/)
        assert.equal(form.get('payment_behavior'),'pending_if_incomplete')
        assert.equal(form.get('proration_behavior'),'always_invoice')
        assert.ok(Number(form.get('proration_date'))>=now)
        assert.equal(form.get('items[0][id]'),sub.items.data[0].id)
        assert.equal(form.get('items[0][price]'),ids.professional)
        sub.pending_update={subscription_items:[{id:sub.items.data[0].id,price:ids.professional}]}
        writes.push('upgrade');result=sub
      }else if(resource==='subscription_schedules'&&!id){
        const sub=subscriptions.get(form.get('from_subscription'))
        assert.match(requestKey,/^sectalk-plan-create-/)
        if(creationKeys.has(requestKey)) return res.end(JSON.stringify(creationKeys.get(requestKey)))
        assert.equal(sub.schedule,null)
        sub.schedule='sub_sched_'+suffix
        result={id:sub.schedule,subscription:sub.id,status:'active',metadata:{},current_phase:{start_date:start,end_date:end}}
        creationKeys.set(requestKey,structuredClone(result))
        schedules.set(result.id,result);writes.push('create')
      }else if(resource==='subscription_schedules'&&subaction==='release'){
        assert.match(requestKey,/^sectalk-plan-release-/)
        result=schedules.get(id)
        subscriptions.get(result.subscription).schedule=null
        result.status='released';writes.push('release')
      }else if(resource==='subscription_schedules'){
        assert.match(requestKey,/^sectalk-plan-schedule-/)
        if(failSchedule) return res.writeHead(503).end(JSON.stringify({error:{message:'Temporary schedule failure'}}))
        assert.equal(form.get('end_behavior'),'release')
        assert.equal(form.get('proration_behavior'),'none')
        assert.equal(form.get('phases[0][start_date]'),String(start))
        assert.equal(form.get('phases[0][end_date]'),String(end))
        assert.equal(form.get('phases[0][items][0][price]'),ids.business)
        assert.equal(form.get('phases[1][start_date]'),String(end))
        assert.equal(form.get('phases[1][duration][interval]'),'month')
        assert.equal(form.get('phases[1][proration_behavior]'),'none')
        writes.push(form.get('phases[1][items][0][price]'));result=schedules.get(id)
        result.metadata.sectalk_plan_change=form.get('metadata[sectalk_plan_change]')
      }
    }
    if(!result)return res.writeHead(404).end(JSON.stringify({error:{message:'Unimplemented fixture route'}}))
    res.end(JSON.stringify(result))
  } catch(error) {
    problem??=error
    res.writeHead(400).end(JSON.stringify({error:{message:'Provider assertion failed'}}))
  }
})

const call=(session,payload)=>fetch(app+'/api/billing/action',{
  method:'POST',headers:{Authorization:'Bearer '+session.access_token,'Content-Type':'application/json'},
  body:JSON.stringify({action:'plan_change',...payload}),
})
async function panel(person) {
  const context=await browser.newContext()
  const page=await context.newPage()
  await page.addInitScript(({name,value})=>localStorage.setItem(name,JSON.stringify(value)),
    {name:'sb-'+new URL(db).hostname.split('.')[0]+'-auth-token',value:person.session})
  await page.goto(app+'/?billing=plan-change')
  await page.getByRole('button',{name:'Manage plan changes'}).click()
  return {page,context}
}
try {
  const owners=await Promise.all(['business','basic'].map(person))
  const [business,basic]=owners
  sql(`insert into sectalk_private.st_v6_plan_versions(plan,version,title,description,visible,active_from)
    values ('basic',${revision},'Basic','Local downgrade fixture',true,now()-interval '1 minute');
    insert into sectalk_private.st_v6_plan_prices(plan,version,cadence,currency,amount,provider_price)
    values ('basic',${revision},'monthly','USD',${amounts.basic},'${ids.basic}');`)
  await new Promise((ok,bad)=>provider.once('error',bad).listen(0,'127.0.0.1',ok))
  child=spawn(process.execPath,[resolve('node_modules/next/dist/bin/next'),'start','--hostname','127.0.0.1','--port','3489'],{
    cwd:resolve('supabase/.temp/v4-auth-qa/device-commands-app'),stdio:'inherit',env:{...process.env,
      NEXT_PUBLIC_SUPABASE_URL:db,NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:publicKey,SECTALK_BILLING_SUPABASE_KEY:service,
      SECTALK_APP_URL:app,STRIPE_SECRET_KEY:key,STRIPE_WEBHOOK_SECRET:secret,STRIPE_PRICE_BASIC_MONTHLY:ids.basic,
      STRIPE_PRICE_PROFESSIONAL_MONTHLY:ids.professional,STRIPE_PRICE_BUSINESS_MONTHLY:ids.business,
      SECTALK_TEST_STRIPE_ORIGIN:'http://127.0.0.1:'+provider.address().port},
  })
  let ready=false
  for(let i=0;i<40&&child.exitCode===null;i++){
    ready=await fetch(app+'/api/health',{signal:AbortSignal.timeout(2000)}).then(r=>r.ok).catch(()=>false)
    if(ready)break
    await setTimeout(500)
  }
  assert(ready)
  assert.equal((await call(business.stale,{stage:'status'})).status,403)
  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const {page,context}=await panel(business)
  const requested=page.getByLabel('Requested plan')
  await requested.selectOption('professional')
  await page.getByRole('button',{name:'Preview change'}).click()
  await page.getByText(/Current terms: Business/).waitFor()
  await page.getByText(/Requested terms: Professional/).waitFor()
  let confirm=page.getByRole('button',{name:'Confirm scheduled downgrade'})
  assert.equal(writes.length,0)
  const confirmation=page.waitForRequest(request=>request.url().endsWith('/api/billing/action')&&request.postDataJSON()?.stage==='confirm')
  await confirm.click()
  const first=(await confirmation).postDataJSON().id
  await page.getByText(/payment provider could not complete the request/).waitFor()
  assert.deepEqual(writes,['create'])
  failSchedule=false
  sql(`update sectalk_private.st_v7_plan_changes set lease_until=now()-interval '1 second' where id='${first}';`)
  await page.getByRole('button',{name:'Refresh plan changes'}).click()
  await page.getByRole('button',{name:'Check or retry plan change'}).click()
  await page.getByText(/Scheduled downgrade to Professional/).waitFor()
  assert.equal((await call(basic.session,{stage:'confirm',id:first})).status,409)
  assert.equal((await call(business.session,{stage:'confirm',id:first})).status,200)
  await requested.selectOption('basic')
  await page.getByRole('button',{name:'Preview change'}).click()
  await page.getByText(/Replace the scheduled downgrade/).waitFor()
  await confirm.click()
  await page.getByText(/Scheduled downgrade to Basic/).waitFor()
  await page.getByRole('button',{name:'Review cancellation'}).click()
  await page.getByRole('button',{name:'Cancel scheduled downgrade'}).click()
  await page.getByText('The scheduled downgrade was canceled.').waitFor()
  assert.equal(business.sub.schedule,null)
  await context.close()

  const upgrade=await panel(basic)
  await upgrade.page.getByLabel('Requested plan').selectOption('professional')
  await upgrade.page.getByRole('button',{name:'Preview change'}).click()
  await upgrade.page.getByText(/net proration adjustment of .*5.00/).waitFor()
  await upgrade.page.getByRole('button',{name:'Confirm upgrade'}).click()
  await upgrade.page.getByText(/Your current plan remains active pending confirmation/).waitFor()
  assert.equal(sql(`select plan from public.st_v2_subscriptions where user_id='${basic.id}';`),'basic')
  basic.sub.items.data[0].price=price('professional')
  basic.sub.pending_update=null
  const event={id:'evt_plan_'+suffix,type:'customer.subscription.pending_update_applied',created:now,livemode:false,data:{object:basic.sub}}
  const bodyText=JSON.stringify(event)
  const stamp=Math.floor(Date.now()/1000)
  const signed=createHmac('sha256',secret).update(stamp+'.'+bodyText).digest('hex')
  const eventResponse=await fetch(app+'/api/billing/webhook',{method:'POST',headers:{'Stripe-Signature':`t=${stamp},v1=${signed}`},body:bodyText})
  assert.equal(eventResponse.status,204)
  assert.equal(sql(`select plan from public.st_v2_subscriptions where user_id='${basic.id}';`),'professional')
  assert.deepEqual(writes,['create',ids.professional,ids.basic,'release','upgrade'])
  assert.ifError(problem)
  console.log('Native plan changes, Stripe proration, scheduling/replacement/release, owner-only replay and signed entitlement reconciliation passed')
} finally {
  await browser?.close()
  child?.kill()
  provider.closeAllConnections()
  await new Promise(ok=>provider.close(ok))
  sql(`delete from sectalk_private.st_v7_stripe_receipts where id='evt_plan_${suffix}';
    delete from sectalk_private.st_v6_plan_prices where provider_price='${ids.basic}';
    delete from sectalk_private.st_v7_plan_entitlements where (plan,version)=('basic',${revision});
    delete from sectalk_private.st_v6_plan_versions where (plan,version)=('basic',${revision});`)
  for(const id of users)await admin.auth.admin.deleteUser(id)
}
