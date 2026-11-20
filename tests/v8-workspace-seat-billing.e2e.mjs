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
const service=process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,publicKey=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const options={auth:{persistSession:false,autoRefreshToken:false}}
const admin=createClient(db,service,options)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const suffix=randomUUID().slice(0,8)
const key='sk_test_seats_'+suffix,secret=randomUUID(),workerSecret=randomUUID(),price='price_QASeats'+suffix,customer='cus_QASeats'+suffix
const base='sub_QABase'+suffix,addon='sub_QASeats'+suffix,item='si_QASeat'+suffix,invoice='in_QASeats'+suffix
const oldInvoice='in_QAOldSeats'+suffix
const time=Math.floor(Date.now()/1000)
let period=time+86400, workspace, owner, subscription, browser, child, problem
let paid=false
const writes=[],users=[]
const sql=statement=>execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
  '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true}).trim()
function value(result){if(result.error)throw result.error;return result.data}
async function person(label){
  const handle='seats_'+label+'_'+suffix,email=handle+'@example.invalid',password=randomUUID()+'!4aS'
  const {user}=value(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  users.push(user.id)
  const client=createClient(db,publicKey,options)
  value(await client.auth.signInWithPassword({email,password}))
  value(await client.rpc('st_save_profile',{p_handle:handle,p_name:'Seat '+label}))
  const stale=value(await client.auth.getSession()).session
  return {id:user.id,client,stale}
}
const provider=createServer(async(req,res)=>{
  res.setHeader('Content-Type','application/json')
  try {
    assert.equal(req.headers.authorization,'Bearer '+key)
    const [,,resource,id]=new URL(req.url,'http://127.0.0.1').pathname.split('/')
    let result
    if(req.method==='GET'&&resource==='prices'&&id===price){
      result={id:price,active:true,livemode:false,type:'recurring',billing_scheme:'per_unit',unit_amount:350,currency:'usd',
        recurring:{interval:'month',interval_count:1,usage_type:'licensed'}}
    }else if(req.method==='GET'&&resource==='subscriptions'){
      result=id===base?{id:base,customer,status:'active',livemode:false,metadata:{sectalk_user:owner.id},default_payment_method:'pm_demo'}:
        id===addon?subscription:null
    }else if(req.method==='GET'&&resource==='invoices'&&(id===invoice||id===oldInvoice)){
      result={id,customer,livemode:false,billing_reason:'subscription_cycle',collection_method:'charge_automatically',
        parent:{subscription_details:{subscription:addon}},status:paid?'paid':'open',status_transitions:{finalized_at:time},
        amount_remaining:paid?0:700,attempted:true}
    }else if(req.method==='DELETE'&&resource==='subscriptions'&&id===addon){
      subscription.status='canceled'
      result=subscription
    }else if(req.method==='POST'&&resource==='subscriptions'){
      let body=''
      for await(const chunk of req)body+=chunk
      const form=new URLSearchParams(body)
      const quantity=Number(form.get('items[0][quantity]'))
      assert.match(req.headers['idempotency-key'],/^sectalk-workspace-seats-[0-9a-f-]+$/)
      assert.equal(form.get('payment_behavior'),'error_if_incomplete')
      if(!id){
        assert.equal(form.get('customer'),customer)
        assert.equal(form.get('items[0][price]'),price)
        assert.equal(form.get('metadata[sectalk_workspace_seats]'),workspace)
        assert.equal(form.get('default_payment_method'),'pm_demo')
      }else{
        assert.equal(id,addon)
        assert.equal(form.get('items[0][id]'),item)
        assert.equal(form.get('proration_behavior'),'always_invoice')
      }
      subscription={id:addon,customer,metadata:{sectalk_workspace_seats:workspace},livemode:false,status:'active',latest_invoice:invoice,
        items:{data:[{id:item,quantity,current_period_end:period,price:{id:price}}]}}
      writes.push(quantity)
      result=subscription
    }
    if(!result)return res.writeHead(404).end(JSON.stringify({error:{message:'Unimplemented provider fixture'}}))
    res.end(JSON.stringify(result))
  } catch(error) {
    problem??=error
    res.writeHead(400).end(JSON.stringify({error:{message:'Provider fixture assertion failed'}}))
  }
})

function seatRequest(person,body,stale=false) {
  return fetch(app+'/api/billing/workspace',{method:'POST',headers:{Authorization:'Bearer '+(stale?person.stale:person.session).access_token,
    'Content-Type':'application/json'},body:JSON.stringify({workspace,...body})})
}
async function webhook(event) {
  const body=JSON.stringify(event)
  const stamp=Math.floor(Date.now()/1000)
  const signed=createHmac('sha256',secret).update(stamp+'.'+body).digest('hex')
  return fetch(app+'/api/billing/webhook',{method:'POST',headers:{'Stripe-Signature':`t=${stamp},v1=${signed}`},body})
}
try {
  owner=await person('owner')
  const [invitee, outsider]=await Promise.all(['invitee','outsider'].map(person))
  for(const actor of [owner,outsider]){
    await fixtureAuthenticator(actor.client)
    actor.session=value(await actor.client.auth.getSession()).session
  }
  workspace=value(await owner.client.rpc('st_v2_create_workspace',{p_name:'Seat QA '+suffix}))
  sql(`insert into public.st_v2_subscriptions (user_id,customer_id,subscription_id,plan,status,period_end,catalog_version,
    billing_currency,billing_cadence,billing_amount) values ('${owner.id}','${customer}','${base}','business','active',
    to_timestamp(${period}),1,'USD','monthly',3000);`)
  await new Promise((ok,bad)=>provider.once('error',bad).listen(0,'127.0.0.1',ok))
  child=spawn(process.execPath,[resolve('node_modules/next/dist/bin/next'),'start','--hostname','127.0.0.1','--port','3489'],{
    cwd:resolve('supabase/.temp/v4-auth-qa/device-commands-app'),stdio:'inherit',env:{...process.env,
      NEXT_PUBLIC_SUPABASE_URL:db,NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:publicKey,SECTALK_BILLING_SUPABASE_KEY:service,
      SECTALK_APP_URL:app,STRIPE_SECRET_KEY:key,STRIPE_WEBHOOK_SECRET:secret,STRIPE_WORKSPACE_SEAT_USD_MONTHLY:price,
      SECTALK_STRIPE_RECONCILE_SECRET:workerSecret,
      SECTALK_TEST_STRIPE_ORIGIN:'http://127.0.0.1:'+provider.address().port},
  })
  let ready=false
  for(let i=0;i<40&&child.exitCode===null;i++){
    ready=await fetch(app+'/api/health',{signal:AbortSignal.timeout(2000)}).then(r=>r.ok).catch(()=>false)
    if(ready)break
    await setTimeout(500)
  }
  assert(ready)
  assert.equal((await seatRequest(owner,{stage:'status'},true)).status,403)
  assert.equal((await seatRequest(outsider,{stage:'status'})).status,403)
  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const page=await browser.newPage()
  await page.addInitScript(({name,value})=>localStorage.setItem(name,JSON.stringify(value)),
    {name:'sb-'+new URL(db).hostname.split('.')[0]+'-auth-token',value:owner.session})
  await page.goto(app+'/billing/workspaces')
  await page.getByLabel('Workspace',{exact:true}).selectOption(workspace)
  await page.getByRole('button',{name:'Review workspace seats'}).click()
  await page.getByText(/Paid seat billing inactive/).waitFor()
  await page.getByRole('button',{name:'Review quantity change'}).click()
  await page.getByRole('button',{name:'Approve seat charge'}).click()
  await page.getByText(/Stripe confirmed 1 workspace seats?\./).waitFor()
  assert.deepEqual(writes,[1])
  const invitation=sql(`insert into public.st_v2_invites(workspace_id,invitee,created_by,workspace_name)
    values ('${workspace}','${invitee.id}','${owner.id}','Seat QA') returning id;`).split(/\s/)[0]
  const before=await invitee.client.rpc('st_v2_reply_invite',{p_invite:invitation,p_accept:true})
  assert.match(before.error?.message??'',/seat capacity/i)
  await page.getByRole('button',{name:'Refresh seats'}).click()
  await page.getByRole('button',{name:'Review seats for invitations'}).click()
  assert.deepEqual(writes,[1])
  await page.getByRole('button',{name:'Approve seat charge'}).click()
  await page.getByText('Stripe confirmed 2 workspace seats.').waitFor()
  assert.deepEqual(writes,[1,2])
  assert.equal(value(await invitee.client.rpc('st_v2_reply_invite',{p_invite:invitation,p_accept:true})),workspace)
  assert.equal((await seatRequest(owner,{stage:'confirm',quantity:1,intent:'manual',amount:350,currency:'USD',cadence:'monthly'})).status,409)
  sql(`delete from public.st_v2_members where (workspace_id,user_id)=('${workspace}','${invitee.id}');`)
  const refreshed=page.waitForResponse(response=>response.url().endsWith('/api/billing/workspace')
    &&response.request().postDataJSON()?.stage==='status')
  await page.getByRole('button',{name:'Refresh seats'}).click()
  assert.equal((await refreshed).status(),200)
  await page.waitForFunction(()=>Array.from(document.querySelectorAll('button')).some(button=>button.textContent==='Refresh seats'&&!button.disabled))
  await page.getByText(/1 occupied .* 2 billed seats/).waitFor()
  const quantity=page.getByLabel('Total billed seats')
  await quantity.fill('1')
  await page.getByRole('button',{name:'Review quantity change'}).click()
  await page.getByRole('button',{name:'Approve seat charge'}).click()
  await page.getByText(/Stripe confirmed 1 workspace seats?\./).waitFor()
  assert.deepEqual(writes,[1,2,1])
  const current=()=>sql(`select extract(epoch from current_until)::bigint from sectalk_private.st_v8_workspace_seats where workspace='${workspace}';`)
  assert.equal(current(),String(period))
  period+=86400
  subscription.items.data[0].current_period_end=period
  const event={type:'invoice.payment_failed',created:time,livemode:false,data:{object:{id:invoice}}}
  assert.equal((await webhook({...event,id:'evt_seat_failed_'+suffix})).status,204)
  assert.notEqual(current(),String(period))
  paid=true
  assert.equal((await webhook({...event,id:'evt_seat_stale_'+suffix,type:'invoice.paid',data:{object:{id:oldInvoice}}})).status,204)
  assert.notEqual(current(),String(period))
  assert.equal((await webhook({...event,id:'evt_seat_paid_'+suffix,type:'invoice.paid'})).status,204)
  assert.equal(current(),String(period))
  assert.equal(sql(`select count(*) from sectalk_private.st_v8_workspace_seat_changes where workspace='${workspace}' and outcome='settled';`),'3')
  sql(`delete from public.st_v2_workspaces where id='${workspace}';`)
  const reconcile=()=>fetch(app+'/api/billing/reconcile',{method:'POST',headers:{Authorization:'Bearer '+workerSecret}})
  assert.equal((await reconcile()).status,200)
  assert.equal(subscription.status,'canceled')
  assert.equal(sql(`select (finished_at is not null)::text from sectalk_private.st_v8_workspace_seat_closures where subscription='${addon}';`),'true')
  assert.ifError(problem)
  console.log('Native seat billing, tenant and fresh assurance, paid invitation true-up, cap enforcement, proration, renewal and audit passed')
} finally {
  await browser?.close()
  child?.kill()
  provider.closeAllConnections()
  await new Promise(ok=>provider.close(ok))
  sql(`delete from sectalk_private.st_v7_stripe_receipts where id in ('evt_seat_failed_${suffix}','evt_seat_paid_${suffix}','evt_seat_stale_${suffix}');`)
  if(workspace)sql(`delete from public.st_v2_workspaces where id='${workspace}';`)
  sql(`delete from sectalk_private.st_v8_workspace_seat_closures where subscription='${addon}';`)
  for(const id of users)await admin.auth.admin.deleteUser(id)
}
