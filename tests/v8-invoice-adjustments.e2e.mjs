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
const suffix=randomUUID().slice(0,8),key='sk_test_adjustments_'+suffix,secret=randomUUID()
const customer='cus_AdjustQA'+suffix,base='sub_BaseQA'+suffix,seat='sub_SeatQA'+suffix,refund='re_RefundQA'+suffix
const time=Math.floor(Date.now()/1000)
const id=(kind)=>'in_'+kind+suffix
const invoices=new Map(),notes=new Map(),mutations=new Map(),users=[]
let workspace,browser,child,problem
let refundState='pending'
const sql=statement=>execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
  '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true}).trim()
function value(result){if(result.error)throw result.error;return result.data}
async function person(label){
  const handle='adjust_'+label+'_'+suffix,email=handle+'@example.invalid',password=randomUUID()+'!4aS'
  const {user}=value(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  users.push(user.id)
  const client=createClient(db,publicKey,options)
  value(await client.auth.signInWithPassword({email,password}))
  value(await client.rpc('st_save_profile',{p_handle:handle,p_name:'Adjustment '+label}))
  const stale=value(await client.auth.getSession()).session
  await fixtureAuthenticator(client)
  return {id:user.id,client,stale,session:value(await client.auth.getSession()).session}
}
function invoice(kind,number,status,subscription=seat){
  const row={id:id(kind),number,status,currency:'usd',livemode:false,customer,
    parent:{subscription_details:{subscription}},status_transitions:{finalized_at:time,paid_at:status==='paid'?time:null},
    subtotal:1000,subtotal_excluding_tax:1000,total:1000,total_excluding_tax:1000,
    amount_due:1000,amount_paid:status==='paid'?1000:0,amount_remaining:status==='paid'?0:1000,
    pre_payment_credit_notes_amount:0,post_payment_credit_notes_amount:0,total_taxes:[]}
  invoices.set(row.id,row)
  return row
}
const paidInvoice=invoice('Paid','QA-0001','paid')
const openInvoice=invoice('Open','QA-0002','open')
invoice('Base','QA-0003','paid',base)
const provider=createServer(async(req,res)=>{
  res.setHeader('Content-Type','application/json')
  try {
    assert.equal(req.headers.authorization,'Bearer '+key)
    const url=new URL(req.url,'http://127.0.0.1')
    const [,,resource,reference]=url.pathname.split('/')
    let result
    if(req.method==='GET'&&resource==='invoices'){
      if (reference) result=invoices.get(reference)
      else result={data:[...invoices.values()],has_more:false}
    }else if(req.method==='GET'&&resource==='subscriptions'&&reference===base){
      result={id:base,customer,status:'active',collection_method:'charge_automatically',livemode:false}
    }else if(req.method==='GET'&&resource==='invoice_payments'){
      assert.equal(url.searchParams.get('invoice'),paidInvoice.id)
      result={data:[{status:'paid',payment:{type:'payment_intent',payment_intent:'pi_QA'}}],has_more:false}
    }else if(req.method==='GET'&&resource==='refunds'&&reference===refund){
      result={id:refund,status:refundState,amount:200,currency:'usd'}
    }else if(req.method==='GET'&&resource==='credit_notes'&&reference!=='preview'){
      result=notes.get(reference)
    }else if(resource==='credit_notes'){
      let body=''
      for await(const chunk of req)body+=chunk
      const params=req.method==='GET'?url.searchParams:new URLSearchParams(body)
      const target=invoices.get(params.get('invoice'))
      assert.equal(target.parent.subscription_details.subscription,seat)
      const amount=Number(params.get('amount'))
      assert.equal(params.get('reason'),'order_change')
      const requestedRefund=Number(params.get('refund_amount')),requestedCredit=Number(params.get('credit_amount'))
      assert.ok(!(requestedRefund&&requestedCredit))
      const post=target.status==='paid'?amount:0
      assert.equal(requestedRefund+requestedCredit,post)
      const note={amount,currency:'usd',customer,invoice:target.id,livemode:false,pre_payment_amount:amount-post,
        post_payment_amount:post,status:'issued',reason:'order_change',
        refunds:requestedRefund?[{refund,amount_refunded:amount}]:[],customer_balance_transaction:requestedCredit?'cbtxn_QA':null}
      if (reference==='preview') result=note
      else {
        assert.equal(params.get('email_type'),'none')
        const adjustment=params.get('metadata[sectalk_invoice_adjustment]')
        assert.equal(req.headers['idempotency-key'],'sectalk-adjustment-'+adjustment)
        assert.match(adjustment,/^[0-9a-f-]{36}$/)
        if (mutations.has(adjustment)) result=mutations.get(adjustment)
        else {
          result={...note,id:'cn_QA'+suffix+(notes.size+1),metadata:{sectalk_invoice_adjustment:adjustment}}
          const remaining=target.status==='paid'?target.amount_paid-target.post_payment_credit_notes_amount:target.amount_remaining
          assert.ok(amount<=remaining)
          target.post_payment_credit_notes_amount+=post
          target.pre_payment_credit_notes_amount+=amount-post
          target.amount_remaining-=amount-post
          mutations.set(adjustment,result)
          notes.set(result.id,result)
        }
      }
    }
    if(!result)return res.writeHead(404).end(JSON.stringify({error:{message:'Unimplemented provider fixture'}}))
    res.end(JSON.stringify(result))
  } catch(error) {
    problem??=error
    res.writeHead(400).end(JSON.stringify({error:{message:'Provider assertion failed'}}))
  }
})

const call=(session,payload)=>fetch(app+'/api/billing/workspace?section=adjustments',{method:'POST',
  headers:{Authorization:'Bearer '+session.access_token,'Content-Type':'application/json'},body:JSON.stringify({workspace,...payload})})
const terms=(invoice,kind,amount)=>({stage:'preview',invoice,kind,amount,currency:'USD',reason:'order_change'})
async function webhook(type,resource,signed=true){
  const body=JSON.stringify({id:'evt_adjust_'+randomUUID().replaceAll('-',''),type,created:time,livemode:false,data:{object:{id:resource}}})
  const stamp=Math.floor(Date.now()/1000)
  const signature=createHmac('sha256',signed?secret:'wrong').update(stamp+'.'+body).digest('hex')
  return fetch(app+'/api/billing/webhook',{method:'POST',headers:{'Stripe-Signature':`t=${stamp},v1=${signature}`},body})
}
try {
  const [owner,operator,ordinary,outsider]=await Promise.all(['owner','operator','ordinary','outsider'].map(person))
  workspace=value(await owner.client.rpc('st_v2_create_workspace',{p_name:'Adjust QA '+suffix}))
  sql(`insert into public.st_v2_members(workspace_id,user_id,role) values
    ('${workspace}','${operator.id}','member'),('${workspace}','${ordinary.id}','admin');
    insert into public.st_v2_subscriptions(user_id,customer_id,subscription_id,plan,status,period_end)
    values('${owner.id}','${customer}','${base}','business','active',now()+interval '1 month');
    insert into sectalk_private.st_v8_workspace_seats(workspace,customer,subscription,quantity,current_until)
    values('${workspace}','${customer}','${seat}',8,now()+interval '1 month');`)
  value(await owner.client.rpc('st_v7_billing_admin_manage',{p_workspace:workspace,p_account:operator.id,p_enabled:true}))
  await new Promise((ok,bad)=>provider.once('error',bad).listen(0,'127.0.0.1',ok))
  child=spawn(process.execPath,[resolve('node_modules/next/dist/bin/next'),'start','--hostname','127.0.0.1','--port','3489'],{
    cwd:resolve('supabase/.temp/v4-auth-qa/device-commands-app'),stdio:'inherit',env:{...process.env,
      NEXT_PUBLIC_SUPABASE_URL:db,NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:publicKey,SECTALK_BILLING_SUPABASE_KEY:service,
      SECTALK_APP_URL:app,STRIPE_SECRET_KEY:key,STRIPE_WEBHOOK_SECRET:secret,
      SECTALK_TEST_STRIPE_ORIGIN:'http://127.0.0.1:'+provider.address().port},
  })
  let ready=false
  for(let i=0;i<40&&child.exitCode===null;i++){
    ready=await fetch(app+'/api/health',{signal:AbortSignal.timeout(2000)}).then(r=>r.ok).catch(()=>false)
    if(ready)break
    await setTimeout(500)
  }
  assert(ready)
  for(const denied of [owner.session,ordinary.session,outsider.session,operator.stale])
    assert.equal((await call(denied,{stage:'status'})).status,403)
  assert.equal((await call(operator.session,terms(id('Base'),'refund',100))).status,409)
  assert.equal((await call(operator.session,terms(paidInvoice.id,'refund',1001))).status,409)
  assert.equal(mutations.size,0)

  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const page=await browser.newPage()
  await page.addInitScript(({name,value})=>localStorage.setItem(name,JSON.stringify(value)),
    {name:'sb-'+new URL(db).hostname.split('.')[0]+'-auth-token',value:operator.session})
  await page.goto(app+'/billing/workspaces')
  await page.getByLabel('Workspace',{exact:true}).selectOption(workspace)
  await page.getByRole('button',{name:'Review invoice adjustments'}).click()
  const selection=page.getByLabel('Workspace seat invoice')
  await selection.selectOption(paidInvoice.id)
  await page.getByLabel('Amount in USD').fill('2.00')
  const reviewResponse=page.waitForResponse(response=>response.url().includes('section=adjustments')
    &&response.request().postDataJSON()?.stage==='preview')
  await page.getByRole('button',{name:'Preview invoice change'}).click()
  const reviewed=await reviewResponse
  assert.ifError(problem)
  assert.equal(reviewed.status(),200,await reviewed.text())
  await page.locator('[aria-label="Review invoice adjustment"]').getByText(/Refund to original payment.*Invoice QA-0001/).waitFor()
  assert.equal(mutations.size,0)
  const pending=page.waitForRequest(req=>req.url().includes('section=adjustments')&&req.postDataJSON()?.stage==='confirm')
  await page.getByRole('button',{name:'Confirm invoice change'}).click()
  const adjustmentId=(await pending).postDataJSON().id
  await page.getByRole('list',{name:'Invoice change history'}).getByText(/Refund pending/).waitFor()
  assert.equal(mutations.size,1)
  const replay=await call(operator.session,{stage:'confirm',id:adjustmentId})
  assert.equal(replay.status,200)
  assert.equal((await replay.json()).state,'refund_pending')
  assert.equal(mutations.size,1)
  refundState='succeeded'
  assert.equal((await webhook('refund.updated',refund,false)).status,400)
  assert.equal((await webhook('refund.updated',refund)).status,204)
  const status=await call(operator.session,{stage:'status'})
  assert.equal(status.status,200)
  assert.equal((await status.json()).history[0].state,'refunded')
  assert.equal((await call(operator.session,terms(paidInvoice.id,'credit',801))).status,409)

  const credit=await call(operator.session,terms(paidInvoice.id,'credit',300))
  assert.equal(credit.status,200)
  assert.equal((await call(operator.session,{stage:'confirm',id:(await credit.json()).id})).status,200)
  const adjustment=await call(operator.session,terms(openInvoice.id,'adjustment',400))
  assert.equal(adjustment.status,200)
  assert.equal((await call(operator.session,{stage:'confirm',id:(await adjustment.json()).id})).status,200)
  assert.equal(paidInvoice.post_payment_credit_notes_amount,500)
  assert.equal(openInvoice.amount_remaining,600)
  assert.equal(mutations.size,3)
  assert.equal(sql(`select count(*) from sectalk_private.st_v8_invoice_adjustments where workspace='${workspace}' and actor='${operator.id}';`),'3')
  assert.ifError(problem)
  console.log('Delegated billing refunds, customer credit, open invoice adjustment, signed completion, bounds, and audit passed')
} finally {
  await browser?.close()
  child?.kill()
  provider.closeAllConnections()
  await new Promise(ok=>provider.close(ok))
  if(workspace){
    sql(`delete from sectalk_private.st_v8_invoice_adjustments where workspace='${workspace}';
      delete from public.st_v2_workspaces where id='${workspace}';
      delete from sectalk_private.st_v8_workspace_seat_closures where subscription='${seat}';`)
  }
  for(const id of users)await admin.auth.admin.deleteUser(id)
}
