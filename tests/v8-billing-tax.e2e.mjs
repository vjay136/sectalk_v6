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
const suffix=randomUUID().slice(0,8),key='sk_test_tax_'+suffix,secret=randomUUID()
const version=60000000+parseInt(suffix.slice(0,6),16)
const now=Math.floor(Date.now()/1000),customer='cus_TaxQA'+suffix,subscription='sub_TaxQA'+suffix,invoice='in_TaxQA'+suffix
const price=(label)=>'price_Tax'+label+suffix
const rates={cgst:'txr_QACGST'+suffix,sgst:'txr_QASGST'+suffix,igst:'txr_QAIGST'+suffix}
const prices=new Map([[price('Local'),{currency:'inr',amount:10000,period:'month',behavior:'exclusive'}],
  [price('Annual'),{currency:'inr',amount:118000,period:'year',behavior:'inclusive'}],
  [price('Europe'),{currency:'eur',amount:10000,period:'month',behavior:'exclusive'}]])
const alphabet='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
const first14='29ABCDE1234F1Z'
const gstin=first14+alphabet[(36-[...first14].reduce((sum,char,i)=>{
  const value=alphabet.indexOf(char)*(i%2?2:1)
  return sum+Math.floor(value/36)+value%36
},0)%36)%36]
const users=[]
const euCustomer='cus_TaxEurope'+suffix
let browser,child,problem,checkouts=0,capturedCustomer
const sql=statement=>execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
  '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true}).trim()
function value(result){if(result.error)throw result.error;return result.data}
async function person(label){
  const handle='tax_'+label+'_'+suffix,email=handle+'@example.invalid',password=randomUUID()+'!4aS'
  const {user}=value(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  users.push(user.id)
  const client=createClient(db,publicKey,options)
  value(await client.auth.signInWithPassword({email,password}))
  value(await client.rpc('st_save_profile',{p_handle:handle,p_name:'Tax QA '+label}))
  const stale=value(await client.auth.getSession()).session
  await fixtureAuthenticator(client)
  return {id:user.id,client,stale,session:value(await client.auth.getSession()).session}
}
function priceObject(id){
  const entry=prices.get(id)
  if(!entry)return null
  return {id,currency:entry.currency,unit_amount:entry.amount,livemode:false,active:true,type:'recurring',
    billing_scheme:'per_unit',product:'prod_TaxQA',tax_behavior:entry.behavior,
    recurring:{interval:entry.period,interval_count:1,usage_type:'licensed'}}
}
let owner
const invoiceSnapshot=()=>({id:invoice,number:'TX'+suffix.toUpperCase()+'-0001',status:'paid',currency:'inr',livemode:false,customer,
  customer_name:'Frozen QA Company',customer_tax_ids:[{type:'in_gst',value:gstin}],
  parent:{subscription_details:{subscription}},status_transitions:{finalized_at:now,paid_at:now},
  subtotal:10000,subtotal_excluding_tax:10000,total:11800,total_excluding_tax:10000,amount_due:11800,amount_paid:11800,
  total_taxes:['cgst','sgst'].map(name=>({amount:900,taxable_amount:10000,tax_behavior:'exclusive',taxability_reason:'standard_rated',
    tax_rate_details:{tax_rate:rates[name]}}))})
const provider=createServer(async(req,res)=>{
  res.setHeader('Content-Type','application/json')
  try {
    assert.equal(req.headers.authorization,'Bearer '+key)
    const [,,resource,id]=new URL(req.url,'http://127.0.0.1').pathname.split('/')
    let result
    if(req.method==='GET'&&resource==='prices') result=priceObject(id)
    if(req.method==='GET'&&resource==='tax_rates'){
      const label=Object.keys(rates).find(name=>rates[name]===id)
      if(label) result={id,active:true,livemode:false,country:'IN',display_name:label.toUpperCase(),
        inclusive:label==='igst',percentage:label==='igst'?18:9}
    }
    if(req.method==='GET'&&resource==='subscriptions'&&id===subscription){
      result={id:subscription,customer,metadata:{sectalk_user:owner.id},livemode:false,status:'active',
        cancel_at_period_end:false,items:{data:[{price:priceObject(price('Local')),current_period_end:now+86400}]}}
    }
    if(req.method==='GET'&&resource==='invoices') result=id===invoice?invoiceSnapshot():{data:[invoiceSnapshot()],has_more:false}
    if(req.method==='POST'){
      let text=''
      for await(const chunk of req)text+=chunk
      const form=new URLSearchParams(text)
      if(resource==='tax'&&id==='calculations'){
        assert.equal(form.get('line_items[0][amount]'),'10000')
        assert.equal(form.get('line_items[0][product]'),'prod_TaxQA')
        assert.equal(form.get('customer_details[address][country]'),'FR')
        assert.equal(form.get('line_items[0][tax_behavior]'),'exclusive')
        result={currency:'eur',amount_total:12000,tax_amount_inclusive:0,tax_amount_exclusive:2000,
          tax_breakdown:[{amount:2000,taxability_reason:'standard_rated',tax_rate_details:{tax_type:'vat'}}]}
      }
      if(resource==='customers'){
        assert.match(req.headers['idempotency-key'],/^sectalk-tax-customer-/)
        if(form.get('address[country]')==='FR'){
          assert.equal(form.get('address[postal_code]'),'75001')
          assert.equal(form.get('tax_id_data[0][type]'),null)
          result={id:euCustomer}
        }else{
          assert.equal(form.get('address[country]'),'IN')
          assert.equal(form.get('address[state]'),'Karnataka')
          assert.equal(form.get('tax_id_data[0][type]'),'in_gst')
          assert.equal(form.get('tax_id_data[0][value]'),gstin)
          capturedCustomer=form.get('name')
          result={id:customer}
        }
      }
      if(resource==='checkout'&&id==='sessions'){
        checkouts++
        if(form.get('customer')===euCustomer){
          assert.equal(form.get('line_items[0][price]'),price('Europe'))
          assert.equal(form.get('automatic_tax[enabled]'),'true')
          assert.equal(form.get('tax_id_collection[enabled]'),'true')
          assert.equal(form.get('customer_update[address]'),'auto')
        }else{
          assert.equal(form.get('customer'),customer)
          assert.equal(form.get('line_items[0][price]'),price('Local'))
          assert.equal(form.get('line_items[0][tax_rates][0]'),rates.cgst)
          assert.equal(form.get('line_items[0][tax_rates][1]'),rates.sgst)
          assert.equal(form.get('customer_update[address]'),'never')
        }
        assert.match(form.get('subscription_data[metadata][sectalk_tax_quote]'),/^[0-9a-f-]{36}$/)
        result={id:'cs_test_TaxQA'+suffix,status:'open',url:'https://checkout.stripe.com/c/pay/TaxQA'+suffix}
      }
    }
    if(!result)return res.writeHead(404).end(JSON.stringify({error:{message:'Unimplemented provider fixture'}}))
    res.end(JSON.stringify(result))
  } catch(error) {
    problem??=error
    res.writeHead(400).end(JSON.stringify({error:{message:'Provider fixture assertion failed'}}))
  }
})
const call=(session,payload)=>fetch(app+'/api/billing/action',{method:'POST',
  headers:{Authorization:'Bearer '+session.access_token,'Content-Type':'application/json'},body:JSON.stringify(payload)})
const terms={plan:'professional',cadence:'monthly',currency:'INR',version}
const profile={company:'Frozen QA Company',country:'IN',region:'29',city:'Bengaluru',postal:'560001',address:'1 QA Street',taxId:gstin}
try {
  owner=await person('owner')
  const outsider=await person('outsider')
  sql(`insert into sectalk_private.st_v6_plan_versions(plan,version,title,description,visible,active_from)
    values('professional',${version},'Pro','Tax QA offer',true,now()-interval '1 minute');
    insert into sectalk_private.st_v6_plan_prices(plan,version,cadence,currency,amount,provider_price) values
    ('professional',${version},'monthly','INR',10000,'${price('Local')}'),
    ('professional',${version},'annual','INR',118000,'${price('Annual')}'),
    ('professional',${version},'monthly','EUR',10000,'${price('Europe')}');`)
  await new Promise((ok,bad)=>provider.once('error',bad).listen(0,'127.0.0.1',ok))
  child=spawn(process.execPath,[resolve('node_modules/next/dist/bin/next'),'start','--hostname','127.0.0.1','--port','3489'],{
    cwd:resolve('supabase/.temp/v4-auth-qa/device-commands-app'),stdio:'inherit',env:{...process.env,
      NEXT_PUBLIC_SUPABASE_URL:db,NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:publicKey,SECTALK_BILLING_SUPABASE_KEY:service,
      SECTALK_APP_URL:app,STRIPE_SECRET_KEY:key,STRIPE_WEBHOOK_SECRET:secret,SECTALK_STRIPE_DOCUMENT_SECRET:randomUUID(),
      SECTALK_STRIPE_TAX:'enabled',SECTALK_GST_SELLER_STATE:'29',SECTALK_GST_RATE_BPS:'1800',STRIPE_GST_CGST_EXCLUSIVE:rates.cgst,
      STRIPE_GST_SGST_EXCLUSIVE:rates.sgst,STRIPE_GST_IGST_INCLUSIVE:rates.igst,
      SECTALK_TEST_STRIPE_ORIGIN:'http://127.0.0.1:'+provider.address().port},
  })
  let ready=false
  for(let i=0;i<40&&child.exitCode===null;i++){
    ready=await fetch(app+'/api/health',{signal:AbortSignal.timeout(2000)}).then(r=>r.ok).catch(()=>false)
    if(ready)break
    await setTimeout(500)
  }
  assert(ready)
  assert.equal((await call(owner.stale,{action:'tax_preview',...terms,profile})).status,403)
  assert.equal((await call(owner.session,{action:'checkout',...terms})).status,409)
  assert.equal((await call(owner.session,{action:'tax_preview',...terms,profile:{...profile,region:'27'}})).status,400)
  const inclusive=await call(outsider.session,{action:'tax_preview',...terms,cadence:'annual',
    profile:{...profile,region:'27',taxId:'',city:'Mumbai',postal:'400001'}})
  assert.equal(inclusive.status,200,await inclusive.clone().text())
  const inclusiveQuote=await inclusive.json()
  assert.deepEqual(inclusiveQuote.estimate.lines,[{label:'IGST',amount:18000}])
  assert.equal(inclusiveQuote.estimate.total,118000)
  assert.equal(inclusiveQuote.estimate.net,100000)
  const vat=await call(outsider.session,{action:'tax_preview',...terms,currency:'EUR',
    profile:{...profile,country:'FR',region:'',taxId:'',city:'Paris',postal:'75001'}})
  assert.equal(vat.status,200,await vat.clone().text())
  const vatQuote=await vat.json()
  assert.deepEqual(vatQuote.estimate.lines,[{label:'VAT',amount:2000}])
  assert.equal((await call(owner.session,{action:'checkout',...terms,cadence:'annual',taxQuote:inclusiveQuote.id})).status,409)
  assert.equal(checkouts,0)
  const taxCheckout=await call(outsider.session,{action:'checkout',...terms,currency:'EUR',taxQuote:vatQuote.id})
  assert.ifError(problem)
  assert.equal(taxCheckout.status,200,await taxCheckout.clone().text())

  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const context=await browser.newContext()
  await context.route('https://checkout.stripe.com/**',route=>route.fulfill({contentType:'text/html',body:'<main>Hosted tax checkout</main>'}))
  const page=await context.newPage()
  await page.addInitScript(({name,value})=>localStorage.setItem(name,JSON.stringify(value)),
    {name:'sb-'+new URL(db).hostname.split('.')[0]+'-auth-token',value:owner.session})
  await page.goto(app+'/?billing=tax')
  await page.getByRole('button',{name:'Compare plans',exact:true}).click()
  await page.getByLabel('Currency').selectOption('INR')
  await page.getByRole('button',{name:'Review tax and checkout'}).click()
  await page.getByLabel('Company legal name (optional)').fill(profile.company)
  await page.getByLabel('Place of supply').selectOption(profile.region)
  await page.getByLabel('Street address').fill(profile.address)
  await page.getByLabel('City',{exact:true}).fill(profile.city)
  await page.getByLabel('Postal code').fill(profile.postal)
  await page.getByLabel('Company GSTIN (optional)').fill(profile.taxId)
  await page.getByRole('button',{name:'Save and estimate tax'}).click()
  await page.getByText('CGST',{exact:true}).waitFor()
  await page.getByText('SGST',{exact:true}).waitFor()
  await page.getByRole('button',{name:'Continue to Stripe checkout'}).click()
  await page.waitForURL(url=>url.origin==='https://checkout.stripe.com')
  await page.getByText('Hosted tax checkout').waitFor()
  assert.equal(checkouts,2)
  assert.equal(capturedCustomer,profile.company)
  const event={id:'evt_tax_'+suffix,type:'customer.subscription.created',created:now,livemode:false,data:{object:{id:subscription}}}
  const body=JSON.stringify(event),stamp=Math.floor(Date.now()/1000)
  const signature=createHmac('sha256',secret).update(stamp+'.'+body).digest('hex')
  const result=await fetch(app+'/api/billing/webhook',{method:'POST',headers:{'Stripe-Signature':`t=${stamp},v1=${signature}`},body})
  assert.equal(result.status,204)
  sql(`update sectalk_private.st_v8_tax_profiles set details=details||'{"company":"Changed Company"}' where account='${owner.id}';`)
  await page.goto(app+'/billing/documents')
  await page.getByText(profile.company,{exact:true}).waitFor()
  await page.getByText(gstin,{exact:true}).waitFor()
  await page.getByText('Tax breakdown',{exact:true}).click()
  await page.getByText(/CGST.*9.00/).waitFor()
  await page.getByText(/SGST.*9.00/).waitFor()
  assert.ifError(problem)
  console.log('Native tax cart, GST split and inclusive totals, provider VAT, quote scope, hosted tax fields and immutable invoice passed')
} finally {
  await browser?.close()
  child?.kill()
  provider.closeAllConnections()
  await new Promise(ok=>provider.close(ok))
  sql(`delete from sectalk_private.st_v7_stripe_receipts where id='evt_tax_${suffix}';
    delete from sectalk_private.st_v7_stripe_invoice_numbers where invoice='${invoice}';`)
  for(const id of users)await admin.auth.admin.deleteUser(id)
  sql(`delete from sectalk_private.st_v6_plan_prices where (plan,version)=('professional',${version});
    delete from sectalk_private.st_v7_plan_entitlements where (plan,version)=('professional',${version});
    delete from sectalk_private.st_v6_plan_versions where (plan,version)=('professional',${version});`)
}
