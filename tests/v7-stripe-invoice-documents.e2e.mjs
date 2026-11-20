import assert from 'node:assert/strict'
import {spawn,execFileSync} from 'node:child_process'
import {createHmac,randomUUID} from 'node:crypto'
import {createServer} from 'node:http'
import {readFile,writeFile} from 'node:fs/promises'
import {resolve} from 'node:path'
import {setTimeout} from 'node:timers/promises'
import {PDFDocument,PDFRawStream,decodePDFRawStream} from 'pdf-lib'
import {createClient} from '@supabase/supabase-js'
import {fixtureAuthenticator} from './workspace-admin-fixture.mjs'

const db = new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
assert.equal(db,'http://127.0.0.1:55321')
const app = 'http://127.0.0.1:3489'
const service=process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
const publicKey=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const options={auth:{persistSession:false,autoRefreshToken:false}}
const admin=createClient(db,service,options)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const suffix=randomUUID().slice(0,8)
const signingSecret=randomUUID()
const providerKey='sk_test_invoices' + suffix
const invoiceId='in_' + suffix
const customer='cus_' + suffix
const subscription='sub_' + suffix
const number='QA'+suffix.toUpperCase()+'-0001'
const now=Math.floor(Date.now()/1000)
const users=[]
let child,browser,tenant,providerReads=0,drift=false
function data(result) {if(result.error) throw result.error;return result.data}
function sql(statement) {
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true}).trim()
}
async function person(role) {
  const handle='bill06_'+role+'_'+suffix
  const email=handle+'@example.invalid'
  const password=randomUUID()+'!oA9'
  const {user}=data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  users.push(user.id)
  const client=createClient(db,publicKey,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:'Invoice '+role}))
  return {id:user.id,client}
}
const invoice={id:invoiceId,number,object:'invoice',status:'paid',livemode:false,customer,currency:'usd',
  parent:{type:'subscription_details',subscription_details:{subscription}},status_transitions:{finalized_at:now-3600,paid_at:now-1800},
  subtotal:1801,subtotal_excluding_tax:1801,total_excluding_tax:1801,total:2004,amount_paid:2004,amount_due:0,
  total_taxes:[
    {amount:126,taxable_amount:1801,tax_behavior:'exclusive',taxability_reason:'standard_rated'},
    {amount:77,taxable_amount:1801,tax_behavior:'exclusive',taxability_reason:'portion_reduced_rated'},
  ],customer_email:'blacklisted-private@example.invalid',invoice_pdf:'https://pay.stripe.com/contains-private-url'}
const provider=createServer((request,response)=>{
  const path=new URL(request.url,'http://127.0.0.1')
  response.setHeader('Content-Type','application/json')
  providerReads++
  if(request.method==='GET'&&request.headers.authorization==='Bearer '+providerKey) {
    if(path.pathname==='/v1/invoices'&&path.searchParams.get('customer')===customer
      &&path.searchParams.get('subscription')===subscription) {
      const draft={...invoice,id:'in_draft'+suffix,number:'DRAFT-0002',status:'draft'}
      const foreign={...invoice,id:'in_foreign'+suffix,number:'FOREIGN-0001',customer:'cus_Foreign'}
      return response.end(JSON.stringify({object:'list',data:[invoice,draft,foreign],has_more:false}))
    }
    if(path.pathname==='/v1/invoices/'+invoiceId) return response.end(JSON.stringify(drift
      ? {...invoice,number:'CHANGED-0001'} : invoice))
  }
  response.writeHead(404).end(JSON.stringify({error:{message:'Unbound fixture resource'}}))
})
async function pdfText(bytes,title) {
  const document=await PDFDocument.load(bytes)
  assert.equal(document.getTitle(),title)
  assert.equal(document.getPageCount(),1)
  const page=document.getPage(0)
  const contents=page.node.Contents()
  const operations=contents.asArray().map(ref=>document.context.lookup(ref,PDFRawStream))
    .map(stream=>Buffer.from(decodePDFRawStream(stream).decode()).toString('ascii')).join(' ')
  return [...operations.matchAll(/<([0-9a-f]+)> Tj/gi)].map(match=>Buffer.from(match[1],'hex').toString('latin1')).join('\n')
}
try {
  const owner=await person('owner')
  const member=await person('member')
  const foreign=await person('foreign')
  tenant=data(await owner.client.rpc('st_v2_create_workspace',{p_name:'Invoice workspace '+suffix}))
  sql("insert into public.st_v2_members(workspace_id,user_id,role) values ('"+tenant+"','"+member.id+"','member');"+
    "select public.st_v2_sync_billing('evt_bill06_"+suffix+"','"+owner.id+"','"+customer+"','"+subscription+
    "','business','active',now()+interval '1 day',false,now());")
  await fixtureAuthenticator(owner.client)
  data(await owner.client.rpc('st_v7_billing_admin_manage',{p_workspace:tenant,p_account:member.id,p_enabled:true}))
  await new Promise((resolve,reject)=>provider.once('error',reject).listen(0,'127.0.0.1',resolve))
  child=spawn(process.execPath,[resolve('node_modules/next/dist/bin/next'),'start','--hostname','127.0.0.1','--port','3489'],{
    cwd:resolve('supabase/.temp/v4-auth-qa/device-commands-app'),stdio:'inherit',env:{...process.env,
      NEXT_PUBLIC_SUPABASE_URL:db,NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:publicKey,SECTALK_BILLING_SUPABASE_KEY:service,
      SECTALK_APP_URL:app,STRIPE_SECRET_KEY:providerKey,STRIPE_WEBHOOK_SECRET:'fixture_invoice_signing',
      SECTALK_STRIPE_DOCUMENT_SECRET:signingSecret,SECTALK_TEST_STRIPE_ORIGIN:'http://127.0.0.1:'+provider.address().port},
  })
  let ready=false
  for(let i=0;i<40&&child.exitCode===null;i++) {
    ready=await fetch(app+'/api/health',{signal:AbortSignal.timeout(2000)}).then(r=>r.ok).catch(()=>false)
    if(ready) break
    await setTimeout(500)
  }
  assert(ready)
  const session=async person=>data(await person.client.auth.getSession()).session
  const send=async (person,query={})=>fetch(app+'/api/billing/invoices?'+new URLSearchParams(query),{
    headers:{Authorization:'Bearer '+(await session(person)).access_token}})
  const own=await send(owner)
  assert.equal(own.status,200,await own.clone().text())
  const ownInvoice=(await own.json()).invoices[0]
  assert.equal(ownInvoice.number,number)
  assert.equal(ownInvoice.total,2004)
  assert.deepEqual(ownInvoice.taxes.map(tax=>tax.amount),[126,77])
  assert.doesNotMatch(JSON.stringify(ownInvoice),/blacklisted-private|contains-private-url/)
  const delegated=await send(member,{workspace:tenant})
  assert.equal(delegated.status,200)
  const entries=(await delegated.json()).invoices
  assert.deepEqual(entries.map(invoice=>invoice.number),[number])
  const receipt=entries[0].receipt_ticket
  assert(receipt)
  const initialReads=providerReads
  assert.equal((await send(foreign,{workspace:tenant,ticket:receipt})).status,403)
  assert.equal((await send(member,{workspace:tenant,ticket:receipt.slice(1)})).status,404)
  assert.equal((await send(member,{workspace:tenant,ticket:ownInvoice.invoice_ticket})).status,404)
  const payload=Buffer.from(JSON.stringify({id:invoiceId,kind:'invoice',expires:Date.now()-1000})).toString('base64url')
  const signature=createHmac('sha256',signingSecret).update(JSON.stringify(['sectalk-stripe-invoice-v1',
    member.id,tenant,customer,subscription,payload])).digest('base64url')
  assert.equal((await send(member,{workspace:tenant,ticket:payload+'.'+signature})).status,404)
  assert.equal(providerReads,initialReads)
  drift=true
  assert.equal((await send(member,{workspace:tenant,ticket:receipt})).status,404)
  drift=false
  const ownPdf=await send(owner,{ticket:ownInvoice.invoice_ticket})
  assert.equal(ownPdf.status,200)
  assert.equal(ownPdf.headers.get('content-type'),'application/pdf')
  const original=Buffer.from(await ownPdf.arrayBuffer())
  assert.equal(original.subarray(0,5).toString(),'%PDF-', 'Owner PDF bytes '+original.length)
  assert.match(await pdfText(original,'Invoice '+number),/USD 20\.04/)

  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const page=await browser.newPage({acceptDownloads:true})
  await page.addInitScript(({name,value})=>localStorage.setItem(name,JSON.stringify(value)),
    {name:'sb-'+new URL(db).hostname.split('.')[0]+'-auth-token',value:await session(member)})
  await page.goto(app+'/billing/workspaces')
  await page.getByLabel('Workspace',{exact:true}).selectOption(tenant)
  await page.getByRole('link',{name:'Invoices and receipts',exact:true}).click()
  await page.getByRole('heading',{name:'Invoice '+number,exact:true}).waitFor()
  await page.getByText('Tax breakdown',{exact:true}).click()
  await page.getByText(/1\.26.*standard rated/).waitFor()
  async function download(type) {
    const pending=page.waitForEvent('download')
    const wire=page.waitForResponse(response=>response.url().includes('/api/billing/invoices?')&&response.url().includes('ticket='))
    await page.getByRole('button',{name:'Download '+type+' PDF',exact:true}).click()
    const received=await pending
    const transport=await wire
    assert.equal(transport.headers()['content-type'],'application/octet-stream',JSON.stringify({status:transport.status(),headers:Object.keys(transport.headers()),method:transport.request().method(),serviceWorker:transport.fromServiceWorker()}))
    const delivered=await transport.body()
    assert.equal(delivered.subarray(0,5).toString(),'%PDF-', 'Browser response bytes '+delivered.length)
    assert.equal(received.suggestedFilename(),'sectalk-'+type+'-'+number+'.pdf')
    const contents=await readFile(await received.path())
    assert.deepEqual(contents,delivered)
    const body=await pdfText(contents,(type==='receipt'?'Payment receipt':'Invoice')+' '+number)
    assert.match(body,/USD 20\.04/)
    assert.match(body,/USD 1\.26 \(exclusive\)/)
    assert.match(body,/USD 0\.77 \(exclusive\)/)
    assert.doesNotMatch(body,/blacklisted-private|contains-private-url/)
    if(type==='receipt') {
      assert.match(body,/Payment recorded/)
      if(process.env.SECTALK_INVOICE_SAMPLE_PATH) await writeFile(process.env.SECTALK_INVOICE_SAMPLE_PATH,contents)
    }
  }
  await download('invoice')
  await download('receipt')
  data(await owner.client.rpc('st_v7_billing_admin_manage',{p_workspace:tenant,p_account:member.id,p_enabled:false}))
  assert.equal((await send(member,{workspace:tenant,ticket:receipt})).status,403)
  assert.equal(sql("select count(*) from sectalk_private.st_v7_stripe_invoice_numbers where invoice='"+invoiceId+"';"),'1')
  console.log('Finalized Stripe sequence, exact taxes, scoped browser PDFs, signed ticket expiry, and live revocation passed')
} finally {
  await browser?.close()
  child?.kill()
  provider.closeAllConnections()
  await new Promise(resolve=>provider.close(resolve))
  if(tenant) sql("delete from public.st_v2_workspaces where id='"+tenant+"';")
  for(const id of users) await admin.auth.admin.deleteUser(id)
  sql("delete from sectalk_private.st_v7_stripe_invoice_numbers where invoice='"+invoiceId+"';"+
    "delete from sectalk_private.st_v2_billing_events where event_id='evt_bill06_"+suffix+"';")
}
