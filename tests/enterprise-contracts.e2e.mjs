import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import {execFileSync} from 'node:child_process'
import {randomUUID} from 'node:crypto'
import {createClient} from '@supabase/supabase-js'

const app=new URL(process.env.SECTALK_STORAGE_TEST_APP)
const backend=new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname,'127.0.0.1')
assert.equal(backend.origin,'http://127.0.0.1:55321')
const options={auth:{persistSession:false,autoRefreshToken:false}}
const publicKey=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const service=createClient(backend.href,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
const suffix=randomUUID().slice(0,8)
const password=randomUUID()+'!5a'
const actors=[],workspaces=[]
const sql=statement=>execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-q','-v','ON_ERROR_STOP=1',
  '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true})
const date=days=>new Date(Date.now()+days*86400000).toISOString().slice(0,10)
function data(result) {if(result.error)throw result.error;return result.data}
async function account(label) {
  const handle='ec_'+label+'_'+suffix, email=handle+'@example.invalid'
  const {user}=data(await service.auth.admin.createUser({email,password,email_confirm:true}))
  actors.push(user.id)
  const client=createClient(backend.href,publicKey,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:label+' enterprise QA'}))
  return {id:user.id,email,client}
}
async function billing(actor,workspace) {
  const page=await browser.newPage()
  page.setDefaultTimeout(25000)
  await page.goto(app.href)
  await page.getByLabel('Email address',{exact:true}).fill(actor.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation',{name:'SecTalk features'}).waitFor()
  await page.goto(new URL('/billing/workspaces',app).href)
  await page.getByLabel('Workspace',{exact:true}).selectOption(workspace)
  const panel=page.getByRole('region',{name:'Enterprise contracts',exact:true})
  await panel.getByRole('button',{name:'Open enterprise orders',exact:true}).click()
  const ready=panel.getByRole('button',{name:'Refresh enterprise orders',exact:true})
  const verify=panel.getByRole('form',{name:'Verify your current sign-in',exact:true})
  await ready.or(verify).first().waitFor()
  if(await verify.isVisible()) {
    await verify.getByLabel('Current password',{exact:true}).fill(password)
    await verify.getByRole('button',{name:'Verify and continue',exact:true}).click()
  }
  await ready.waitFor()
  return {page,panel,refresh:()=>ready.click()}
}
async function browserClient(page) {
  const token=await page.evaluate(()=>{
    const key=Object.keys(localStorage).find(key=>/^sb-.+-auth-token$/.test(key))
    return JSON.parse(localStorage.getItem(key)).access_token
  })
  return createClient(backend.href,publicKey,{...options,global:{headers:{Authorization:'Bearer '+token}}})
}
async function document(page,button) {
  const [saved]=await Promise.all([page.waitForEvent('download'),button.click()])
  return readFile(await saved.path(),'utf8')
}

try {
  const [owner,commercial,delegate,outsider]=await Promise.all(['owner','commercial','delegate','outside'].map(account))
  const scope=data(await owner.client.rpc('st_v2_create_workspace',{p_name:'Enterprise paperwork '+suffix}))
  const foreign=data(await outsider.client.rpc('st_v2_create_workspace',{p_name:'Unrelated paperwork '+suffix}))
  workspaces.push(scope,foreign)
  sql(`insert into public.st_v2_subscriptions(user_id,plan,catalog_version,status,period_end)
      values('${owner.id}','enterprise',1,'active',now()+interval '90 days');
    insert into sectalk_private.st_v8_enterprise_billing_operators values('${scope}','${commercial.id}');
    insert into public.st_v2_members(workspace_id,user_id,role) values('${scope}','${delegate.id}','member');
    insert into sectalk_private.st_v7_billing_admins(workspace,account,assigned_by)
      values('${scope}','${delegate.id}','${owner.id}');`)
  const view={p_workspace:scope}
  assert.equal((await outsider.client.rpc('st_v8_enterprise_billing_view',view)).error?.code,'42501')
  assert.equal((await commercial.client.rpc('st_v8_enterprise_billing_view',{p_workspace:foreign})).error?.code,'42501')
  const [seller,buyer]=await Promise.all([billing(commercial,scope),billing(owner,scope)])
  await seller.panel.getByText('Prepare annual order form',{exact:true}).click()
  const reference='Annual enterprise '+suffix, terms='Synthetic local annual agreement with custom negotiated pricing.'
  await seller.panel.getByLabel('Order reference',{exact:true}).fill(reference)
  await seller.panel.getByLabel('Annual total',{exact:true}).fill('12345.67')
  await seller.panel.getByLabel('Committed seats',{exact:true}).fill('37')
  await seller.panel.getByLabel('Commitment start date',{exact:true}).fill(date(10))
  await seller.panel.getByLabel('Quote expiry date',{exact:true}).fill(date(5))
  await seller.panel.getByLabel('Order terms',{exact:true}).fill(terms)
  await seller.panel.getByRole('button',{name:'Save annual quote',exact:true}).click()
  const [sellerClient,buyerClient]=await Promise.all([browserClient(seller.page),browserClient(buyer.page)])
  const sellerCard=seller.panel.getByRole('article',{name:reference,exact:true})
  await sellerCard.getByText(/Awaiting acceptance/).waitFor()
  const [quoted]=data(await sellerClient.rpc('st_v8_enterprise_billing_view',view)).orders
  assert.equal(quoted.annual_total,1234567)
  assert.equal(quoted.committed_seats,37)
  const action={p_workspace:scope,p_order:quoted.id}
  assert.equal((await sellerClient.rpc('st_v8_enterprise_billing_command',{...action,p_action:'accept',p_data:{po:'SELF-123'}})).error?.code,'42501')
  assert.equal((await delegate.client.rpc('st_v8_enterprise_billing_command',{...action,p_action:'accept',p_data:{po:'DELEGATE-123'}})).error?.code,'42501')
  await buyer.refresh()
  const buyerCard=buyer.panel.getByRole('article',{name:reference,exact:true})
  const form=await document(buyer.page,buyerCard.getByRole('button',{name:'Download order form'}))
  for(const expected of [reference,terms,'37','12,345.67',date(10)])assert.ok(form.includes(expected),expected)
  await buyerCard.getByLabel('Purchase order reference',{exact:true}).fill('QA-PO-'+suffix)
  await buyerCard.getByRole('button',{name:'Accept annual order',exact:true}).click()
  await buyerCard.getByText('Purchase order QA-PO-'+suffix,{exact:true}).waitFor()
  assert.equal((await buyerClient.rpc('st_v8_enterprise_billing_command',{...action,p_action:'invoice',p_data:{due:date(30)}})).error?.code,'42501')
  await seller.refresh()
  await sellerCard.getByLabel('Invoice due date',{exact:true}).fill(date(30))
  await sellerCard.getByRole('button',{name:'Issue manual invoice',exact:true}).click()
  await sellerCard.getByText(/Invoice issued/).waitFor()
  await buyer.refresh()
  const invoice=await document(buyer.page,buyerCard.getByRole('button',{name:'Download manual invoice'}))
  for(const expected of ['Manual invoice ENT-',reference,'QA-PO-'+suffix,date(30),'12,345.67'])assert.ok(invoice.includes(expected),expected)
  await sellerCard.getByLabel('Payment reconciliation reference',{exact:true}).fill('OFFLINE-QA-'+suffix)
  await sellerCard.getByRole('button',{name:'Record full offline payment',exact:true}).click()
  await sellerCard.getByText(/^Paid ·/).waitFor()
  data(await sellerClient.rpc('st_v8_enterprise_billing_command',{...action,p_action:'paid',p_data:{payment:'OFFLINE-QA-'+suffix}}))
  const state=sql(`copy(select string_agg(action,',' order by id) from sectalk_private.st_v8_enterprise_order_events
    where order_id='${quoted.id}') to stdout;`).trim()
  assert.equal(state,'quote,accept,invoice,paid')
  sql(`delete from sectalk_private.st_v8_enterprise_billing_operators where workspace='${scope}' and actor='${commercial.id}';`)
  assert.equal((await sellerClient.rpc('st_v8_enterprise_billing_view',view)).error?.code,'42501')
  console.log('Passed scoped quote, annual pricing, independent PO acceptance, downloads, manual invoice, offline reconciliation, immutable event count and revocation.')
} finally {
  await browser.close()
  for(const workspace of workspaces)sql(`begin; set local session_replication_role=replica;
    delete from sectalk_private.st_v8_enterprise_order_events where workspace='${workspace}'; set local session_replication_role=origin;
    delete from sectalk_private.st_v8_enterprise_orders where workspace='${workspace}';
    delete from public.st_v2_workspaces where id='${workspace}'; commit;`)
  for(const actor of actors)sql(`delete from auth.users where id='${actor}';`)
}
