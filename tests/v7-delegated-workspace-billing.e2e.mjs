import assert from 'node:assert/strict'
import {spawn, execFileSync} from 'node:child_process'
import {randomUUID} from 'node:crypto'
import {createServer} from 'node:http'
import {resolve} from 'node:path'
import {setTimeout} from 'node:timers/promises'
import {createClient} from '@supabase/supabase-js'
import {fixtureAuthenticator} from './workspace-admin-fixture.mjs'

const db = new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
assert.equal(db, 'http://127.0.0.1:55321')
const app = 'http://127.0.0.1:3489'
const service = process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const options = {auth:{persistSession:false,autoRefreshToken:false}}
const admin = createClient(db,service,options)
const {chromium} = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const suffix = randomUUID().slice(0,8)
const providerKey = 'sk_test_workspaceBilling' + suffix
const customer = 'cus_Adm12' + suffix
const subscription = 'sub_Adm12' + suffix
const users = []
const spaces = []
let child, browser, providerReads = 0

function data(result) {
  if (result.error) throw result.error
  return result.data
}
function sql(statement) {
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true}).trim()
}
async function person(role) {
  const handle = 'adm12_' + role + '_' + suffix
  const email = handle + '@example.invalid'
  const password = randomUUID()+'!oA9'
  const {user} = data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  users.push(user.id)
  const client = createClient(db,publicKey,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:'Billing ' + role}))
  return {id:user.id,handle,client}
}
async function workspace(person, label) {
  const id = data(await person.client.rpc('st_v2_create_workspace',{p_name:label + ' ' + suffix}))
  spaces.push(id)
  return id
}
const invoice = (number, owner = customer, sub = subscription) => ({number,status:'open',currency:'usd',
  total:1800,amount_due:1800,created:Math.floor(Date.now()/1000),customer:owner,
  customer_email:'never-return@example.invalid',hosted_invoice_url:'https://invoice.stripe.com/internal-fixture',
  parent:{type:'subscription_details',subscription_details:{subscription:sub}}})
const stripeFixture = createServer((request,response) => {
  response.setHeader('Content-Type','application/json')
  const url = new URL(request.url,'http://127.0.0.1')
  const fail = () => response.writeHead(409).end(JSON.stringify({error:{message:'Unexpected Stripe request'}}))
  if (request.method !== 'GET' || request.headers.authorization !== 'Bearer ' + providerKey) return fail()
  providerReads++
  if (url.pathname === '/v1/invoices' && url.searchParams.get('customer') === customer
    && url.searchParams.get('subscription') === subscription && url.searchParams.get('limit') === '20') {
    return response.end(JSON.stringify({object:'list',data:[invoice('BILLING-FIXTURE'),
      invoice('FOREIGN-CUSTOMER','cus_Foreign'),invoice('FOREIGN-SUBSCRIPTION',customer,'sub_Foreign')],has_more:false}))
  }
  if (url.pathname === '/v1/subscriptions/' + subscription) {
    return response.end(JSON.stringify({id:subscription,customer,status:'past_due',collection_method:'charge_automatically',
      default_payment_method:{id:'pm_PRIVATE',card:{last4:'0009'}},metadata:{sensitive:'unrelated secret'}}))
  }
  return fail()
})

try {
  const owner = await person('owner')
  const candidate = await person('candidate')
  const other = await person('other')
  const tenant = await workspace(owner,'Billing paid workspace')
  const foreign = await workspace(other,'Foreign workspace')
  sql("insert into public.st_v2_members(workspace_id,user_id,role) values ('"+tenant+"','"+candidate.id+"','admin');"+
    "select public.st_v2_sync_billing('evt_adm12_"+suffix+"','"+owner.id+"','"+customer+"','"+subscription+
    "','business','active',now()+interval '1 day',false,now());"+
    "select sectalk_private.st_v7_write_usage('"+tenant+"','recording_ms','adm12',120000,now());")
  await new Promise((resolve,reject)=>stripeFixture.once('error',reject).listen(0,'127.0.0.1',resolve))
  child = spawn(process.execPath,[resolve('node_modules/next/dist/bin/next'),'start','--hostname','127.0.0.1','--port','3489'],{
    cwd:resolve('supabase/.temp/v4-auth-qa/device-commands-app'),stdio:'inherit',env:{...process.env,
      NEXT_PUBLIC_SUPABASE_URL:db,NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:publicKey,SECTALK_BILLING_SUPABASE_KEY:service,
      SECTALK_APP_URL:app,STRIPE_SECRET_KEY:providerKey,STRIPE_WEBHOOK_SECRET:'fixture_delegation_key',
      SECTALK_TEST_STRIPE_ORIGIN:'http://127.0.0.1:'+stripeFixture.address().port},
  })
  let ready = false
  for (let i=0;i<40 && child.exitCode===null;i++) {
    ready = await fetch(app+'/api/health',{signal:AbortSignal.timeout(2000)}).then(r=>r.ok).catch(()=>false)
    if (ready) break
    await setTimeout(500)
  }
  assert(ready,'Local production app started')
  const session = async person => data(await person.client.auth.getSession()).session
  const lookup = async (person,id=tenant) => fetch(app+'/api/billing/workspace?workspace='+id,{
    headers:{Authorization:'Bearer '+(await session(person)).access_token},
  })
  assert.equal((await lookup(candidate)).status,403)
  assert.equal((await lookup(owner)).status,403)
  assert.equal(providerReads,0)
  assert.deepEqual(data(await candidate.client.rpc('st_v7_billing_admin_view')),[])

  await fixtureAuthenticator(owner.client)
  browser = await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  async function pageFor(person) {
    const page = await browser.newPage()
    await page.addInitScript(({name,value})=>localStorage.setItem(name,JSON.stringify(value)),
      {name:'sb-'+new URL(db).hostname.split('.')[0]+'-auth-token',value:await session(person)})
    await page.goto(app+'/?billing=workspace')
    return page
  }
  const ownerPage = await pageFor(owner)
  await ownerPage.getByRole('link',{name:'Manage workspace billing access',exact:true}).click()
  await ownerPage.getByLabel('Workspace',{exact:true}).selectOption(tenant)
  await ownerPage.getByRole('button',{name:'Manage billing access',exact:true}).click()
  await ownerPage.getByLabel('Workspace member').selectOption(candidate.id)
  await ownerPage.getByRole('button',{name:'Grant billing access',exact:true}).click()
  await ownerPage.getByText('Billing access granted.',{exact:true}).waitFor()
  assert.equal((await lookup(candidate,foreign)).status,403)
  assert.equal(providerReads,0)

  const result = await lookup(candidate)
  assert.equal(result.status,200,await result.clone().text())
  const billing = await result.json()
  assert.deepEqual(billing.invoices.map(invoice=>invoice.number),['BILLING-FIXTURE'])
  assert.deepEqual(billing.payment,{status:'past_due',collection:'charge_automatically',subscription_method_set:true})
  assert.doesNotMatch(JSON.stringify(billing),/never-return|last4|pm_PRIVATE|unrelated secret|INTERNAL|invoice\.stripe/i)
  const delegatePage = await pageFor(candidate)
  await delegatePage.getByRole('link',{name:'Workspace billing',exact:true}).click()
  await delegatePage.getByLabel('Workspace',{exact:true}).selectOption(tenant)
  await delegatePage.getByText('business (version 1)',{exact:true}).waitFor()
  await delegatePage.getByText('2 of 100',{exact:true}).waitFor()
  await delegatePage.getByRole('cell',{name:'BILLING-FIXTURE',exact:true}).waitFor()
  await delegatePage.getByText('past due',{exact:true}).waitFor()
  assert.equal(await delegatePage.getByRole('region',{name:'Billing administrator access'}).count(),0)
  await ownerPage.getByRole('button',{name:'Revoke billing access',exact:true}).click()
  await ownerPage.getByText('Billing access revoked.',{exact:true}).waitFor()
  const before = providerReads
  assert.equal((await lookup(candidate)).status,403)
  assert.equal(providerReads,before)
  assert.deepEqual(data(await candidate.client.rpc('st_v7_billing_admin_view')),[])
  console.log('Delegated billing browser, owner grant/revoke, scoped Stripe invoices, redaction, and tenant denial passed')
} finally {
  await browser?.close()
  child?.kill()
  stripeFixture.closeAllConnections()
  await new Promise(resolve=>stripeFixture.close(resolve))
  for (const id of spaces) sql("delete from public.st_v2_workspaces where id='"+id+"';")
  for (const id of users) await admin.auth.admin.deleteUser(id)
  sql("delete from sectalk_private.st_v2_billing_events where event_id='evt_adm12_"+suffix+"';")
}
