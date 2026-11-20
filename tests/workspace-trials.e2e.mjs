import assert from 'node:assert/strict'
import { createHmac, randomUUID } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { createServer } from 'node:http'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const backend = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(backend.origin, 'http://127.0.0.1:55321')
const required=process.env.SECTALK_TRIAL_TEST_MODE==='required'
const options={auth:{persistSession:false,autoRefreshToken:false}}
const admin=createClient(backend.href,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const { chromium }=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
const users=[]
const slug=randomUUID().slice(0,8)
const password=randomUUID()+'!3q'
const sessionId='cs_test_trial'+slug
const setupId='seti_test_trial'+slug
const webCheckout='https://checkout.stripe.com/c/setup/'+sessionId
let started=0
let retrieved=0
let requestFields
let workspace
let server

function data(result) {
  if(result.error)throw result.error
  return result.data
}

async function actor(label) {
  const handle=`trial_${label}_${slug}`
  const email=handle+'@example.invalid'
  const {user}=data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  users.push(user.id)
  const client=createClient(backend.href,process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY,options)
  const {session}=data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:label+' trial QA'}))
  return {client,session,handle,email}
}

async function webhook(fields, signatureCorrect=true) {
  const created=Math.floor(Date.now()/1000)
  const reservation=requestFields.get('client_reference_id')
  const payload=JSON.stringify({id:'evt_trial_'+slug,type:'checkout.session.completed',created,data:{object:{
    id:sessionId,mode:'setup',status:'complete',client_reference_id:reservation,
    metadata:{sectalk_workspace_trial:reservation},setup_intent:setupId,...fields,
  }}})
  const key=process.env.SECTALK_TRIAL_WEBHOOK_FIXTURE_SECRET
  assert.ok(key)
  const signature=createHmac('sha256',key).update(`${created}.${payload}`).digest('hex')
  return fetch(new URL('/api/billing/webhook',app),{method:'POST',headers:{
    'Stripe-Signature':`t=${created},v1=${signatureCorrect?signature:'0'.repeat(64)}`,
  },body:payload})
}

try {
  if(required){
    server=createServer(async(req,res)=>{
      const send=body=>{res.setHeader('Content-Type','application/json');res.end(JSON.stringify(body))}
      if(req.url==='/v1/checkout/sessions'&&req.method==='POST'){
        started++
        const chunks=[]
        for await(const chunk of req)chunks.push(chunk)
        requestFields=new URLSearchParams(Buffer.concat(chunks).toString())
        send({id:sessionId,status:'open',url:webCheckout});return
      }
      if(req.url==='/v1/setup_intents/'+setupId){
        retrieved++;send({id:setupId,status:'succeeded',payment_method:'pm_fixture',payment_method_types:['card']});return
      }
      res.statusCode=409;send({error:{type:'invalid_request_error',message:'Unexpected fixture request'}})
    })
    await new Promise(resolve=>server.listen(Number(process.env.SECTALK_TRIAL_FIXTURE_PORT),'127.0.0.1',resolve))
  }
  const owner=await actor('owner')
  const member=await actor('member')
  workspace=data(await owner.client.rpc('st_v2_create_workspace',{p_name:'Trial workspace '+slug}))
  data(await owner.client.rpc('st_v2_invite',{p_workspace:workspace,p_handle:member.handle}))
  const invitations=data(await member.client.from('st_v2_invites').select('id').eq('workspace_id',workspace))
  data(await member.client.rpc('st_v2_reply_invite',{p_invite:invitations[0].id,p_accept:true}))
  const endpoint=new URL('/api/workspaces/trial?workspace='+workspace,app)
  assert.equal((await fetch(endpoint)).status,401)
  assert.equal((await fetch(endpoint,{headers:{Authorization:'Bearer '+member.session.access_token}})).status,403)

  const page=await browser.newPage()
  await page.goto(app.href)
  await page.getByLabel('Email address',{exact:true}).fill(owner.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Workspaces',exact:true}).click()
  const tabs=page.getByRole('group',{name:'Workspace sections'})
  await tabs.getByRole('button',{name:'Trial',exact:true}).click()
  let panel=page.getByRole('region',{name:'Workspace trial',exact:true})
  await panel.getByLabel('Trial plan',{exact:true}).selectOption(required?'professional':'business')
  if(required)await page.route('https://checkout.stripe.com/**',route=>route.fulfill({status:200,body:'Controlled card confirmation fixture'}))
  const response=page.waitForResponse(result=>result.url().endsWith('/api/workspaces/trial')&&result.request().method()==='POST')
  await panel.getByRole('button',{name:required?'Confirm a card with Stripe':'Start 14-day trial',exact:true}).click()
  assert.equal((await response).status(),200)

  if(required){
    await page.waitForURL(webCheckout)
    assert.equal(started,1)
    assert.equal(requestFields.get('mode'),'setup')
    assert.equal(requestFields.get('allowed_payment_method_types[0]'),'card')
    assert.equal(requestFields.get('metadata[sectalk_workspace_trial]'),requestFields.get('client_reference_id'))
    assert.equal(requestFields.get('success_url'),new URL('/?trial=return',app).href)
    assert.ok(![...requestFields.keys()].some(key=>key.startsWith('line_items')))
    await page.goto(requestFields.get('success_url'))
    panel=page.getByRole('region',{name:'Workspace trial',exact:true})
    await panel.getByText('Waiting for Stripe to confirm the card for this trial.',{exact:true}).waitFor()
    assert.equal((await webhook({},false)).status,400)
    assert.equal((await webhook({id:'cs_test_wrong123'})).status,204)
    assert.equal((await fetch(endpoint,{headers:{Authorization:'Bearer '+owner.session.access_token}}).then(res=>res.json())).state,'pending')
    assert.equal((await webhook({})).status,204)
    assert.equal((await webhook({})).status,204)
    assert.ok(retrieved>=2)
  }
  await panel.getByText(required?/Professional trial is active/:/Business \(Team\) trial is active/).waitFor()
  const expiration=await panel.locator('time').getAttribute('datetime')
  assert.ok(Math.abs(Date.parse(expiration)-Date.now()-336*3600000)<30000)
  assert.equal(data(await owner.client.rpc('st_v7_my_entitlements')).plan,'free')
  const summary=data(await owner.client.rpc('st_v6_workspace_admin_overview',{p_workspace:workspace}))
  assert.equal(summary.seat_limit,required?30:100)
  console.log('Passed real trial UI and policy enforcement for '+(required?'hosted card confirmation via a loopback Stripe contract and signed webhook':'optionally card-free activation')+'.')
} finally {
  await browser.close()
  if(server)await new Promise(resolve=>server.close(resolve))
  if(workspace)execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-q','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres'],{
    input:`delete from public.st_v2_workspaces where id='${workspace}';`,windowsHide:true,
  })
  for(const user of users)data(await admin.auth.admin.deleteUser(user))
}
