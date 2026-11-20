import assert from 'node:assert/strict'
import {createHmac, randomUUID} from 'node:crypto'
import {spawn, execFileSync} from 'node:child_process'
import {createServer} from 'node:http'
import {resolve} from 'node:path'
import {setTimeout} from 'node:timers/promises'
import {createClient} from '@supabase/supabase-js'

const db = new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
assert.equal(db, 'http://127.0.0.1:55321')
const app = 'http://127.0.0.1:3489'
const admin = createClient(db,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,{auth:{persistSession:false,autoRefreshToken:false}})
const key = 'sk_test_fixture' + randomUUID().replaceAll('-','')
const webhook = 'fixture_' + randomUUID()
const worker = randomUUID()
const suffix = randomUUID().replaceAll('-','')
const sub = 'sub_' + suffix
const customer = 'cus_' + suffix
const price = 'price_fixture' + suffix
const now = Math.floor(Date.now() / 1000)
let child, user, reads = 0, vendorStatus = 'active', available = true, wrongCustomer = false

function sql(statement) {
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true}).trim()
}
const collector = createServer((request,response) => {
  response.setHeader('Content-Type','application/json')
  if (request.method !== 'GET' || request.headers.authorization !== 'Bearer ' + key
    || request.url !== '/v1/subscriptions/' + sub) {
    response.writeHead(404).end(JSON.stringify({error:{message:'Missing fixture resource',code:'resource_missing'}}))
    return
  }
  reads++
  if (!available) {
    response.writeHead(503).end(JSON.stringify({error:{message:'Fixture unavailable',type:'api_error'}}))
    return
  }
  response.end(JSON.stringify({id:sub,object:'subscription',metadata:{sectalk_user:user.id},
    customer:wrongCustomer?'cus_Foreign':customer,status:vendorStatus,cancel_at_period_end:false,
    items:{data:[{current_period_end:now+604800, price:{id:price,unit_amount:1200,currency:'usd'}}]}}))
})

function signAndPost(body,timestamp = Math.floor(Date.now()/1000)) {
  const signature = createHmac('sha256',webhook).update(timestamp + '.' + body).digest('hex')
  return fetch(app+'/api/billing/webhook',{method:'POST',body,headers:{'Stripe-Signature':'t='+timestamp+',v1='+signature}})
}
function event(label, type = 'customer.subscription.updated', created = now) {
  return JSON.stringify({id:'evt_'+suffix+label,object:'event',livemode:false,type,created,
    data:{object:{id:sub,object:'subscription',status:type.endsWith('deleted')?'canceled':'active'}}})
}
try {
  const result = await admin.auth.admin.createUser({email:'billing_'+suffix+'@example.invalid',email_confirm:true})
  if (result.error) throw result.error
  user = result.data.user
  await new Promise((resolve,reject)=>collector.once('error',reject).listen(0,'127.0.0.1',resolve))
  child = spawn(process.execPath,[resolve('node_modules/next/dist/bin/next'),'start','--hostname','127.0.0.1','--port','3489'],{
    cwd:resolve('supabase/.temp/v4-auth-qa/device-commands-app'),stdio:'inherit',
    env:{...process.env,NEXT_PUBLIC_SUPABASE_URL:db,NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY,
      SECTALK_APP_URL:app,STRIPE_SECRET_KEY:key,STRIPE_WEBHOOK_SECRET:webhook,STRIPE_PRICE_BASIC_MONTHLY:price,
      SECTALK_TEST_STRIPE_ORIGIN:'http://127.0.0.1:'+collector.address().port,
      SECTALK_STRIPE_RECONCILE_SECRET:worker,SECTALK_BILLING_SUPABASE_KEY:process.env.SECTALK_STORAGE_TEST_SERVICE_KEY},
  })
  let ready = false
  for (let count=0; count<30 && child.exitCode===null; count++) {
    ready = await fetch(app+'/api/health',{signal:AbortSignal.timeout(3000)}).then(r=>r.ok).catch(()=>false)
    if (ready) break
    await setTimeout(500)
  }
  assert(ready, 'Isolated Stripe test app started')
  const first = event('First')
  assert.equal((await signAndPost(first,now-301)).status,400)
  assert.equal((await fetch(app+'/api/billing/webhook',{method:'POST',body:first,headers:{'Stripe-Signature':'invalid'}})).status,400)
  assert.equal(reads,0)
  assert.equal((await signAndPost(first)).status,204)
  assert.equal((await signAndPost(first)).status,204)
  assert.equal((await signAndPost(first+' ')).status,400)
  assert.equal(reads,1)
  const subscription = () => sql("select status from public.st_v2_subscriptions where user_id='"+user.id+"';")
  assert.equal(subscription(),'active')
  assert.equal((await signAndPost(event('StaleDelete','customer.subscription.deleted',now-60))).status,204)
  assert.equal(subscription(),'active')

  const retry = event('Retry')
  available=false
  assert.equal((await signAndPost(retry)).status,503)
  assert.equal(sql("select done from sectalk_private.st_v7_stripe_receipts where id='evt_"+suffix+"Retry';"),'f')
  available=true
  vendorStatus='past_due'
  assert.equal((await signAndPost(retry)).status,204)
  assert.equal(subscription(),'past_due')

  const drain = secret => fetch(app+'/api/billing/reconcile',{method:'POST',headers:{Authorization:'Bearer '+secret}})
  assert.equal((await drain('wrong')).status,401)
  const priorReads=reads
  wrongCustomer=true
  vendorStatus='active'
  assert.equal((await drain(worker)).status,200)
  assert.equal(subscription(),'past_due')
  assert.equal(reads,priorReads+1)
  const waitBackoff=await drain(worker)
  assert.equal(waitBackoff.status,200)
  assert.equal(reads,priorReads+1)
  sql("update sectalk_private.st_v7_stripe_reconcile set ready_at=now()-interval '1 second' where subscription='"+sub+"';")
  wrongCustomer=false
  const concurrent = await Promise.all([drain(worker),drain(worker)])
  assert(concurrent.every(response=>response.status===200))
  assert.equal(reads,priorReads+2)
  assert.equal(subscription(),'active')
  assert.equal((await drain(worker)).status,200)
  assert.equal(reads,priorReads+2)
  console.log('Stripe signature, immutable duplicate, provider retry, out-of-order reading, and scoped reconciliation passed')
} finally {
  child?.kill()
  collector.closeAllConnections()
  await new Promise(resolve=>collector.close(resolve))
  if (user) {
    sql("delete from sectalk_private.st_v2_billing_events where event_id like 'evt_"+suffix+"%' or event_id in (" +
      "select 'reconcile:'||lease::text from sectalk_private.st_v7_stripe_reconcile where subscription='"+sub+"');" +
      "delete from sectalk_private.st_v7_stripe_receipts where id like 'evt_"+suffix+"%';" +
      "delete from sectalk_private.st_v7_stripe_reconcile where subscription='"+sub+"';")
    await admin.auth.admin.deleteUser(user.id)
  }
}
