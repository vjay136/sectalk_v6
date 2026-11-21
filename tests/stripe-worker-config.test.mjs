import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import test from 'node:test'
import ts from 'typescript'

const requireModule = createRequire(import.meta.url)

function loadSource(path, env, imports) {
  const source = readFileSync(new URL('../apps/web/' + path, import.meta.url), 'utf8')
  const {outputText} = ts.transpileModule(source, {
    compilerOptions: {module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true},
  })
  const module = {exports: {}}
  const dependencies = name => {
    const key = name.split('/').at(-1)
    if (Object.hasOwn(imports,key)) return imports[key]
    return requireModule(name)
  }
  new Function('exports','require','module','process',outputText)(module.exports,dependencies,module,{env})
  return module.exports
}

test('Stripe reconciliation works without the web project webhook secret', async () => {
  const workerSecret = 'reconciliation-bearer-fixture-0001'
  const env = {
    STRIPE_SECRET_KEY:'sk_test_sectalk_worker_fixture',
    SECTALK_APP_URL:'http://127.0.0.1:3489',
    NEXT_PUBLIC_SUPABASE_URL:'http://127.0.0.1:55321',
    SECTALK_BILLING_SUPABASE_KEY:'local-database-fixture',
    SECTALK_STRIPE_RECONCILE_SECRET:workerSecret,
  }
  const ledgerCalls = []
  const stripeModule = loadSource('lib/stripe-server.ts',env,{
    billing:{paidPlans:[]},
    'supabase-js':{createClient:()=>({rpc:async name=>{
      ledgerCalls.push(name)
      return {data:[],error:null}
    }})},
  })
  assert.ok(stripeModule.stripeReconciliationClient)
  assert.equal(stripeModule.stripe,null)
  assert.equal(stripeModule.webhookSecret,undefined)

  const reconcile = loadSource('app/api/billing/reconcile/route.ts',env,{
    'stripe-server':stripeModule,
    'stripe-coupon':{},
    'stripe-renewal':{},
    'stripe-reconciliation':{},
    'notification-email-server':{notificationDrainAuthorized:(request,secret)=>request.headers.get('Authorization')==='Bearer '+secret},
    'stripe-workspace-seats':{closeWorkspaceSeatSubscriptions:async provider=>{
      assert.equal(provider,stripeModule.stripeReconciliationClient)
    }},
  })
  const request = secret => new Request(env.SECTALK_APP_URL+'/api/billing/reconcile',{
    method:'POST',headers:{Authorization:'Bearer '+secret},
  })
  assert.equal((await reconcile.POST(request('incorrect'))).status,401)
  assert.deepEqual(ledgerCalls,[])
  const authenticated = await reconcile.POST(request(workerSecret))
  assert.equal(authenticated.status,200)
  assert.deepEqual(await authenticated.json(),{processed:0,synchronized:0})
  assert.deepEqual(ledgerCalls,[
    'st_v7_stripe_reconcile_claim','st_v7_renewal_probe_claim','st_v7_coupon_probe_claim',
  ])

  const webhook = loadSource('app/api/billing/webhook/route.ts',env,{
    'stripe-server':stripeModule,
    'operational-metrics-server':{withOperationalMetrics:(_event,handle)=>handle()},
    'stripe-reconciliation':{},
    'stripe-coupon':{},
    'stripe-renewal':{},
    'stripe-workspace-seats':{},
    'stripe-invoice-adjustments':{},
    'razorpay-billing':{},
    'request-body':{},
  })
  const denied = await webhook.POST(new Request(env.SECTALK_APP_URL+'/api/billing/webhook',{
    method:'POST',headers:{'Stripe-Signature':'t=123,v1=invalid'},body:'{}',
  }))
  assert.equal(denied.status,503)
  assert.equal(ledgerCalls.length,3)
})
