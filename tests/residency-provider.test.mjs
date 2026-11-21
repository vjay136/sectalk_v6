import assert from 'node:assert/strict'
import test from 'node:test'
import {verifyProviderTarget} from '../apps/web/lib/residency-provider.ts'

const target={cell:'20000000-0000-4000-8000-000000000001',project:'abcdefghijklmnopqrst',region:'eu-central-1',organization:'qa-organization'}
const runtime={controlProject:'zzzzzzzzzzzzzzzzzzzz',managementToken:'synthetic_read_token_for_fixture',
  publishableKey:'sb_publishable_disposablefixture',installationNonce:'20000000-0000-4000-8000-000000000002'}
const record={ref:target.project,region:target.region,organization_slug:target.organization,status:'ACTIVE_HEALTHY'}

test('reads the exact Supabase project and independent installation without forwarding management credentials',async()=>{
  const calls=[]
  const mock=async(url,options)=>{
    calls.push({url,options})
    return Response.json(calls.length===1?record:true)
  }
  assert.equal(await verifyProviderTarget(target,runtime,mock),true)
  assert.equal(calls[0].url,'https://api.supabase.com/v1/projects/'+target.project)
  assert.equal(calls[0].options.headers.Authorization,'Bearer '+runtime.managementToken)
  assert.equal(calls[0].options.method,undefined)
  assert.equal(calls[1].url,'https://'+target.project+'.supabase.co/rest/v1/rpc/st_v8_residency_target_ready')
  assert.equal(calls[1].options.headers.Authorization,undefined)
  assert.equal(calls[1].options.headers.apikey,runtime.publishableKey)
  assert.deepEqual(JSON.parse(calls[1].options.body),{
    p_cell:target.cell,p_project:target.project,p_installation_nonce:runtime.installationNonce,
  })
  assert.ok(calls.every(call=>call.options.redirect==='error'&&call.options.cache==='no-store'))
})

test('rejects provider mismatches without probing a target',async()=>{
  for(const replacement of [{ref:runtime.controlProject},{region:'eu-west-1'},{organization_slug:'wrong-org'},{status:'INACTIVE'}]) {
    let calls=0
    const mock=async()=>{
      calls++
      return Response.json({...record,...replacement})
    }
    assert.equal(await verifyProviderTarget(target,runtime,mock),false)
    assert.equal(calls,1)
  }
  assert.equal(await verifyProviderTarget(target,{...runtime,controlProject:target.project},
    async()=>assert.fail('Control project must never be probed as dedicated')),false)
  assert.equal(await verifyProviderTarget(target,{...runtime,publishableKey:'sb_secret_fake_secret'},
    async()=>assert.fail('Privileged credentials must never be sent to this probe')),false)
})

test('rejects missing or oversized verification observations',async()=>{
  for(const response of [Response.json(false),new Response('x'.repeat(40000)),new Response(null,{status:403})]) {
    let count=0
    assert.equal(await verifyProviderTarget(target,runtime,async()=>++count===1?Response.json(record):response),false)
  }
})
