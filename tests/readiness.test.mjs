import assert from 'node:assert/strict'
import test from 'node:test'
import { checkReadiness } from '../apps/web/lib/readiness.ts'

const config={url:'https://database.example.invalid',key:'publishable-key'}

test('requires a successful response with a boolean readiness marker',async()=>{
  let called=false
  assert.equal(await checkReadiness(config,async (url,options)=>{
    called=true
    assert.equal(url.pathname,'/rest/v1/rpc/st_v6_ready')
    assert.equal(options.headers.apikey,config.key)
    assert.equal(options.cache,'no-store')
    return Response.json(true)
  }),true)
  assert.ok(called)
  assert.equal(await checkReadiness(config,async()=>Response.json(false)),false)
  assert.equal(await checkReadiness(config,async()=>Response.json(true,{status:500})),false)
})

test('fails closed when configuration, network or the response body is invalid',async()=>{
  let called=false
  assert.equal(await checkReadiness({},async()=>{called=true}),false)
  assert.equal(called,false)
  assert.equal(await checkReadiness(config,async()=>{throw new Error('network unavailable')}),false)
  assert.equal(await checkReadiness(config,async()=>new Response('broken json')),false)
})
