import assert from 'node:assert/strict'
import test from 'node:test'
import { checkReadiness } from '../apps/web/lib/readiness.ts'

const config={url:'https://database.example.invalid',key:'publishable-key'}

test('requires a successful response with a boolean readiness marker',async()=>{
  let called=false
  assert.equal(await checkReadiness(config,async (url,options)=>{
    called=true
    assert.equal(url.pathname,'/rest/v1/rpc/st_v8_release_ready')
    assert.equal(options.headers.apikey,config.key)
    assert.equal(options.cache,'no-store')
    assert.equal(options.redirect,'error')
    assert.deepEqual(JSON.parse(options.body),{p_surface:'web'})
    return Response.json(true)
  }),true)
  assert.ok(called)
  assert.equal(await checkReadiness(config,async()=>Response.json(false)),false)
  assert.equal(await checkReadiness(config,async()=>Response.json(true,{status:500})),false)
})

test('uses the correct schema check for separately deployed services',async()=>{
  for(const service of ['admin','workers']){
    assert.equal(await checkReadiness(config,async(_,options)=>{
      assert.deepEqual(JSON.parse(options.body),{p_surface:service})
      return Response.json(true)
    },service),true)
  }
})

test('fails closed when configuration, network or the response body is invalid',async()=>{
  let called=false
  assert.equal(await checkReadiness({},async()=>{called=true}),false)
  assert.equal(called,false)
  assert.equal(await checkReadiness(config,async()=>{throw new Error('network unavailable')}),false)
  assert.equal(await checkReadiness(config,async()=>new Response('broken json')),false)
})
