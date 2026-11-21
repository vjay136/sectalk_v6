import assert from 'node:assert/strict'
import test from 'node:test'
import { checkReadiness, readinessResponse } from '../apps/web/lib/readiness.ts'
import { hostedSignup, signupConfiguration } from '../apps/web/lib/signup-configuration.mjs'

const config={url:'https://database.example.invalid',key:'publishable-key'}

test('hosted signup requires its server credential and a valid HTTPS confirmation origin',async()=>{
  const origin='https://sectalk.example.com'
  const request=origin+'/api/ready'
  const env={
    VERCEL:'1',VERCEL_ENV:'production',SECTALK_APP_URL:origin,
    NEXT_PUBLIC_SUPABASE_URL:config.url,NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:config.key,
  }
  assert.ok(hostedSignup(env))
  assert.equal(signupConfiguration(request,env),null)
  const response=await readinessResponse('web',false)
  assert.equal(response.status,503)
  assert.deepEqual(await response.json(),{status:'not_ready'})
  assert.equal(signupConfiguration(request,{...env,SECTALK_SIGNUP_ADMISSION_SERVICE_KEY:' ' }),null)
  assert.equal(signupConfiguration(request,{...env,SECTALK_AUTH_RISK_SERVICE_KEY:'synthetic-workflow-key'})?.redirect,
    origin+'/auth/confirm')
  const keyed={...env,SECTALK_SIGNUP_ADMISSION_SERVICE_KEY:'synthetic-signup-key'}
  assert.equal(signupConfiguration(request,keyed)?.serviceKey,'synthetic-signup-key')
  assert.equal(signupConfiguration(request,{...keyed,SECTALK_APP_URL:'http://localhost:3000'}),null)
  assert.equal(signupConfiguration(request,{...keyed,SECTALK_APP_URL:''}),null)
})

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
