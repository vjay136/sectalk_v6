import assert from 'node:assert/strict'
import test from 'node:test'
import { createClient } from '@supabase/supabase-js'
import { attachmentReadinessStatus, checkReadiness, checkSignupServiceReadiness, readinessResponse } from '../apps/web/lib/readiness.ts'
import { hostedSignup, signupConfiguration } from '../apps/web/lib/signup-configuration.mjs'
import { supabaseApiFetch } from '../apps/web/lib/supabase-api-fetch.mjs'

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
  assert.equal(signupConfiguration(request,{...env,SECTALK_SIGNUP_ADMISSION_SERVICE_KEY:config.key}),null)
  assert.equal(signupConfiguration(request,{...env,SECTALK_SIGNUP_ADMISSION_SERVICE_KEY:'sb_publishable_different'}),null)
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

test('signup readiness verifies the credential without issuing a signup admission permit',async()=>{
  const service={...config,key:'sb_secret_fixture'}
  const ready=await checkSignupServiceReadiness(service,async(url,options)=>{
    assert.equal(url.pathname,'/rest/v1/rpc/st_v8_signup_service_ready')
    assert.deepEqual(options.headers,{apikey:service.key,'Content-Type':'application/json'})
    assert.deepEqual(JSON.parse(options.body),{})
    return Response.json(true)
  })
  assert.equal(ready,true)
  assert.equal(await checkSignupServiceReadiness(service,async()=>Response.json(true,{status:401})),false)
})

test('signup transport uses the modern key via apikey for both Auth and PostgREST',async()=>{
  const modernKey='sb_secret_fixture'
  const requests=[]
  const client=createClient(config.url,modernKey,{
    auth:{persistSession:false,autoRefreshToken:false},
    global:{fetch:supabaseApiFetch(modernKey,async(input,options)=>{
      assert.equal(options.headers.get('apikey'),modernKey)
      assert.equal(options.headers.get('authorization'),null)
      assert.equal(options.redirect,'error')
      requests.push(new URL(input).pathname)
      return Response.json(true)
    })},
  })
  await client.rpc('st_v8_signup_service_ready')
  await client.auth.admin.createUser({email:'fixture@example.invalid'})
  assert.deepEqual(requests,['/rest/v1/rpc/st_v8_signup_service_ready','/auth/v1/admin/users'])
  for (const [key,bearer] of [['legacy-token','legacy-token'],[modernKey,'different-token']]) {
    await supabaseApiFetch(key,async(_,options)=>{
      assert.equal(options.headers.get('authorization'),`Bearer ${bearer}`)
    })(config.url,{headers:{Authorization:`Bearer ${bearer}`}})
  }
})

test('hosted attachment readiness requires a server key, distinct ticket secret and private chat bucket',async()=>{
  const storage={...config,key:'sb_secret_fixture',publishableKey:config.key,ticketSecret:'x'.repeat(32)}
  const bucket={id:'sectalk-chat-files',public:false}
  assert.equal(await attachmentReadinessStatus(storage,async(url,options)=>{
    assert.equal(url.pathname,'/storage/v1/bucket/sectalk-chat-files')
    assert.equal(options.method,'GET')
    assert.equal(options.cache,'no-store')
    assert.equal(options.redirect,'error')
    assert.equal(options.headers.get('apikey'),storage.key)
    assert.equal(options.headers.get('authorization'),null)
    return Response.json(bucket)
  }),'ready')
  for(const invalid of [
    {key:undefined},{key:config.key},{key:'sb_publishable_other'},
    {ticketSecret:'short'},{ticketSecret:undefined},{key:storage.ticketSecret},
  ]) {
    let requested=false
    assert.notEqual(await attachmentReadinessStatus({...storage,...invalid},async()=>{requested=true}),'ready')
    assert.equal(requested,false)
  }
  for(const response of [
    Response.json(bucket,{status:403}),Response.json({...bucket,public:true}),
    Response.json({...bucket,id:'other-bucket'}),new Response('invalid'),
  ]) assert.notEqual(await attachmentReadinessStatus(storage,async()=>response),'ready')
  assert.equal(await attachmentReadinessStatus({...storage,key:'legacy-fixture'},async(_,options)=>{
    assert.equal(options.headers.get('authorization'),'Bearer legacy-fixture')
    return Response.json(bucket)
  }),'ready')
  assert.equal(await attachmentReadinessStatus({...storage,ticketSecret:'short'}),'invalid_ticket_secret')
  assert.equal(await attachmentReadinessStatus({...storage,key:'sb_publishable_other'}),'invalid_storage_configuration')
  assert.equal(await attachmentReadinessStatus(storage,async()=>Response.json({message:'ignored'},{status:401})),'storage_key_rejected')
  assert.equal(await attachmentReadinessStatus(storage,async()=>Response.json(bucket,{status:503})),'storage_unavailable')
  assert.equal(await attachmentReadinessStatus(storage,async()=>Response.json({...bucket,public:true})),'private_bucket_not_verified')
})

test('fails closed when configuration, network or the response body is invalid',async()=>{
  let called=false
  assert.equal(await checkReadiness({},async()=>{called=true}),false)
  assert.equal(called,false)
  assert.equal(await checkReadiness(config,async()=>{throw new Error('network unavailable')}),false)
  assert.equal(await checkReadiness(config,async()=>new Response('broken json')),false)
})
