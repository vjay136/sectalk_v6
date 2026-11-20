import assert from 'node:assert/strict'
import {execFileSync} from 'node:child_process'
import {randomUUID} from 'node:crypto'
import {createClient} from '@supabase/supabase-js'

const app=new URL(process.env.SECTALK_STORAGE_TEST_APP)
const origin=new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
assert.equal(app.hostname,'127.0.0.1')
assert.equal(origin,'http://127.0.0.1:55321')
const options={auth:{persistSession:false,autoRefreshToken:false}}
const admin=createClient(origin,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const client=createClient(origin,process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY,options)
const email='billing_assurance_'+randomUUID()+'@example.invalid'
const password=randomUUID()+'!aQ'
function data(result) {if (result.error) throw result.error; return result.data}
const {user}=data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
function post(jwt) {
  return fetch(new URL('/api/billing/action',app),{
    method:'POST',headers:{Origin:app.origin,'Content-Type':'application/json',Authorization:'Bearer '+jwt},
    body:JSON.stringify({action:'portal'}),
  })
}
try {
  const {session}=data(await client.auth.signInWithPassword({email,password}))
  const token=session.access_token
  const {session_id}=JSON.parse(Buffer.from(token.split('.')[1],'base64url').toString())
  assert.match(session_id,/^[a-f0-9-]{36}$/)
  const initial=await post(token)
  const initialStatus=initial.status
  assert.ok([404,503].includes(initialStatus))
  assert.deepEqual(await initial.json(),{error:initialStatus===404?'No billing account is linked yet.':
    'Payment checkout is unavailable on this deployment.'})
  execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres'],
    {input:"update auth.mfa_amr_claims set updated_at=now()-interval '6 minutes' where session_id='"+session_id+"';"})
  const denied=await post(token)
  assert.equal(denied.status,403)
  assert.deepEqual(await denied.json(),{error:'Verify your current sign-in to continue to billing.'})
  const refreshed=data(await client.auth.signInWithPassword({email,password})).session
  assert.equal((await post(refreshed.access_token)).status,initialStatus)
  console.log('Billing action accepted fresh native proof and rejected a valid but stale session before any payment-provider call.')
} finally { await admin.auth.admin.deleteUser(user.id) }
