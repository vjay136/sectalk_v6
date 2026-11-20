import assert from 'node:assert/strict'
import test from 'node:test'
import { secretFindings } from '../scripts/verify-secrets.mjs'
import { providerFailureEvent } from '../apps/web/lib/provider-log.mjs'

test('credential findings contain rule names and omit detected values',()=>{
  const supabase='sb_'+'secret_'+'x'.repeat(26)
  const header=Buffer.from(JSON.stringify({alg:'HS256',typ:'JWT'})).toString('base64url')
  const service=Buffer.from(JSON.stringify({role:'service_role'})).toString('base64url')
  const publicRole=Buffer.from(JSON.stringify({role:'anon'})).toString('base64url')
  const tail='y'.repeat(24)
  assert.deepEqual(secretFindings(supabase+' '+header+'.'+service+'.'+tail),
    ['Supabase secret key','Supabase service-role JWT'])
  assert.deepEqual(secretFindings(header+'.'+publicRole+'.'+tail),[])
})

test('the scanner rejects unknown public variables, raw logging, and build values',()=>{
  const configured='provider-value-'+String(9).repeat(20)
  assert.deepEqual(secretFindings('process.env.NEXT_PUBLIC_SUPABASE_URL',{source:true}),[])
  assert.deepEqual(secretFindings('process.env["NEXT_PUBLIC_ADMIN_TOKEN"]; console.error(provider)',{source:true}),
    ['Unapproved browser environment variable NEXT_PUBLIC_ADMIN_TOKEN','Direct console logging in application source'])
  assert.deepEqual(secretFindings('asset:'+configured,{privateValues:[configured]}),
    ['Configured server-only value in a browser asset'])
})

test('provider logs serialize only known operation labels and failure categories',()=>{
  assert.deepEqual(JSON.parse(providerFailureEvent('meeting_signing','signing_failed')),{
    level:'warn',event:'provider_failure',service:'meeting_signing',failure:'signing_failed',
  })
  const payload={role:'service_role', token:'private-test-value'}
  const log=providerFailureEvent(payload,new Error('private-test-value'),payload)
  assert.equal(log.includes('private-test-value'),false)
  assert.deepEqual(JSON.parse(log),{level:'warn',event:'provider_failure',service:'unknown',failure:'unknown'})
})
