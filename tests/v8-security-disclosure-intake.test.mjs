import assert from 'node:assert/strict'
import test from 'node:test'
import {getSecurityDisclosure,vulnerabilityIntakeContact} from '../apps/web/lib/security-disclosure.ts'

test('first-party publication needs configured intake and keeps valid explicit overrides',()=>{
  const origin='https://security.example.invalid'
  const settings={
    SECTALK_APP_URL:origin,
    NEXT_PUBLIC_SUPABASE_URL:'https://storage.example.invalid',
    NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:'synthetic-public',
    SECTALK_DISCLOSURE_SERVICE_KEY:'synthetic-service',
    SECTALK_DISCLOSURE_ENCRYPTION_KEY:Buffer.alloc(32,1).toString('base64url'),
    SECTALK_SECURITY_CONTACT_EXPIRES:new Date(Date.now()+86400000).toISOString().replace(/\.\d{3}Z$/,'Z'),
    SECTALK_SECURITY_CONTACT:undefined,
  }
  const saved=Object.fromEntries(Object.keys(settings).map(key=>[key,process.env[key]]))
  function setting(key,value){if(value===undefined)delete process.env[key];else process.env[key]=value}
  Object.entries(settings).forEach(([key,value])=>setting(key,value))
  try {
    const intake=origin+'/security/report'
    assert.equal(vulnerabilityIntakeContact(),intake)
    assert.equal(getSecurityDisclosure()?.contact,intake)
    process.env.SECTALK_SECURITY_CONTACT='mailto:report@example.invalid'
    assert.equal(getSecurityDisclosure()?.contact,'mailto:report@example.invalid')
    process.env.SECTALK_SECURITY_CONTACT='invalid contact'
    assert.equal(getSecurityDisclosure(),null)
    process.env.SECTALK_SECURITY_CONTACT=intake
    delete process.env.SECTALK_DISCLOSURE_SERVICE_KEY
    assert.equal(vulnerabilityIntakeContact(),null)
    assert.equal(getSecurityDisclosure(),null)
    process.env.SECTALK_SECURITY_CONTACT='mailto:report@example.invalid'
    assert.equal(getSecurityDisclosure()?.contact,'mailto:report@example.invalid')
    process.env.SECTALK_DISCLOSURE_SERVICE_KEY='synthetic-service'
    process.env.SECTALK_SECURITY_CONTACT_EXPIRES='2000-01-01T00:00:00Z'
    assert.equal(vulnerabilityIntakeContact(),null)
    assert.equal(getSecurityDisclosure(),null)
  } finally {Object.entries(saved).forEach(([key,value])=>setting(key,value))}
})
