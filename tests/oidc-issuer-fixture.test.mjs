import assert from 'node:assert/strict'
import { createHash, createPublicKey, randomBytes, randomUUID, verify } from 'node:crypto'
import { once } from 'node:events'
import { test } from 'node:test'
import { createSyntheticOidcIssuer } from './fixtures/oidc-issuer.mjs'

const secret = () => randomBytes(32).toString('base64url')
const issuer = 'https://oidc.qa.example.invalid'
const callback = 'http://127.0.0.1:3563/auth/v1/callback'
const clientId = 'sectalk-qa-' + randomBytes(4).toString('hex')
const clientSecret = secret(), testerCode = secret()
const email = 'verified@tenant-' + clientId.slice(-8) + '.example.invalid'

test('synthetic OIDC discovery, signed tokens and single-use S256 authorization', async () => {
  let time = Date.now()
  const server = createSyntheticOidcIssuer({ issuer, clientId, clientSecret, testerCode, email, now: () => time })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const base = 'http://127.0.0.1:' + server.address().port
  try {
    const discovery = await fetch(base + '/.well-known/openid-configuration').then(response => response.json())
    assert.equal(discovery.issuer, issuer)
    assert.deepEqual(discovery.code_challenge_methods_supported, ['S256'])
    for (const [field, path] of Object.entries({ authorization_endpoint: '/authorize', token_endpoint: '/token', jwks_uri: '/jwks', userinfo_endpoint: '/userinfo' })) {
      assert.equal(discovery[field], issuer + path)
    }
    const verifier = secret(), state = randomUUID(), nonce = secret()
    const challenge = createHash('sha256').update(verifier).digest('base64url')
    const authorization = new URLSearchParams({ client_id: clientId, redirect_uri: callback, response_type: 'code',
      scope: 'openid profile email', code_challenge_method: 'S256', code_challenge: challenge, state, nonce })
    const post = (path, values, headers) => fetch(base + path, { method: 'POST', body: new URLSearchParams(values),
      headers, redirect: 'manual' })
    const authorize = params => fetch(base + '/authorize?' + params, { redirect: 'manual' })
    const ticket = async () => {
      const response = await authorize(authorization)
      assert.equal(response.status, 200)
      assert.equal(response.headers.get('content-security-policy'),
        "default-src 'none'; form-action 'self' " + callback +
        " http://127.0.0.1:3564/auth/workspace-sso; frame-ancestors 'none'")
      const content = await response.text()
      assert.ok(!content.includes(testerCode))
      return content.match(/name="ticket" value="([A-Za-z0-9_-]{43})"/)?.[1]
    }
    const grant = async (ticketId) => {
      const result = await post('/authorize', { ticket: ticketId, tester_code: testerCode })
      assert.equal(result.status, 303)
      const next = new URL(result.headers.get('location'))
      assert.equal(next.origin + next.pathname, callback)
      assert.equal(next.searchParams.get('state'), state)
      return next.searchParams.get('code')
    }
    const swap = (code, values = {}, headers) => post('/token', {
      grant_type: 'authorization_code', redirect_uri: callback, code, code_verifier: verifier, ...values,
    }, headers)
    const basic = { Authorization: 'Basic ' + Buffer.from(clientId + ':' + clientSecret).toString('base64') }
    assert.equal((await authorize(new URLSearchParams({ ...Object.fromEntries(authorization), redirect_uri: callback + '/' }))).status, 400)
    assert.equal((await authorize(new URLSearchParams({ ...Object.fromEntries(authorization), code_challenge_method: 'plain' }))).status, 400)
    const flow = await ticket()
    assert.equal((await post('/authorize', { ticket: flow, tester_code: secret() })).status, 403)
    const code = await grant(flow)
    assert.equal((await post('/authorize', { ticket: flow, tester_code: testerCode })).status, 403)
    assert.equal((await swap(code, { client_id: clientId, client_secret: secret() })).status, 401)
    assert.equal((await swap(code, { redirect_uri: callback + '/' }, basic)).status, 400)
    const result = await swap(code, {}, basic)
    assert.equal(result.status, 200)
    const { access_token: access, id_token: jwt } = await result.json()
    const [header, payload, signature] = jwt.split('.')
    const { keys: [jwk] } = await fetch(base + '/jwks').then(response => response.json())
    assert.equal(JSON.parse(Buffer.from(header, 'base64url')).kid, jwk.kid)
    assert.ok(verify('RSA-SHA256', Buffer.from(header + '.' + payload), createPublicKey({ key: jwk, format: 'jwk' }),
      Buffer.from(signature, 'base64url')))
    const claims = JSON.parse(Buffer.from(payload, 'base64url'))
    assert.deepEqual([claims.iss, claims.aud, claims.nonce, claims.email, claims.email_verified], [issuer, clientId, nonce, email, true])
    assert.equal((await fetch(base + '/userinfo')).status, 401)
    const user = await fetch(base + '/userinfo', { headers: { Authorization: 'Bearer ' + access } }).then(response => response.json())
    assert.deepEqual([user.sub, user.email], [claims.sub, email])
    assert.equal((await swap(code, {}, basic)).status, 400)
    const concurrent = await grant(await ticket())
    const concurrentStatuses = await Promise.all([1, 2].map(async () => (await swap(concurrent, {
      client_id: clientId, client_secret: clientSecret,
    })).status))
    assert.deepEqual(concurrentStatuses.sort(), [200, 400])
    const wrongProof = await grant(await ticket())
    assert.equal((await swap(wrongProof, { code_verifier: secret() }, basic)).status, 400)
    assert.equal((await swap(wrongProof, {}, basic)).status, 400)
    const expired = await grant(await ticket())
    time += 61_000
    assert.equal((await swap(expired, {}, basic)).status, 400)
    const expiredTicket = await ticket()
    time += 121_000
    assert.equal((await post('/authorize', { ticket: expiredTicket, tester_code: testerCode })).status, 403)
    assert.equal((await fetch(base + '/userinfo', { headers: { Authorization: 'Bearer ' + access } })).status, 401)
  } finally {
    await new Promise(resolve => server.close(resolve))
  }
})

test('fixture only issues synthetic identities with independent tester credentials', () => {
  const setup = { issuer, clientId, clientSecret, testerCode, email }
  assert.throws(() => createSyntheticOidcIssuer({ ...setup, email: 'real@example.com' }), /configuration is invalid/)
  assert.throws(() => createSyntheticOidcIssuer({ ...setup, testerCode: clientSecret }), /configuration is invalid/)
})

test('fixture can use an exact disposable hosted callback without accepting other projects or following the redirect',async()=>{
  const disposableProjectRef='a'.repeat(20)
  const hosted='https://'+disposableProjectRef+'.supabase.co/auth/v1/callback'
  const server=createSyntheticOidcIssuer({issuer,clientId,clientSecret,testerCode,email,disposableProjectRef})
  server.listen(0,'127.0.0.1')
  await once(server,'listening')
  const base='http://127.0.0.1:'+server.address().port
  const state=randomUUID(),challenge=createHash('sha256').update(secret()).digest('base64url')
  const start=redirect_uri=>fetch(base+'/authorize?'+new URLSearchParams({client_id:clientId,redirect_uri,
    response_type:'code',scope:'openid email',state,code_challenge:challenge,code_challenge_method:'S256'}),{redirect:'manual'})
  try{
    for(const unauthorized of [callback,hosted.replace(disposableProjectRef,'b'.repeat(20)),hosted+'?extra=1']){
      const result=await start(unauthorized)
      assert.equal(result.status,400)
      await result.body.cancel()
    }
    const authorized=await start(hosted)
    assert.equal(authorized.status,200)
    assert.equal(authorized.headers.get('content-security-policy'),
      "default-src 'none'; form-action 'self' " + hosted + "; frame-ancestors 'none'")
    const ticket=(await authorized.text()).match(/name="ticket" value="([A-Za-z0-9_-]{43})"/)?.[1]
    assert.ok(ticket)
    const result=await fetch(base+'/authorize',{method:'POST',redirect:'manual',
      body:new URLSearchParams({ticket,tester_code:testerCode})})
    assert.equal(result.status,303)
    const destination=new URL(result.headers.get('location'))
    assert.equal(destination.origin+destination.pathname,hosted)
    assert.equal(destination.searchParams.get('state'),state)
  }finally{
    await new Promise(resolve=>server.close(resolve))
  }
  assert.throws(()=>createSyntheticOidcIssuer({issuer,clientId,clientSecret,testerCode,email,
    disposableProjectRef:'https://somewhere.example.invalid'}),/configuration is invalid/)
})
