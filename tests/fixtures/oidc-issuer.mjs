import { createHash, generateKeyPairSync, randomBytes, sign, timingSafeEqual } from 'node:crypto'
import { createServer } from 'node:http'
import { pathToFileURL } from 'node:url'

const fixtureCallback = 'http://127.0.0.1:3563/auth/v1/callback'
const fixtureAppCallback = 'http://127.0.0.1:3564/auth/workspace-sso'
const secretShape = /^[A-Za-z0-9_-]{43}$/
const verifierShape = /^[A-Za-z0-9._~-]{43,128}$/
const flowStateShape = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/
const id = () => randomBytes(32).toString('base64url')
const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url')
const digest = value => createHash('sha256').update(value).digest('base64url')
const matches = (expected, value) => typeof value === 'string' &&
  timingSafeEqual(Buffer.from(digest(expected)), Buffer.from(digest(value)))

async function formBody(request) {
  if (request.headers['content-type']?.split(';')[0] !== 'application/x-www-form-urlencoded') return null
  const chunks = []
  let size = 0
  for await (const part of request) {
    size += part.length
    if (size > 4096) return null
    chunks.push(part)
  }
  return new URLSearchParams(Buffer.concat(chunks).toString('utf8'))
}

const one = (form, name) => form.getAll(name).length === 1 ? form.get(name) : null

export function createSyntheticOidcIssuer({ issuer, clientId, clientSecret, testerCode, email, disposableProjectRef, now = Date.now }) {
  const url = URL.parse(issuer ?? '')
  if (url?.protocol !== 'https:' || url.origin !== issuer || !/^(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]*$/.test(url.hostname) ||
      !/^sectalk-qa-[a-f0-9]{8}$/.test(clientId ?? '') || !secretShape.test(clientSecret ?? '') ||
      !secretShape.test(testerCode ?? '') || testerCode === clientSecret ||
      (disposableProjectRef!==undefined&&(typeof disposableProjectRef!=='string'||!/^[a-z]{20}$/.test(disposableProjectRef))) ||
      email !== 'verified@tenant-' + clientId.slice(-8) + '.example.invalid') {
    throw new Error('Synthetic OIDC fixture configuration is invalid')
  }
  const callback=disposableProjectRef?'https://'+disposableProjectRef+'.supabase.co/auth/v1/callback':fixtureCallback
  const formDestinations = disposableProjectRef ? callback : callback + ' ' + fixtureAppCallback
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: id(), alg: 'RS256', use: 'sig' }
  const profile = { sub: id(), email, email_verified: true, name: 'Synthetic SecTalk test identity' }
  const requests = new Map(), codes = new Map(), tokens = new Map()
  const paths = { authorize: issuer + '/authorize', token: issuer + '/token', jwks: issuer + '/jwks', userinfo: issuer + '/userinfo' }

  function issueToken(nonce) {
    const iat = Math.floor(now() / 1000)
    const content = encode({ alg: 'RS256', kid: jwk.kid, typ: 'JWT' }) + '.' +
      encode({ ...profile, iss: issuer, aud: clientId, iat, exp: iat + 120, ...(nonce && { nonce }) })
    return content + '.' + sign('RSA-SHA256', Buffer.from(content), privateKey).toString('base64url')
  }

  return createServer(async (request, response) => {
    response.setHeader('Cache-Control', 'no-store')
    response.setHeader('Referrer-Policy', 'no-referrer')
    response.setHeader('X-Content-Type-Options', 'nosniff')
    response.setHeader('X-Robots-Tag', 'noindex, nofollow')
    response.setHeader('Content-Security-Policy', "default-src 'none'; form-action 'self' " + formDestinations + "; frame-ancestors 'none'")
    const json = (status, data) => {
      response.writeHead(status, { 'Content-Type': 'application/json' })
      response.end(JSON.stringify(data))
    }
    const invalid = (error = 'invalid_request') => json(400, { error })
    if (!request.url.startsWith('/') || request.url.startsWith('//')) return invalid()
    const target = new URL(request.url, issuer)
    for (const store of [requests, codes, tokens]) {
      for (const [key, value] of store) if (value.expires <= now()) store.delete(key)
    }

    try {
      if (request.method === 'GET' && target.pathname === '/.well-known/openid-configuration') {
        return json(200, { issuer, authorization_endpoint: paths.authorize, token_endpoint: paths.token,
          jwks_uri: paths.jwks, userinfo_endpoint: paths.userinfo, response_types_supported: ['code'],
          grant_types_supported: ['authorization_code'], subject_types_supported: ['public'],
          scopes_supported: ['openid', 'email', 'profile'], id_token_signing_alg_values_supported: ['RS256'],
          code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'] })
      }
      if (request.method === 'GET' && target.pathname === '/jwks') return json(200, { keys: [jwk] })
      if (request.method === 'GET' && target.pathname === '/authorize') {
        const query = target.searchParams
        const state = one(query, 'state'), nonce = one(query, 'nonce'), challenge = one(query, 'code_challenge')
        if (one(query, 'client_id') !== clientId || one(query, 'redirect_uri') !== callback ||
            one(query, 'response_type') !== 'code' || one(query, 'code_challenge_method') !== 'S256' ||
            !one(query, 'scope')?.split(' ').includes('openid') || !flowStateShape.test(state ?? '') ||
            (query.has('nonce') && !verifierShape.test(nonce ?? '')) || !secretShape.test(challenge ?? '')) return invalid()
        if (requests.size >= 128) return json(429, { error: 'temporarily_unavailable' })
        const ticket = id()
        requests.set(ticket, { state, nonce, challenge, expires: now() + 120_000 })
        response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
        return response.end('<!doctype html><html lang="en"><meta charset="utf-8"><title>SecTalk synthetic identity</title>' +
          '<h1>SecTalk synthetic identity</h1><form method="post" action="/authorize"><input type="hidden" name="ticket" value="' +
          ticket + '"><label>Tester code <input type="password" name="tester_code" required autocomplete="off"></label>' +
          '<button type="submit">Authorize synthetic identity</button></form></html>')
      }
      if (request.method === 'POST' && target.pathname === '/authorize') {
        const form = await formBody(request)
        const ticket = form && one(form, 'ticket'), pending = requests.get(ticket)
        if (!pending || !matches(testerCode, one(form, 'tester_code'))) return json(403, { error: 'access_denied' })
        requests.delete(ticket)
        if (pending.expires <= now()) return json(403, { error: 'access_denied' })
        if (codes.size >= 128) return json(429, { error: 'temporarily_unavailable' })
        const code = id()
        codes.set(code, { ...pending, expires: now() + 60_000 })
        const next = new URL(callback)
        next.searchParams.set('state', pending.state)
        next.searchParams.set('code', code)
        response.writeHead(303, { Location: next.href })
        return response.end()
      }
      if (request.method === 'POST' && target.pathname === '/token') {
        const form = await formBody(request)
        if (!form || one(form, 'grant_type') !== 'authorization_code' || one(form, 'redirect_uri') !== callback) return invalid()
        const basic = request.headers.authorization?.match(/^Basic ([A-Za-z0-9+/]+=*)$/)
        const postId = one(form, 'client_id'), postSecret = one(form, 'client_secret')
        const authorized = request.headers.authorization ? basic && !postId && !postSecret &&
          matches(clientId + ':' + clientSecret, Buffer.from(basic[1], 'base64').toString('utf8')) :
          postId === clientId && matches(clientSecret, postSecret)
        if (!authorized) return json(401, { error: 'invalid_client' })
        const code = one(form, 'code'), saved = codes.get(code), verifier = one(form, 'code_verifier')
        if (!saved) return invalid('invalid_grant')
        codes.delete(code)
        if (saved.expires <= now() || !verifierShape.test(verifier ?? '') ||
            !matches(saved.challenge, digest(verifier))) return invalid('invalid_grant')
        if (tokens.size >= 128) return json(429, { error: 'temporarily_unavailable' })
        const access = id()
        tokens.set(access, { expires: now() + 120_000 })
        return json(200, { access_token: access, token_type: 'Bearer', expires_in: 120, id_token: issueToken(saved.nonce) })
      }
      if (request.method === 'GET' && target.pathname === '/userinfo') {
        const token = request.headers.authorization?.match(/^Bearer ([A-Za-z0-9_-]{43})$/i)?.[1]
        return tokens.has(token) ? json(200, profile) : json(401, { error: 'invalid_token' })
      }
      return json(404, { error: 'not_found' })
    } catch {
      return json(400, { error: 'invalid_request' })
    }
  })
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { SECTALK_OIDC_SANDBOX, SECTALK_OIDC_ISSUER, SECTALK_OIDC_CLIENT_ID, SECTALK_OIDC_CLIENT_SECRET,
    SECTALK_OIDC_TESTER_CODE, SECTALK_OIDC_TEST_EMAIL, SECTALK_OIDC_DISPOSABLE_PROJECT_REF } = process.env
  if (SECTALK_OIDC_SANDBOX !== 'yes') throw new Error('Start the synthetic issuer only in the authorized disposable sandbox')
  createSyntheticOidcIssuer({ issuer: SECTALK_OIDC_ISSUER, clientId: SECTALK_OIDC_CLIENT_ID,
    clientSecret: SECTALK_OIDC_CLIENT_SECRET, testerCode: SECTALK_OIDC_TESTER_CODE, email: SECTALK_OIDC_TEST_EMAIL,
    disposableProjectRef:SECTALK_OIDC_DISPOSABLE_PROJECT_REF })
    .listen(8080, '0.0.0.0')
}
