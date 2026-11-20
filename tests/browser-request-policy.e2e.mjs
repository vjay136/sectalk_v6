import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { request as requestHttp } from 'node:http'
import { createServer } from 'node:https'
import { once } from 'node:events'

const backend = new URL(process.env.SECTALK_STORAGE_TEST_APP)
assert.equal(backend.hostname, '127.0.0.1')
const integrationOrigin = 'https://integrations.example.test'
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE ?? 'playwright')

const proxy = createServer({
  key: readFileSync(process.env.SECTALK_TEST_TLS_KEY), cert: readFileSync(process.env.SECTALK_TEST_TLS_CERT),
}, (request, response) => {
  const probe = request.url === '/?probe=security-headers'
  const upstream = requestHttp({ hostname: backend.hostname, port: backend.port, method: request.method,
    path: request.url, headers: { ...request.headers, 'x-forwarded-proto': 'https', ...(probe ? { 'accept-encoding': 'identity' } : {}) } }, result => {
    if (probe) {
      let html = ''
      result.setEncoding('utf8')
      result.on('data', chunk => { html += chunk })
      result.on('end', () => {
        delete result.headers['content-length']
        response.writeHead(result.statusCode, result.headers)
        response.end(html.replace('</head>', '<script>window.secTalkSyntheticScriptRan = true</script></head>'))
      })
      return
    }
    response.writeHead(result.statusCode, result.headers)
    result.pipe(response)
  })
  upstream.on('error', () => response.writeHead(502).end())
  request.pipe(upstream)
})
proxy.listen(0, '127.0.0.1')
await once(proxy, 'listening')

const productionOrigin = new URL(`https://127.0.0.1:${proxy.address().port}`)
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
try {
  const context = await browser.newContext({ ignoreHTTPSErrors: true })
  await context.addInitScript(() => {
    window.secTalkPolicyEvents = []
    window.addEventListener('securitypolicyviolation', event => {
      window.secTalkPolicyEvents.push({ directive: event.effectiveDirective, blocked: event.blockedURI })
    })
  })
  const page = await context.newPage()
  const response = await page.goto(new URL('/?probe=security-headers', productionOrigin).href)
  assert.equal(response.status(), 200)
  const policy = response.headers()['content-security-policy']
  const scriptSource = policy.split(';').find(directive => directive.trim().startsWith('script-src '))
  const nonce = scriptSource.match(/'nonce-([A-Za-z+/0-9=]+)'/)[1]
  assert.match(scriptSource, /'strict-dynamic'/)
  assert.doesNotMatch(scriptSource, /'unsafe-inline'|'unsafe-eval'/)
  assert.match(policy, /frame-ancestors 'none'/)
  assert.match(response.headers()['cache-control'], /no-store/)
  assert.match(response.headers()['strict-transport-security'], /max-age=31536000/)
  assert.equal(response.headers()['x-content-type-options'], 'nosniff')
  assert.equal(response.headers()['referrer-policy'], 'no-referrer')
  assert.ok(await page.locator('script').evaluateAll((scripts, expected) => scripts.some(script => script.nonce === expected), nonce))

  await page.waitForFunction(() => window.secTalkPolicyEvents.some(event =>
    event.directive === 'script-src-elem' && event.blocked === 'inline'))
  assert.equal(await page.evaluate(() => window.secTalkSyntheticScriptRan), undefined)
  assert.equal(await page.evaluate(async () => {
    const audio = new AudioContext()
    try {
      await audio.audioWorklet.addModule('/voice-note-pcm.js')
      const capture = new AudioWorkletNode(audio, 'voice-note-pcm')
      return capture.numberOfInputs
    } finally { await audio.close() }
  }), 1)

  const changed = page.waitForResponse(result => result.url().endsWith('/api/preferences/language'))
  await page.getByLabel('Language').selectOption('ar')
  const saved = await changed
  assert.equal(saved.status(), 204)
  const cookie = (await context.cookies()).find(entry => entry.name === '__Host-sectalk_locale')
  assert.equal(cookie.value, 'ar')
  assert.equal(cookie.path, '/')
  assert.equal(cookie.httpOnly, true)
  assert.equal(cookie.secure, true)
  assert.equal(cookie.sameSite, 'Lax')
  assert.doesNotMatch(await page.evaluate(() => document.cookie), /sectalk_locale/)
  const reloaded = await page.reload()
  assert.notEqual(reloaded.headers()['content-security-policy'], policy)
  assert.equal(await page.locator('html').getAttribute('dir'), 'rtl')

  const denied = await context.request.post(new URL('/api/preferences/language', productionOrigin).href, {
    headers: { Origin: 'https://untrusted.example.test' }, data: { locale: 'en' },
  })
  assert.equal(denied.status(), 403)
  assert.equal(denied.headers()['access-control-allow-origin'], undefined)
  assert.equal((await context.cookies()).find(entry => entry.name === cookie.name).value, 'ar')
  const deniedNoOrigin = await context.request.post(new URL('/api/auth/sign-in', productionOrigin).href, {
    headers: { 'Sec-Fetch-Site': 'cross-site' }, data: {},
  })
  assert.equal(deniedNoOrigin.status(), 403)

  const read = new URL('/api/v1/rooms', productionOrigin).href
  const preflight = { Origin: integrationOrigin, 'Access-Control-Request-Method': 'GET',
    'Access-Control-Request-Headers': 'authorization' }
  const allowed = await context.request.fetch(read, { method: 'OPTIONS', headers: preflight })
  assert.equal(allowed.status(), 204)
  assert.equal(allowed.headers()['access-control-allow-origin'], integrationOrigin)
  assert.equal(allowed.headers()['access-control-allow-credentials'], undefined)
  for (const headers of [{ ...preflight, Origin: 'https://untrusted.example.test' },
    { ...preflight, 'Access-Control-Request-Method': 'POST' },
    { ...preflight, 'Access-Control-Request-Headers': 'authorization,x-other' }]) {
    const blocked = await context.request.fetch(read, { method: 'OPTIONS', headers })
    assert.equal(blocked.status(), 403)
    assert.equal(blocked.headers()['access-control-allow-origin'], undefined)
  }
  const unauthorized = await context.request.get(read, { headers: { Origin: integrationOrigin } })
  assert.equal(unauthorized.status(), 401)
  assert.equal(unauthorized.headers()['access-control-allow-origin'], integrationOrigin)

  const meeting = await context.request.get(new URL('/meeting-guest', productionOrigin).href)
  assert.match(meeting.headers()['content-security-policy'], /frame-src https:\/\/challenges.cloudflare.com/)
  assert.match(meeting.headers()['permissions-policy'], /display-capture=\(\)/)
  console.log('Verified fresh CSP nonces, browser enforcement and hydration, HTTPS preference cookies, request-origin checks, and scoped integration read preflights.')
} finally {
  await browser.close()
  proxy.close()
}
