// Run only against disposable v4-auth-qa and a fixture issuer controlled by the QA operator.
// Launch SecTalk with SECTALK_SSO_AUTH_URL=http://127.0.0.1:3563 and the loopback app URL.
// Use local GoTrue v2.198.0 on port 3565 with custom OAuth enabled, API_EXTERNAL_URL=http://127.0.0.1:3563/auth/v1,
// and the exact SecTalk /auth/workspace-sso redirect allowed. Supply the disposable service JWT to the fixture.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { createServer } from 'node:http'
import { createClient } from '@supabase/supabase-js'
import { preflightSyntheticOidcIssuer } from './fixtures/oidc-preflight.mjs'
import { verifyStaffPanel } from './workspace-admin-fixture.mjs'

const project = 'http://127.0.0.1:55321'
const gateway = 'http://127.0.0.1:3563'
const nativeOrigin = 'http://127.0.0.1:3565'
const settings = process.env
const app = URL.parse(settings.SECTALK_STORAGE_TEST_APP ?? '')
const issuer = URL.parse(settings.SECTALK_OIDC_ISSUER ?? '')
const clientId = settings.SECTALK_OIDC_CLIENT_ID, clientSecret = settings.SECTALK_OIDC_CLIENT_SECRET
const testerCode = settings.SECTALK_OIDC_TESTER_CODE, email = settings.SECTALK_OIDC_TEST_EMAIL
const publicKey = settings.SECTALK_STORAGE_TEST_PUBLIC_KEY, serviceKey = settings.SECTALK_STORAGE_TEST_SERVICE_KEY
const nativeAdminKey = settings.SECTALK_OIDC_GATEWAY_ADMIN_JWT
const suffix = /^sectalk-qa-([a-f0-9]{8})$/.exec(clientId ?? '')?.[1]
const domain = 'tenant-' + suffix + '.example.invalid'
const provider = 'custom:sectalk-qa-' + suffix
const secretShape = /^[A-Za-z0-9_-]{43}$/

if (settings.SECTALK_OIDC_DISPOSABLE_QA !== 'yes' || settings.SECTALK_STORAGE_TEST_URL !== project ||
    app?.hostname !== '127.0.0.1' || app.origin !== settings.SECTALK_STORAGE_TEST_APP ||
    issuer?.protocol !== 'https:' || issuer.origin !== settings.SECTALK_OIDC_ISSUER ||
    !/^(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]*$/.test(issuer.hostname) ||
    !suffix || email !== 'verified@' + domain || !secretShape.test(clientSecret ?? '') ||
    !secretShape.test(testerCode ?? '') || testerCode === clientSecret || !publicKey || !serviceKey ||
    !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(nativeAdminKey ?? '')) {
  throw new Error('Use the disposable OIDC browser fixture with matching synthetic issuer settings')
}

const options = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(project, serviceKey, options)
const password = randomUUID() + '1!Q'
const ownerEmail = 'owner-' + suffix + '@example.invalid'
const workspaceName = 'Synthetic OIDC workspace ' + suffix
const protectedNativePaths = new Set(['/authorize', '/callback', '/token'])
const providerEndpoint = nativeOrigin + '/admin/custom-providers'
const providerApi = (method, path = '', data) => fetch(providerEndpoint + path, {
  method, signal: AbortSignal.timeout(12_000), redirect: 'error',
  headers: { Authorization: 'Bearer ' + nativeAdminKey, 'Content-Type': 'application/json' },
  ...(data && { body: JSON.stringify(data) }),
})
const sql = statement => execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-qAt',
  '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres'], {
  input: statement, encoding: 'utf8', windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'], timeout: 20_000,
}).trim()
const data = result => {
  if (result.error) {
    const error = new Error('Disposable Supabase request failed')
    if (typeof result.error.code === 'string' && /^[a-zA-Z0-9_]{1,64}$/.test(result.error.code)) error.code = result.error.code
    throw error
  }
  return result.data
}
const buttons = (page, name) => page.getByRole('button', { name, exact: true })

const proxy = createServer(async (request, response) => {
  try {
    const target = new URL(request.url, gateway)
    const path = target.pathname.slice('/auth/v1'.length)
    if (target.origin !== gateway || !target.pathname.startsWith('/auth/v1/') || !protectedNativePaths.has(path)) {
      response.writeHead(404)
      return response.end()
    }
    const headers = new Headers()
    for (const name of ['authorization', 'apikey', 'content-type', 'cookie', 'origin', 'referer', 'user-agent']) {
      if (typeof request.headers[name] === 'string') headers.set(name, request.headers[name])
    }
    const chunks = []
    let size = 0
    for await (const chunk of request) {
      size += chunk.length
      if (size > 16_384) {
        response.writeHead(413)
        return response.end()
      }
      chunks.push(chunk)
    }
    const result = await fetch(nativeOrigin + path + target.search, { method: request.method, headers, redirect: 'manual',
      signal: AbortSignal.timeout(15_000), body: chunks.length ? Buffer.concat(chunks) : undefined })
    const forwarded = {}
    for (const name of ['location', 'content-type', 'cache-control']) {
      if (result.headers.has(name)) forwarded[name] = result.headers.get(name)
    }
    const cookies = result.headers.getSetCookie()
    if (cookies.length) forwarded['Set-Cookie'] = cookies
    response.writeHead(result.status, forwarded)
    response.end(Buffer.from(await result.arrayBuffer()))
  } catch {
    response.writeHead(503)
    response.end()
  }
})

async function openWorkspaces(page) {
  const workspaces = buttons(page.getByRole('navigation', { name: 'SecTalk features' }), 'Workspaces')
  const rules = page.getByRole('checkbox', { name: 'I accept the SecTalk Community Rules.' })
  const target = await Promise.race([
    workspaces.waitFor().then(() => 'workspaces'),
    rules.waitFor().then(() => 'rules'),
  ])
  if (target === 'rules') {
    await rules.check()
    await buttons(page, 'Accept and continue').click()
  }
  await workspaces.click()
}

let phase = 'approved issuer HTTPS preflight', registered = false, browser, ownerId, workspace
try {
  await preflightSyntheticOidcIssuer({issuer:issuer.origin})
  phase = 'native provider registration'
  const created = await providerApi('POST', '', { provider_type: 'oidc', identifier: provider, name: 'Synthetic SecTalk issuer',
    client_id: clientId, client_secret: clientSecret, issuer: issuer.origin, scopes: ['openid', 'profile', 'email'],
    pkce_enabled: true, skip_nonce_check: false, email_optional: false, enabled: true })
  if (!created.ok) {
    await created.body?.cancel()
    phase += ' (HTTP ' + created.status + ')'
    throw new Error('Native provider registration failed')
  }
  registered = true
  const registration = await created.json()
  assert.ok(registration.identifier === provider && registration.pkce_enabled === true)

  phase = 'synthetic workspace owner registration'
  const owner = data(await admin.auth.admin.createUser({ email: ownerEmail, password, email_confirm: true })).user
  ownerId = owner.id
  assert.match(ownerId, /^[a-f0-9-]{36}$/)
  phase = 'synthetic workspace owner password verification'
  const ownerClient = createClient(project, publicKey, options)
  data(await ownerClient.auth.signInWithPassword({ email: ownerEmail, password }))
  phase = 'synthetic workspace owner profile'
  data(await ownerClient.rpc('st_save_profile', { p_handle: 'oidc_owner_' + suffix, p_name: 'Synthetic owner' }))
  phase = 'synthetic workspace Enterprise entitlement'
  sql("insert into public.st_v2_subscriptions(user_id,plan,status,period_end) values('" + ownerId + "','enterprise','active',now()+interval '1 day');")
  phase = 'synthetic workspace creation'
  workspace = data(await ownerClient.rpc('st_v2_create_workspace', { p_name: workspaceName }))
  assert.match(workspace, /^[a-f0-9-]{36}$/)
  phase = 'synthetic workspace provider-domain approval'
  sql("insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values('" + workspace + "','" + domain + "',now());" +
    "insert into sectalk_private.st_v7_oidc_domain_approvals(domain,identifier) values('" + domain + "','" + provider + "');")

  phase = 'native Auth gateway and workspace settings'
  proxy.listen(3563, '127.0.0.1')
  await once(proxy, 'listening')
  const { chromium } = await import(settings.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
  browser = await chromium.launch({ executablePath: settings.SECTALK_TEST_BROWSER })
  const ownerPage = await browser.newPage()
  const rootUrl = new URL('/#account', app).href
  await ownerPage.goto(rootUrl)
  await ownerPage.getByLabel('Email address', { exact: true }).fill(ownerEmail)
  await ownerPage.getByLabel('Password', { exact: true }).fill(password)
  await ownerPage.locator('button.submit-auth').click()
  await openWorkspaces(ownerPage)
  await buttons(ownerPage, 'Integrations').click()
  await buttons(ownerPage, 'Single sign-on').click()
  const config = ownerPage.getByRole('region', { name: 'Enterprise workspace sign-in' })
  await verifyStaffPanel(config)
  await config.getByRole('combobox', { name: /Verified domain/ }).selectOption(domain)
  await config.getByLabel('Identity provider type').selectOption('oidc')
  await config.getByRole('checkbox', { name: 'Admit new verified domain users as ordinary members' }).check()
  await buttons(config, 'Save workspace sign-in').click()
  await config.getByText('Workspace sign-in configured.', { exact: true }).waitFor()

  phase = 'browser authorization and native PKCE'
  const memberPage = await browser.newPage()
  await memberPage.goto(rootUrl)
  await memberPage.getByText('Sign in with workspace SSO', { exact: true }).click()
  await memberPage.getByLabel('Workspace email domain', { exact: true }).fill(domain)
  phase = 'native authorization redirect'
  await buttons(memberPage, 'Continue with workspace SSO').click()
  await memberPage.waitForURL(url => url.origin === issuer.origin && url.pathname === '/authorize')
  phase = 'synthetic issuer consent form'
  const authorization = new URL(memberPage.url()).searchParams
  const checks = {
    client: authorization.get('client_id') === clientId,
    callback: authorization.get('redirect_uri') === gateway + '/auth/v1/callback',
    response: authorization.get('response_type') === 'code',
    challenge: authorization.get('code_challenge_method') === 'S256' && secretShape.test(authorization.get('code_challenge') ?? ''),
    scope: authorization.get('scope')?.split(' ').includes('openid'),
    state: /^[a-f0-9-]{36}$/.test(authorization.get('state') ?? ''),
  }
  for (const [parameter, matched] of Object.entries(checks)) {
    phase = 'synthetic issuer ' + parameter + ' contract'
    assert.ok(matched)
  }
  phase = 'synthetic issuer consent form'
  await memberPage.getByLabel('Tester code').fill(testerCode)
  phase = 'issuer token exchange and SecTalk callback'
  const [authorized, nativeCallback, completed] = await Promise.all([
    memberPage.waitForResponse(response => response.url() === issuer.origin + '/authorize' &&
      response.request().method() === 'POST'),
    memberPage.waitForResponse(response => {
      const url = new URL(response.url())
      return url.origin === gateway && url.pathname === '/auth/v1/callback'
    }),
    memberPage.waitForResponse(response => response.url() === app.origin + '/api/auth/workspace-sso' &&
      response.request().postDataJSON()?.action === 'complete'),
    buttons(memberPage, 'Authorize synthetic identity').click(),
  ])
  assert.equal(authorized.status(), 303)
  assert.equal(nativeCallback.status(), 302)
  assert.equal(completed.status(), 200)
  await openWorkspaces(memberPage)
  await memberPage.getByRole('heading', { name: workspaceName, exact: true }).waitFor()

  phase = 'workspace membership and receipt revocation'
  const access = await memberPage.evaluate(() => {
    const key = Object.keys(localStorage).find(name => name.endsWith('-auth-token'))
    return JSON.parse(localStorage.getItem(key)).access_token
  })
  const scoped = createClient(project, publicKey, { ...options, global: { headers: { Authorization: 'Bearer ' + access } } })
  const member = data(await scoped.auth.getUser(access)).user
  assert.ok(member.email === email)
  assert.match(member.id, /^[a-f0-9-]{36}$/)
  assert.equal(sql("select role from public.st_v2_members where (workspace_id,user_id)=('" + workspace + "','" + member.id + "');"), 'member')
  assert.equal(data(await scoped.rpc('st_v7_workspace_uses_sso', { p_workspace: workspace })), true)
  assert.equal(data(await ownerClient.rpc('st_v7_workspace_uses_sso', { p_workspace: workspace })), false)
  await buttons(config, 'Disconnect workspace SSO').click()
  await config.getByText('Workspace sign-in removed.', { exact: true }).waitFor()
  assert.equal(data(await scoped.rpc('st_v7_workspace_uses_sso', { p_workspace: workspace })), false)
  console.log('Passed signed native OIDC, PKCE, JIT workspace membership and session receipt revocation.')
} catch (error) {
  process.exitCode = 1
  const code = typeof error?.code === 'string' && /^[a-zA-Z0-9_]{1,64}$/.test(error.code) ? ' (' + error.code + ')' : ''
  console.error('Disposable workspace OIDC verification failed during ' + phase + code + '.')
} finally {
  if (browser) await browser.close().catch(() => { process.exitCode = 1 })
  if (proxy.listening) await new Promise(resolve => proxy.close(resolve))
  if (registered) {
    try {
      const removed = await providerApi('DELETE', '/' + provider)
      await removed.body?.cancel()
      assert.ok(removed.ok)
    } catch {
      console.error('Disposable OIDC provider cleanup failed.')
      process.exitCode = 1
    }
  }
  if (ownerId) {
    try {
      sql("delete from sectalk_private.st_v7_oidc_domain_approvals where domain='" + domain + "' and identifier='" + provider + "';" +
        (workspace ? "delete from public.st_v2_workspaces where id='" + workspace + "';" : '') +
        "delete from auth.users where email in ('" + ownerEmail + "','" + email + "');")
    } catch {
      console.error('Disposable OIDC workspace cleanup failed.')
      process.exitCode = 1
    }
  }
}
