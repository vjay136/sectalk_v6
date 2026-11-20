import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto'
import { createServer } from 'node:http'
import { createClient } from '@supabase/supabase-js'
import { fixtureAuthenticator } from './workspace-admin-fixture.mjs'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const dbUrl = new URL(process.env.SECTALK_STORAGE_TEST_URL)
const receiver = new URL(process.env.SECTALK_TEST_WEBHOOK_ORIGIN)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(receiver.hostname, '127.0.0.1')
assert.equal(receiver.protocol, 'http:')
assert.equal(dbUrl.origin, 'http://127.0.0.1:55321')
const auth = { persistSession: false, autoRefreshToken: false }
const admin = createClient(dbUrl.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, { auth })
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const drainSecret = process.env.SECTALK_WEBHOOK_DRAIN_SECRET
assert.ok(drainSecret?.length >= 32)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
const accounts = []
const workspaces = []
const requests = []
const sink = createServer((request, response) => {
  let body = ''
  request.setEncoding('utf8').on('data', chunk => { body += chunk }).on('end', () => {
    requests.push({ body, headers: request.headers, path: request.url })
    response.writeHead(requests.length === 1 ? 503 : 204).end()
  })
})
await new Promise(resolve => sink.listen(Number(receiver.port), receiver.hostname, resolve))
const suffix = randomUUID().slice(0, 8)
const password = randomUUID() + '1!Q'
function data(result) {
  assert.equal(result.error, null, result.error?.message)
  return result.data
}
function sql(statement) {
  execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1',
    '-U', 'postgres', '-d', 'postgres'], { input: statement, windowsHide: true })
}
function code(secret) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bits = [...secret.replace(/=+$/, '')].map(letter => alphabet.indexOf(letter).toString(2).padStart(5, '0')).join('')
  const key = Buffer.from(bits.match(/.{8}/g).map(group => parseInt(group, 2)))
  const now = Buffer.alloc(8)
  now.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)))
  const digest = createHmac('sha1', key).update(now).digest()
  return String((digest.readUInt32BE(digest.at(-1) & 15) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}
async function user(label, plan) {
  const handle = 'integ_' + label + '_' + suffix
  const email = handle + '@example.invalid'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  accounts.push(user.id)
  const client = createClient(dbUrl.origin, publicKey, { auth })
  const { session } = data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: 'Integration ' + label }))
  if (plan) data(await admin.rpc('st_v2_sync_billing', {
    p_event: 'integration_' + label + '_' + suffix, p_user: user.id, p_customer: 'integration_cus_' + label + '_' + suffix,
    p_subscription: 'integration_sub_' + label + '_' + suffix, p_plan: plan, p_status: 'active', p_cancel: false,
    p_end: new Date(Date.now() + 86_400_000).toISOString(), p_synced: new Date().toISOString(),
  }))
  const name = 'API workspace ' + label + ' ' + suffix
  const workspace = data(await client.rpc('st_v2_create_workspace', { p_name: name }))
  workspaces.push(workspace)
  return { id: user.id, email, client, session, workspace, name }
}
async function room(person, name, visibility) {
  const id = randomUUID()
  data(await person.client.rpc('st_v6_room_create', {
    p_id: id, p_workspace: person.workspace, p_name: name, p_kind: visibility, p_template: 'blank',
  }))
  return id
}
const button = (scope, name) => scope.getByRole('button', { name, exact: true })
const drain = () => fetch(new URL('/api/integrations/webhooks/drain', app), { method: 'POST', headers: { Authorization: 'Bearer ' + drainSecret } })
const api = (resource, key) => fetch(new URL('/api/v1/' + resource, app), { headers: key ? { Authorization: 'Bearer ' + key } : {} })

try {
  const [owner, outsider, delegate] = await Promise.all([user('team', 'business'), user('free'), user('delegate')])
  sql(`insert into public.st_v2_members(workspace_id,user_id,role) values('${owner.workspace}','${delegate.id}','admin');`)
  const privateRoom = await room(owner, 'Sensitive fixture', 'private')
  const foreignRoom = await room(outsider, 'Foreign fixture', 'public')
  const ownRoom = await room(owner, 'Discoverable fixture', 'public')
  const anotherRoom = await room(owner, 'Discoverable page two', 'public')
  assert.equal((await outsider.client.rpc('st_v6_integration_access', { p_workspace: outsider.workspace })).data, 'upgrade')
  assert.equal((await outsider.client.rpc('st_v6_integration_key_list', { p_workspace: owner.workspace })).error?.code, '42501')
  assert.equal((await api('workspace')).status, 401)
  async function assertDenied(actor, token) {
    const workspace = { p_workspace: owner.workspace }
    for (const rpc of ['st_v7_workspace_sso_settings','st_v8_scim_settings']) {
      assert.equal(data(await actor.client.rpc(rpc,workspace)).access,'none')
    }
    for (const category of ['keys','webhooks']) {
      const denied = await fetch(new URL('/api/integrations/'+category,app),{
        method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},
        body:JSON.stringify({workspace:owner.workspace,action:'revoke',key:randomUUID(),endpoint:randomUUID()}),
      })
      assert.equal(denied.status,403)
    }
  }
  await assertDenied(outsider,outsider.session.access_token)

  const adminPage = await browser.newPage()
  await adminPage.goto(new URL('/#account',app).href,{waitUntil:'domcontentloaded'})
  await adminPage.getByLabel('Email address',{exact:true}).fill(delegate.email)
  await adminPage.getByLabel('Password',{exact:true}).fill(password)
  await adminPage.locator('button.submit-auth').click()
  await button(adminPage.getByRole('navigation',{name:'SecTalk features'}),'Workspaces').click()
  await adminPage.getByRole('combobox',{name:/Active workspace/}).selectOption(owner.workspace)
  await adminPage.getByRole('heading',{name:owner.name,exact:true}).waitFor()
  assert.equal(await button(adminPage,'Integrations').count(),0)
  await fixtureAuthenticator(delegate.client)
  const assuredAdmin = data(await delegate.client.auth.getSession()).session
  await assertDenied(delegate,assuredAdmin.access_token)

  const page = await browser.newPage()
  await page.goto(new URL('/#account', app).href, { waitUntil: 'domcontentloaded', timeout: 90000 })
  await page.getByLabel('Email address', { exact: true }).fill(owner.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await button(page.getByRole('navigation', { name: 'SecTalk features' }), 'Workspaces').click()
  await button(page, 'Integrations').click()
  await page.getByRole('heading', { name: 'Verify staff access', exact: true }).waitFor()
  await button(page, 'Set up authenticator').click()
  await page.getByLabel('Authenticator code').fill(code((await page.locator('.mfa-setup code').textContent()).trim()))
  await button(page, 'Verify access').click()
  const area = page.getByRole('region', { name: 'Workspace integrations' })
  await area.getByLabel('Label', { exact: true }).waitFor()
  await button(area,'Single sign-on').click()
  await area.getByText('Enterprise SSO requires an Enterprise workspace.',{exact:true}).waitFor()
  await button(area,'SCIM').click()
  await area.getByText('An Enterprise workspace is required to issue a provisioning token.',{exact:true}).waitFor()
  assert.equal(await button(area,'Create provisioning token').count(),0)
  await button(area,'API keys').click()
  await area.getByLabel('Label', { exact: true }).fill('Automation fixture')
  await area.getByLabel('Read discoverable rooms').check()
  const generated = page.waitForResponse(response => response.url().endsWith('/api/integrations/keys') && response.status() === 201)
  await button(area, 'Create API key').click()
  const keyResponse = await generated
  const { id: keyId, key } = await keyResponse.json()
  assert.equal(keyResponse.headers()['cache-control'], 'private, no-store')
  const ownerAuthorization = (await keyResponse.request().allHeaders()).authorization
  await area.getByText(key, { exact: true }).waitFor()
  assert.equal((await (await api('workspace', key)).json()).data.id, owner.workspace)
  const visible = await (await api('rooms', key)).json()
  assert.ok(visible.data.some(row => row.id === ownRoom))
  assert.ok(!visible.data.some(row => row.id === privateRoom || row.id === foreignRoom))
  const first = await (await api('rooms?limit=1', key)).json()
  const second = await (await api('rooms?limit=1&after=' + first.next_cursor, key)).json()
  assert.deepEqual([...first.data, ...second.data].map(row => row.id).sort(), [ownRoom, anotherRoom].sort())
  assert.equal(second.next_cursor, null)
  assert.equal((await api('rooms?limit=101', key)).status, 400)
  sql(`insert into sectalk_private.st_v6_api_rate(key_id,minute,requests)
    values('${keyId}',date_trunc('minute',statement_timestamp()),120)
    on conflict(key_id,minute) do update set requests=120;`)
  const quota = await api('rooms', key)
  assert.equal(quota.status, 429)
  assert.equal(quota.headers.get('retry-after'), '60')
  await button(area, 'Hide credential').click()
  assert.equal(await area.getByText(key, { exact: true }).count(), 0)
  await button(area, 'Revoke API key').click()
  await button(area, 'Confirm revocation').click()
  await area.getByText('Credential revoked.', { exact: true }).waitFor()
  assert.equal((await api('workspace', key)).status, 401)

  const invalid = await fetch(new URL('/api/integrations/webhooks', app), {
    method: 'POST', headers: { Authorization: ownerAuthorization, 'Content-Type': 'application/json' },
    body: JSON.stringify({ workspace: owner.workspace, action: 'create', label: 'Disallowed loopback',
      destination: 'http://127.0.0.1:1/blocked', topics: ['room.created'] }),
  })
  assert.equal(invalid.status, 400)
  await button(area, 'Outbound webhooks').click()
  await area.getByLabel('Label', { exact: true }).fill('Webhook fixture')
  await area.getByLabel('Webhook endpoint URL').fill(new URL('/event', receiver).href)
  const registered = page.waitForResponse(response => response.url().endsWith('/api/integrations/webhooks') && response.status() === 201)
  await button(area, 'Register webhook').click()
  const hook = await (await registered).json()
  assert.match(hook.secret, /^whsec_/)
  await area.getByText(hook.secret, { exact: true }).waitFor()
  const triggeredRoom = await room(owner, 'Webhook visible fixture', 'public')
  await room(owner, 'Webhook private fixture', 'private')
  await room(outsider, 'Webhook foreign fixture', 'public')

  assert.equal((await drain()).status, 200)
  assert.equal(requests.length, 1)
  assert.equal((await drain()).status, 200)
  assert.equal(requests.length, 1, 'Backoff should prevent immediate redelivery')
  sql(`update sectalk_private.st_v6_webhook_jobs set next_attempt=now() where endpoint_id='${hook.id}';`)
  const retry = await drain()
  assert.equal(retry.status, 200)
  assert.equal(requests.length, 2)
  assert.equal(requests[0].body, requests[1].body)
  for (const request of requests) {
    const id = request.headers['webhook-id']
    assert.equal(request.path, '/event')
    assert.equal(id, requests[0].headers['webhook-id'])
    const signature = createHmac('sha256', Buffer.from(hook.secret.slice(6), 'base64'))
      .update(id + '.' + request.headers['webhook-timestamp'] + '.' + request.body).digest()
    assert.ok(timingSafeEqual(signature, Buffer.from(request.headers['webhook-signature'].slice(3), 'base64')))
    assert.deepEqual(JSON.parse(request.body).data, { workspace_id: owner.workspace, room_id: triggeredRoom })
  }
  await area.getByText('Recent deliveries', { exact: true }).click()
  await area.getByText(/room.created · sent · 2 attempts · HTTP 204/).waitFor({ timeout: 25000 })
  await button(area, 'Revoke webhook').click()
  await button(area, 'Confirm revocation').click()
  await area.getByText('Credential revoked.', { exact: true }).waitFor()
  await room(owner, 'After revoked fixture', 'public')
  assert.equal((await drain()).status, 200)
  assert.equal(requests.length, 2)
  console.log('Passed authenticated API credentials, tenant boundaries, signed webhook bytes, retry, delivery log and revocation.')
} finally {
  await browser.close()
  sink.close()
  for (const id of workspaces) sql(`delete from public.st_v2_workspaces where id='${id}';`)
  for (const id of accounts) data(await admin.auth.admin.deleteUser(id))
}
