import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHmac, randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const run = randomUUID().slice(0, 8)
const password = randomUUID() + '1!Q'
const tenantName = 'Tenant Operations QA ' + run
const tenant = randomUUID()
const channel = randomUUID()
const post = randomUUID()
const accounts = []
let browser

function data(result) {
  if (result.error) throw result.error
  return result.data
}

function sql(statement) {
  execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-v', 'ON_ERROR_STOP=1',
    '-U', 'postgres', '-d', 'postgres'], { input: statement, windowsHide: true })
}

async function createAccount(role) {
  const handle = 'tenant_' + role + '_' + run
  const email = handle + '@example.org'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  accounts.push(user.id)
  const client = createClient(supabase.origin, publicKey, options)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: 'Tenant operations QA' }))
  return { id: user.id, email, client }
}

function totp(secret) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bits = [...secret.toUpperCase().replace(/=+$/, '')]
    .map(character => alphabet.indexOf(character).toString(2).padStart(5, '0')).join('')
  const key = Buffer.from(bits.match(/.{8}/g).map(part => Number.parseInt(part, 2)))
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)))
  const mac = createHmac('sha1', key).update(counter).digest()
  return String((mac.readUInt32BE(mac.at(-1) & 15) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}

try {
  const owner = await createAccount('owner')
  const operator = await createAccount('ops')
  sql(`
    insert into sectalk_private.st_v6_tenant_operators values ('${operator.id}');
    insert into public.st_v2_workspaces(id,name,owner) values ('${tenant}','${tenantName}','${owner.id}');
    insert into public.st_v2_members(workspace_id,user_id,role) values ('${tenant}','${owner.id}','owner');
    insert into public.st_v2_channels(id,workspace_id,name) values ('${channel}','${tenant}','private-fixture');
    insert into public.st_v2_posts(id,channel_id,sender,body) values ('${post}','${channel}','${owner.id}','Restricted tenant fixture content');
  `)
  assert.equal(data(await owner.client.rpc('st_v6_tenant_operations_status')), 'none')
  assert.equal((await owner.client.rpc('st_v6_tenant_view', { p_workspace: tenant })).error?.code, '42501')
  assert.equal(data(await operator.client.rpc('st_v6_tenant_operations_status')), 'mfa')

  browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
  const page = await browser.newPage()
  await page.goto(app.href)
  await page.getByLabel('Email address', { exact: true }).fill(operator.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation', { name: 'SecTalk features' }).getByRole('button', { name: 'Safety', exact: true }).click()
  await page.getByRole('button', { name: 'Tenant operations', exact: true }).click()
  await page.getByRole('heading', { name: 'Verify staff access' }).waitFor()
  assert.equal(await page.getByRole('button', { name: 'Staff console', exact: true }).count(), 0)
  await page.getByRole('button', { name: 'Set up authenticator' }).click()
  const secret = (await page.locator('.mfa-setup code').textContent()).trim()
  await page.getByLabel('Authenticator code', { exact: true }).fill(totp(secret))
  await page.getByRole('button', { name: 'Verify access', exact: true }).click()
  await page.getByLabel('Workspace ID or start of name').fill(tenant)
  await page.getByRole('button', { name: 'Search workspaces' }).click()
  const lookup = page.waitForResponse(response => response.url().includes('/rpc/st_v6_tenant_view'))
  await page.getByRole('button', { name: new RegExp(tenantName) }).click()
  const response = await lookup
  assert.equal(response.status(), 200)
  await page.getByRole('heading', { name: tenantName }).waitFor()
  const detail = await response.json()
  assert.deepEqual(Object.keys(detail[0] ?? detail).sort(), ['created_at', 'id', 'member_count', 'name'])
  assert.equal((detail[0] ?? detail).member_count, 1)

  const headers = { apikey: publicKey, authorization: (await response.request().allHeaders()).authorization }
  const content = await fetch(new URL('/rest/v1/st_v2_posts?select=body&id=eq.' + post, supabase), { headers })
  assert.equal(content.status, 200)
  assert.deepEqual(await content.json(), [])
  assert.equal(await page.getByText('Restricted tenant fixture content').count(), 0)
  console.log('Tenant operations browser passed with real TOTP, metadata-only RPC output, and tenant-content isolation.')
} finally {
  await browser?.close()
  sql(`delete from public.st_v2_workspaces where id='${tenant}';
    delete from sectalk_private.st_v6_tenant_access_log where workspace_id='${tenant}'
      ${accounts.length ? "or actor in ('" + accounts.join("','") + "')" : ''};`)
  for (const account of accounts) data(await admin.auth.admin.deleteUser(account))
}
