import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const backend = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(backend.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(backend.href, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const client = createClient(backend.href, process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY, options)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
const fixture = randomUUID().slice(0, 8)
const email = `entitlement-${fixture}@example.invalid`
const password = randomUUID()+'!4x'
let actor

function data(result) {
  if (result.error) throw result.error
  return result.data
}

try {
  const response = await fetch(new URL('/api/billing/catalog', app))
  assert.equal(response.status, 200)
  const catalog = await response.json()
  for (const offer of catalog.plans) {
    assert.equal(offer.entitlements.version, offer.version)
    assert.equal(offer.entitlements.plan, offer.plan)
    assert.ok(offer.entitlements.workspace_limit > 0)
    assert.ok(offer.prices.every(price => !('provider_price' in price)))
  }
  actor = data(await admin.auth.admin.createUser({ email, password, email_confirm: true })).user.id
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: 'offer_'+fixture, p_name: 'Billing limit QA' }))
  data(await admin.rpc('st_v6_sync_catalog_subscription', {
    p_event: 'entitlement_'+fixture, p_user: actor, p_customer: 'cus_ent_'+fixture,
    p_subscription: 'sub_ent_'+fixture, p_provider_price: 'price_local_fixture',
    p_legacy_plan: 'business', p_legacy_cadence: 'monthly', p_status: 'active',
    p_end: new Date(Date.now()+86400000).toISOString(), p_cancel: false,
    p_synced: new Date().toISOString(), p_currency: 'USD', p_amount: null,
  }))

  const page = await browser.newPage()
  await page.goto(app.href)
  await page.getByLabel('Email address', {exact:true}).fill(email)
  await page.getByLabel('Password', {exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation', {name:'SecTalk features'}).getByRole('button',{name:'Billing',exact:true}).click()
  const limits = page.getByRole('list', {name:'Plan limits',exact:true})
  await limits.getByText('Up to 100 members per workspace', {exact:true}).waitFor()
  await limits.getByText('Workspace API access', {exact:true}).waitFor()
  await page.getByText('Terms version 1', {exact:true}).waitFor()
  await page.getByRole('button',{name:'Compare plans',exact:true}).click()
  const free = page.getByRole('article').filter({has:page.getByRole('heading',{name:'Free',exact:true})})
  await free.getByText('Up to 5 members per workspace', {exact:true}).waitFor()
  await page.getByRole('button',{name:'My subscription',exact:true}).click()

  execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-q','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres'],{
    input:`update public.st_v2_subscriptions set status='past_due',period_end=now()-interval '4 days' where user_id='${actor}';`,windowsHide:true,
  })
  await limits.getByText('Up to 5 members per workspace', {exact:true}).waitFor({timeout:18000})
  assert.equal(await limits.getByText('Workspace API access', {exact:true}).count(), 0)
  assert.equal(await page.getByText('Terms version 1', {exact:true}).count(), 0)
  console.log('Passed billing catalog version joins, purchased limits and the signed-in UI reverting to Free after access expired.')
} finally {
  await browser.close()
  if (actor) data(await admin.auth.admin.deleteUser(actor))
}
