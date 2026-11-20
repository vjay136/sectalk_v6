import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHmac, randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const api = path => new URL('/api/billing/' + path, app)
const auth = { persistSession: false, autoRefreshToken: false }
const admin = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, { auth })
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
const suffix = randomUUID().replaceAll('-', '').slice(0, 10)
const title = 'Pro ' + suffix
const olderTitle = 'Original Pro ' + suffix
const password = randomUUID() + '1!Q'
const fixtureSecret = process.env.SECTALK_BILLING_TEST_WEBHOOK_SECRET
assert.ok(fixtureSecret?.startsWith('whsec_local_fixture_'))
const priceId = 'price_sectalk_catalog_' + suffix
const users = []
let previousVersion, currentVersion

function data(result) {
  assert.equal(result.error, null, result.error?.message)
  return result.data
}

async function createUser(label) {
  const handle = 'billing_' + label + '_' + suffix
  const email = handle + '@example.invalid'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  users.push(user.id)
  const client = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY, { auth })
  const { session } = data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: 'Catalog ' + label }))
  return { user, email, client, session }
}

async function openBilling(person) {
  const page = await browser.newPage()
  await page.goto(new URL('/#account', app).href)
  await page.getByLabel('Email address', { exact: true }).fill(person.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation', { name: 'SecTalk features' }).getByRole('button', { name: 'Billing', exact: true }).click()
  await page.getByRole('heading', { name: 'Billing', exact: true }).waitFor()
  return page
}

function publish(activeFrom, name, prices) {
  return admin.rpc('st_v6_publish_plan', {
    p_plan: 'professional', p_title: name, p_description: 'Isolated plan fixture',
    p_visible: true, p_active_from: new Date(activeFrom).toISOString(), p_prices: prices,
  }).then(data)
}

function fixtureSQL(sql) {
  execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres'],
    { input: sql, encoding: 'utf8' })
}

try {
  const [subscriber, free] = await Promise.all([createUser('old'), createUser('free')])
  previousVersion = await publish(Date.now() - 30_000, olderTitle, [
    { cadence: 'monthly', currency: 'EUR', amount: 975, provider_price: priceId + '_old' },
  ])
  const providerSubscription = 'sub_sectalk_' + suffix
  const customer = 'cus_sectalk_' + suffix
  data(await admin.rpc('st_v6_sync_catalog_subscription', {
    p_event: 'evt_sectalk_initial_' + suffix, p_user: subscriber.user.id, p_customer: customer,
    p_subscription: providerSubscription, p_provider_price: priceId + '_old', p_legacy_plan: null, p_legacy_cadence: null,
    p_status: 'active', p_end: new Date(Date.now() + 86_400_000).toISOString(), p_cancel: false,
    p_synced: new Date(Date.now() - 5000).toISOString(), p_currency: 'EUR', p_amount: 975,
  }))
  currentVersion = await publish(Date.now() - 1000, title, [
    { cadence: 'monthly', currency: 'USD', amount: 1200, provider_price: priceId + '_usd' },
    { cadence: 'monthly', currency: 'EUR', amount: 1100, provider_price: priceId + '_eur' },
    { cadence: 'annual', currency: 'EUR', amount: 12000, provider_price: priceId + '_annual' },
  ])

  const publicResponse = await fetch(api('catalog'))
  assert.equal(publicResponse.status, 200)
  assert.equal(publicResponse.headers.get('cache-control'), 'no-store')
  const catalogJson = await publicResponse.text()
  assert.ok(!catalogJson.includes(priceId))
  assert.deepEqual(JSON.parse(catalogJson).plans.map(plan => plan.title), ['Free', title, 'Team', 'Enterprise'])
  assert.equal((await free.client.rpc('st_v6_my_plan_title')).data, null)

  const checkout = (token, selection) => fetch(api('action'), {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) },
    body: JSON.stringify({ action: 'checkout', plan: 'professional', cadence: 'monthly', currency: 'EUR', ...selection }),
  })
  assert.equal((await checkout(null, { version: currentVersion })).status, 401)
  assert.equal((await checkout(free.session.access_token, { version: previousVersion })).status, 422)
  assert.equal((await checkout(free.session.access_token, { version: currentVersion, currency: 'XXX' })).status, 400)
  assert.equal((await checkout(subscriber.session.access_token, { version: currentVersion })).status, 409)

  const [paidPage, freePage] = await Promise.all([openBilling(subscriber), openBilling(free)])
  await paidPage.getByRole('heading', { name: olderTitle }).waitFor()
  await paidPage.getByText('Terms version ' + previousVersion + ' · Grandfathered', { exact: true }).waitFor()
  await paidPage.getByText(/EUR\s+9[.,]75 per month/).waitFor()
  await freePage.getByRole('button', { name: 'Compare plans', exact: true }).click()
  const pro = freePage.getByRole('article').filter({ has: freePage.getByRole('heading', { name: title, exact: true }) })
  await pro.getByText(/USD\s+12[.,]00 per month/).waitFor()
  await freePage.getByLabel('Currency').selectOption('EUR')
  await pro.getByText(/EUR\s+11[.,]00 per month/).waitFor()
  await freePage.getByRole('button', { name: 'Annual', exact: true }).click()
  await pro.getByText(/EUR\s+120[.,]00 per year/).waitFor()
  assert.ok(await pro.getByRole('button', { name: 'Continue to checkout' }).isEnabled())
  await freePage.getByLabel('Currency').selectOption('USD')
  assert.ok(await pro.getByRole('button', { name: 'Checkout unavailable' }).isDisabled())

  const timestamp = Math.floor(Date.now() / 1000)
  const body = JSON.stringify({ id: 'evt_sectalk_cancel_' + suffix, type: 'customer.subscription.deleted', created: timestamp, data: { object: {
    id: providerSubscription, customer, metadata: { sectalk_user: subscriber.user.id }, status: 'canceled',
    cancel_at_period_end: false, items: { data: [{ current_period_end: timestamp + 60,
      price: { id: priceId + '_old', currency: 'eur', unit_amount: 975 } }] },
  } } })
  const signature = createHmac('sha256', fixtureSecret).update(timestamp + '.' + body).digest('hex')
  const webhook = value => fetch(api('webhook'), { method: 'POST', headers: { 'Stripe-Signature': 't=' + timestamp + ',v1=' + value }, body })
  assert.equal((await webhook('invalid')).status, 400)
  assert.equal((await webhook(signature)).status, 204)
  assert.equal((await webhook(signature)).status, 204)
  const persisted = data(await subscriber.client.from('st_v2_subscriptions').select('catalog_version,billing_amount,status').single())
  assert.deepEqual(persisted, { catalog_version: previousVersion, billing_amount: 975, status: 'canceled' })
  await paidPage.getByRole('heading', { name: 'Free', exact: true }).waitFor()
  console.log('Passed versioned plan API, currency and cadence controls, grandfathered terms, scope, and signed local webhook.')
} finally {
  await browser.close()
  for (const id of users) {
    const result = await admin.auth.admin.deleteUser(id)
    assert.equal(result.error, null, result.error?.message)
  }
  const revisions = [previousVersion, currentVersion].filter(Number.isSafeInteger)
  if (revisions.length) {
    fixtureSQL(`begin;
      delete from sectalk_private.st_v6_plan_prices where provider_price like '${priceId}%';
      delete from sectalk_private.st_v6_plan_versions where plan='professional' and version in (${revisions.join(',')})
        and title in ('${title}','${olderTitle}');
      delete from sectalk_private.st_v2_billing_events where event_id in ('evt_sectalk_initial_${suffix}','evt_sectalk_cancel_${suffix}');
      commit;`)
  }
}
