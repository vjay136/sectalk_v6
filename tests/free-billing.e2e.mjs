import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const project = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(project.origin, 'http://127.0.0.1:55321')

const clientOptions = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(project.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, clientOptions)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const password = randomUUID() + '!Aa8'
const handle = 'free_' + randomUUID().slice(0, 8)
const email = handle + '@example.invalid'
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
let user

function data(result) {
  assert.equal(result.error, null, result.error?.message)
  return result.data
}

try {
  const catalogResponse = await fetch(new URL('/api/billing/catalog', app))
  assert.equal(catalogResponse.status, 200)
  const catalog = await catalogResponse.json()
  assert.equal(catalog.billingMode, 'free')
  assert.deepEqual(catalog.plans.map(plan => plan.plan), ['free'])
  assert.equal(catalog.checkoutAvailable, false)
  assert.equal(catalog.portalConfigured, false)
  assert.equal(catalog.taxConfigured, false)
  assert.deepEqual(catalog.razorpayOffers, [])

  user = data(await admin.auth.admin.createUser({ email, password, email_confirm: true })).user
  const client = createClient(project.origin, process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY, clientOptions)
  const { session } = data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: 'Free Pilot QA' }))
  assert.equal(data(await client.rpc('st_v7_my_entitlements')).plan, 'free')

  const headers = { Authorization: 'Bearer ' + session.access_token, 'Content-Type': 'application/json' }
  for (const [path, body] of [
    ['/api/billing/action', { action: 'checkout' }],
    ['/api/billing/action', { action: 'razorpay_checkout' }],
    ['/api/billing/action', { action: 'portal' }],
    ['/api/billing/workspace', { action: 'change' }],
    ['/api/billing/workspace?section=adjustments', { action: 'refund' }],
    ['/api/workspaces/trial', { plan: 'professional' }],
    ['/api/billing/renewal-mail', {}],
  ]) {
    const response = await fetch(new URL(path, app), { method: 'POST', headers, body: JSON.stringify(body) })
    assert.equal(response.status, 409, path)
    assert.equal((await response.json()).error, 'SecTalk is free for everyone. Paid billing is paused.')
  }
  const trial = await fetch(new URL('/api/workspaces/trial', app), { headers })
  assert.deepEqual(await trial.json(), { policy: 'unavailable', billingPaused: true })

  for (const width of [1440, 390]) {
    const page = await browser.newPage({ viewport: { width, height: 840 } })
    try {
      await page.goto(new URL('/#account', app).href, { waitUntil: 'domcontentloaded' })
      await page.getByLabel('Email address', { exact: true }).fill(email)
      await page.getByLabel('Password', { exact: true }).fill(password)
      await page.locator('button.submit-auth').click()
      const nav = page.getByRole('navigation', { name: 'SecTalk features' })
      const accept = page.getByRole('button', { name: 'Accept and continue', exact: true })
      await nav.or(accept).first().waitFor()
      if (await accept.isVisible()) {
        await page.getByRole('checkbox', { name: 'I accept the SecTalk Community Rules.' }).check()
        await accept.click()
      }
      if (width === 390) await nav.getByRole('button', { name: 'More', exact: true }).click()
      await nav.getByRole('button', { name: 'Billing', exact: true }).click()
      await page.getByRole('heading', { name: 'Free', exact: true }).waitFor()
      assert.equal(await page.getByRole('button', { name: /checkout|compare plans|billing portal/i }).count(), 0)
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth))
    } finally {
      await page.close()
    }
  }
  console.log('Passed Free entitlements, paused payment endpoints, and desktop and mobile billing screens.')
} finally {
  await browser.close()
  if (user) data(await admin.auth.admin.deleteUser(user.id))
}
