import assert from 'node:assert/strict'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
assert.equal(app.hostname, '127.0.0.1')
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })

try {
  const page = await browser.newPage({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true })
  const catalog = await fetch(new URL('/api/billing/catalog', app)).then(response => response.json())
  assert.ok(Array.isArray(catalog.plans))
  await page.goto(app.href)
  await page.getByRole('link', { name: 'Overview', exact: true }).click()
  await page.getByRole('heading', { name: 'Conversations with stronger safety controls.', exact: true }).waitFor()
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth))
  const navigation = page.getByRole('navigation', { name: 'Public pages', exact: true })
  await navigation.getByRole('link', { name: 'Pricing', exact: true }).click()
  await page.getByRole('heading', { name: 'SecTalk pricing', exact: true }).waitFor()
  for (const plan of catalog.plans) await page.getByRole('heading', { name: plan.title, exact: true }).waitFor()
  await page.getByLabel('Billing interval').selectOption('annual')
  await page.getByRole('button', { name: 'Show prices', exact: true }).click()
  await page.waitForURL(url => url.searchParams.get('cadence') === 'annual')
  await navigation.getByRole('link', { name: 'Security', exact: true }).click()
  await page.getByRole('heading', { name: 'Security and trust', exact: true }).waitFor()
  await page.getByRole('link', { name: 'View service status', exact: true }).click()
  await page.getByRole('heading', { name: 'SecTalk service status', exact: true }).waitFor()
  await page.goto(new URL('/about', app).href)
  await navigation.getByRole('link', { name: 'Docs', exact: true }).click()
  await page.getByRole('link', { name: 'Create or recover an account', exact: true }).click()
  await page.waitForURL(url => url.hash === '#account')
  const legal = page.getByRole('navigation', { name: 'Legal and support', exact: true })
  for (const [link, heading] of [['Terms', 'Terms of service'], ['Privacy', 'Privacy notice'], ['DPA template', 'Data processing addendum template']]) {
    await legal.getByRole('link', { name: link, exact: true }).click()
    await page.getByRole('heading', { name: heading, exact: true }).waitFor()
  }
  assert.equal((await fetch(new URL('/legal/unknown', app))).status, 404)
  await navigation.getByRole('link', { name: 'Overview', exact: true }).click()
  await page.getByRole('link', { name: 'Create an account', exact: true }).click()
  await page.getByLabel('Confirm password', { exact: true }).waitFor()
  assert.equal(await page.locator('input[autocomplete="new-password"]').count(), 2)
  console.log('Passed public mobile navigation, live pricing, interval selection, trust, status, guides, legal pages and signup entry.')
} finally {
  await browser.close()
}
