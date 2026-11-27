import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { totpCode } from './workspace-admin-fixture.mjs'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const project = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(project.origin, 'http://127.0.0.1:57101')
const admin = createClient(project.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
})
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const password = randomUUID() + '!Qa8'
const accounts = []
let browser

function sql(query) {
  return execFileSync('docker', ['exec', '-i', 'supabase_db_v6-preview-atomic-qa', 'psql', '-Xq',
    '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres'], {input: query, windowsHide: true})
}

async function account(operator) {
  const handle = 'authqa_' + randomUUID().slice(0, 16).replaceAll('-', '')
  const email = handle + '@example.invalid'
  const { data, error } = await admin.auth.admin.createUser({email, password, email_confirm: true})
  assert.equal(error, null)
  const id = data.user.id
  assert.match(id, /^[a-f0-9-]{36}$/)
  accounts.push(id)
  if (operator) sql(`insert into public.st_profiles(id, handle, name) values ('${id}', '${handle}', 'QA operator');
    insert into sectalk_private.staff(user_id) values ('${id}');`)
  return email
}

async function signIn(email) {
  const page = await browser.newPage()
  await page.goto(app.href)
  await page.getByLabel('Email', {exact: true}).fill(email)
  await page.getByLabel('Password', {exact: true}).fill(password)
  await page.getByRole('button', {name: 'Sign in', exact: true}).click()
  return page
}

try {
  const [operator, ordinary] = await Promise.all([account(true), account(false)])
  browser = await chromium.launch({executablePath: process.env.SECTALK_TEST_BROWSER})
  const denied = await signIn(ordinary)
  await denied.getByRole('heading', {name: 'Access unavailable'}).waitFor()
  assert.equal(await denied.getByRole('button', {name: 'Set up authenticator'}).count(), 0)
  await denied.close()

  const initial = await signIn(operator)
  await initial.getByRole('button', {name: 'Set up authenticator'}).click()
  const qr = initial.getByRole('img', {name: 'Scan with your authenticator app'})
  await qr.waitFor()
  await initial.waitForFunction(() => [...document.images].some(image =>
    image.alt === 'Scan with your authenticator app' && image.complete && image.naturalWidth > 0))
  const secret = await initial.locator('.mfa-setup code').textContent()
  assert.ok(secret && /^[A-Z2-7]+$/.test(secret))
  const sections = initial.getByRole('group', {name: 'Operator sections'})
  assert.equal(await sections.count(), 0)
  const wrong = await totpCode(secret)
  await initial.getByLabel('Authenticator code').fill(wrong[0] === '0' ? '1' + wrong.slice(1) : '0' + wrong.slice(1))
  await initial.getByRole('button', {name: 'Verify code', exact: true}).click()
  await initial.getByRole('alert').filter({hasText: /invalid or expired/}).waitFor()
  assert.equal(await sections.count(), 0)
  await initial.getByLabel('Authenticator code').fill(await totpCode(secret))
  const overview = initial.waitForResponse(result => new URL(result.url()).pathname.endsWith('/rpc/st_v8_operator_overview'))
  await initial.getByRole('button', {name: 'Verify code', exact: true}).click()
  await sections.getByRole('button', {name: 'Moderation', exact: true}).waitFor()
  assert.equal(await qr.count(), 0)
  const response = await overview
  const snapshot = await response.json()
  assert.equal(response.status(), 200, snapshot.message)
  assert.ok(Number.isInteger(snapshot.directMessages) && snapshot.directMessages >= 0)
  await initial.getByRole('heading', {name:'Direct messages', exact:true}).waitFor()
  const dashboards = initial.getByRole('group', {name:'Overview dashboards'})
  await dashboards.getByRole('button', {name:'Storage', exact:true}).click()
  await initial.getByRole('heading', {name:'Stored object data', exact:true}).waitFor()
  await dashboards.getByRole('button', {name:'Feature coverage', exact:true}).click()
  await initial.getByText('234 of 234 Free-tier features.', {exact:false}).waitFor()
  await initial.getByRole('searchbox', {name:'Find a feature'}).fill('AUTH-01')
  await initial.getByText('1 of 234 Free-tier features.', {exact:false}).waitFor()
  await initial.setViewportSize({width:320,height:740})
  assert.equal(await initial.evaluate(() =>
    document.documentElement.scrollWidth <= document.documentElement.clientWidth), true, 'Overview must fit a 320 px screen')
  await dashboards.getByRole('button', {name:'Safety', exact:true}).click()
  await initial.getByRole('button', {name:'Review reports', exact:true}).click()
  await sections.getByRole('button', {name:'Moderation', exact:true, pressed:true}).waitFor()
  await initial.getByRole('button', {name: 'Sign out', exact: true}).click()
  await initial.getByRole('heading', {name: 'Operator sign-in'}).waitFor()
  await initial.close()

  const again = await signIn(operator)
  await again.getByRole('button', {name: 'Verify code', exact: true}).waitFor()
  assert.equal(await again.getByRole('button', {name: 'Set up authenticator'}).count(), 0)
  assert.equal(await again.getByRole('group', {name: 'Operator sections'}).count(), 0)
  console.log('Passed first-time QR enrollment, operator activity and storage, all 234 inventory entries, mobile layout, and moderation navigation.')
} finally {
  await browser?.close()
  for (const id of accounts) {
    sql(`delete from sectalk_private.staff where user_id='${id}'; delete from auth.users where id='${id}';`)
  }
}
