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
  return {email, id}
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
  const denied = await signIn(ordinary.email)
  await denied.getByRole('heading', {name: 'Access unavailable'}).waitFor()
  assert.equal(await denied.getByRole('button', {name: 'Set up authenticator'}).count(), 0)
  await denied.close()

  const initial = await signIn(operator.email)
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
  await dashboards.getByRole('button', {name:'Product usage', exact:true}).click()
  await initial.getByRole('heading', {name:'Product usage', exact:true}).waitFor()
  await dashboards.getByRole('button', {name:'Safety', exact:true}).click()
  await initial.getByRole('button', {name:'Preview Be Safe', exact:true}).click()
  await initial.getByRole('region', {name:'Be Safe lookup'}).getByLabel('Exact message text').waitFor()
  assert.equal(await sections.getByRole('button', {name:'Abuse blocklists', exact:true}).count(), 0)
  assert.equal(await sections.getByRole('button', {name:'Detection rules', exact:true}).count(), 0)
  assert.equal(await sections.getByRole('button', {name:'Incidents', exact:true}).count(), 0)
  sql(`insert into sectalk_private.st_v7_abuse_blocklist_operators(user_id) values ('${operator.id}');
    insert into sectalk_private.st_v7_detection_operators(user_id) values ('${operator.id}');
    insert into sectalk_private.st_v6_incident_responders(user_id,role) values ('${operator.id}','lead');`)
  const blocklist = initial.waitForResponse(result => new URL(result.url()).pathname.endsWith('/rpc/st_v7_abuse_blocks'))
  await sections.getByRole('button', {name:'Abuse blocklists', exact:true}).click()
  await initial.getByRole('region', {name:'Global abuse blocklists'}).getByRole('button', {name:'Apply filters'}).waitFor()
  assert.ok((await blocklist).ok())
  const rules = initial.waitForResponse(result => new URL(result.url()).pathname.endsWith('/rpc/st_v7_detection_rules'))
  await sections.getByRole('button', {name:'Detection rules', exact:true}).click()
  await initial.getByRole('region', {name:'Detection rules'}).waitFor()
  assert.ok((await rules).ok())
  const incidents = initial.waitForResponse(result => new URL(result.url()).pathname.endsWith('/rpc/st_v6_incident_dashboard'))
  await sections.getByRole('button', {name:'Incidents', exact:true}).click()
  await initial.getByRole('region', {name:'Security incidents'}).getByText('Create an incident', {exact:true}).waitFor()
  assert.ok((await incidents).ok())
  await sections.getByRole('button', {name:'Overview', exact:true}).click()
  await dashboards.getByRole('button', {name:'Safety', exact:true}).click()
  await initial.getByRole('button', {name:'Review reports', exact:true}).click()
  await sections.getByRole('button', {name:'Moderation', exact:true, pressed:true}).waitFor()
  if (process.env.SECTALK_TAB_STRESS === '1') {
    const available = await sections.getByRole('button').allTextContents()
    assert.ok(available.length >= 6)
    let visits = 0
    for (const width of [320,1280]) {
      await initial.setViewportSize({width,height:820})
      await sections.getByRole('button',{name:'Overview',exact:true}).click()
      assert.ok(await dashboards.getByRole('button').evaluateAll(items=>{
        const rows=items.map(item=>item.getBoundingClientRect())
        return rows.length>1 && rows.every((row,index)=>row.left===rows[0].left && (index===0 || row.top>=rows[index-1].bottom))
      }),`Overview tabs stack on the left at ${width}px`)
      for (const label of available) {
        await sections.getByRole('button',{name:label.trim(),exact:true}).click()
        await sections.getByRole('button',{name:label.trim(),exact:true,pressed:true}).waitFor()
        assert.equal(await sections.locator('button[aria-pressed="true"]').count(),1)
        assert.ok(await initial.evaluate(() => document.documentElement.scrollWidth<=innerWidth),
          `${label.trim()} overflows the operator viewport at ${width}px`)
        visits++
      }
    }
    console.log(`Stress checked ${visits} Admin tab transitions across mobile and desktop widths after role verification.`)
  }
  await initial.getByRole('button', {name: 'Sign out', exact: true}).click()
  await initial.getByRole('heading', {name: 'Operator sign-in'}).waitFor()
  await initial.close()

  const again = await signIn(operator.email)
  await again.getByRole('button', {name: 'Verify code', exact: true}).waitFor()
  assert.equal(await again.getByRole('button', {name: 'Set up authenticator'}).count(), 0)
  assert.equal(await again.getByRole('group', {name: 'Operator sections'}).count(), 0)
  console.log('Passed first-time QR enrollment, operator dashboards, all 234 inventory entries, mobile layout, role-scoped safety controls, and moderation navigation.')
} finally {
  await browser?.close()
  for (const id of accounts) {
    sql(`delete from sectalk_private.staff where user_id='${id}'; delete from auth.users where id='${id}';`)
  }
}
