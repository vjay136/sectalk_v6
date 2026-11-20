import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { verifyStaffPanel } from './workspace-admin-fixture.mjs'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const backend = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(backend.origin, 'http://127.0.0.1:55321')
const key = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const service = createClient(backend.href, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const client = createClient(backend.href, key, options)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const run = randomUUID().slice(0, 8)
const handle = 'threatmap_' + run
const email = handle + '@example.invalid'
const password = randomUUID() + '1!q'
const asn = 4201000000 + parseInt(run, 16) % 1000000
const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10)
const users = []
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })

function data(result) {
  if (result.error) throw result.error
  return result.data
}
function sql(statement) {
  return execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-At',
    '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres'], { input: statement, encoding: 'utf8', windowsHide: true }).trim()
}

try {
  const { user } = data(await service.auth.admin.createUser({ email, password, email_confirm: true }))
  users.push(user.id)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: 'Threat map QA' }))
  assert.ok((await client.rpc('st_v7_security_threat_map', { p_day: yesterday })).error)
  sql(`insert into sectalk_private.st_v7_account_operators values('${user.id}','operator');
    insert into sectalk_private.st_v7_threat_observations(session_tag,subject_tag,event,observed_day,latitude_band,longitude_band,asn)
    select extensions.gen_random_bytes(32),extensions.gen_random_bytes(32),e.event,'${yesterday}',6,9,
      case when e.event='step_up_requested' then ${asn}+1 else ${asn} end
    from (values ('high_risk_sign_in',7),('step_up_requested',4),('session_terminated',5)) e(event,total)
    cross join lateral generate_series(1,e.total);`)

  const page = await browser.newPage()
  await page.goto(app.href)
  await page.getByLabel('Email address', { exact: true }).fill(email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  const nav = page.getByRole('navigation', { name: 'SecTalk features' })
  await nav.getByRole('button', { name: 'Safety', exact: true }).click()
  await page.getByRole('group', { name: 'Safety center sections' }).getByRole('button', { name: 'Account administration', exact: true }).click()
  await verifyStaffPanel(page)
  await page.getByRole('group', { name: 'Account administration sections' }).getByRole('button', { name: 'Threat map', exact: true }).click()
  const panel = page.getByRole('region', { name: 'Threat map', exact: true })
  assert.equal(await panel.getByLabel('UTC date').inputValue(), yesterday)
  const asnRow = panel.getByRole('row').filter({ hasText: String(asn) })
  await asnRow.getByRole('cell', { name: '5', exact: true }).waitFor()
  const cohorts = panel.getByRole('table', { name: /Geographic cohorts/ })
  await cohorts.getByRole('cell', { name: '30° N to 50° N', exact: true }).waitFor()
  await cohorts.getByRole('cell', { name: '0° to 20° E', exact: true }).waitFor()
  const choices = panel.getByRole('group', { name: 'Threat events' })
  await choices.getByRole('button', { name: 'Verification requested', exact: true }).click()
  assert.equal(await panel.getByRole('cell', { name: 'AS' + (asn + 1), exact: true }).count(), 0)
  await choices.getByRole('button', { name: 'Sessions ended', exact: true }).click()
  await asnRow.getByRole('cell', { name: '5', exact: true }).waitFor()
  const prior = new Date(Date.now() - 2 * 86400000).toISOString().slice(0, 10)
  await panel.getByLabel('UTC date').fill(prior)
  const lookup = page.waitForResponse(response => response.url().endsWith('/rpc/st_v7_security_threat_map'))
  await panel.getByRole('button', { name: 'View date', exact: true }).click()
  const response = await lookup
  assert.equal(response.status(), 200)
  assert.deepEqual(Object.keys(await response.json()).sort(), ['cells', 'day', 'minimum_accounts', 'networks'])
  assert.equal(await panel.getByRole('cell', { name: 'AS' + asn, exact: true }).count(), 0)
  console.log('Verified real TOTP, date and event tabs, aggregate map cells and ASNs, suppressed small cohorts and bounded response shape.')
} finally {
  await browser.close()
  sql(`delete from sectalk_private.st_v7_threat_observations where asn in (${asn},${asn + 1});`)
  for (const user of users) data(await service.auth.admin.deleteUser(user))
}
