import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHmac, randomUUID } from 'node:crypto'
import { setTimeout as delay } from 'node:timers/promises'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const client = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY, options)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const handle = 'opsqa_' + randomUUID().slice(0, 8)
const email = handle + '@example.org'
const password = randomUUID() + '1!Q'
const unrelatedFile = randomUUID()
let staff
let browser

function data(result) {
  if (result.error) throw result.error
  return result.data
}

function sql(statement) {
  execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-v', 'ON_ERROR_STOP=1',
    '-U', 'postgres', '-d', 'postgres'], { input: statement, windowsHide: true })
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

function dashboardResponse(page) {
  return page.waitForResponse(response => response.url().endsWith('/rpc/st_v6_operational_metrics'))
}

try {
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  staff = user.id
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: 'Operational Metrics QA' }))
  sql(`insert into sectalk_private.staff values('${staff}');`)
  assert.equal((await client.rpc('st_v6_operational_metrics', { p_window: '1h' })).error?.code, '42501')
  assert.ok((await client.rpc('st_v6_record_operational_metrics', { p_samples: [] })).error)

  browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
  const page = await browser.newPage()
  await page.goto(app.href)
  await page.getByLabel('Email address', { exact: true }).fill(email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation', { name: 'SecTalk features' }).getByRole('button', { name: 'Safety', exact: true }).click()
  const tab = page.getByRole('button', { name: 'Operational metrics', exact: true })
  await page.getByRole('button', { name: 'Staff console', exact: true }).click()
  assert.equal(await tab.count(), 0)
  await page.getByRole('button', { name: 'Set up authenticator' }).click()
  const secret = (await page.locator('.mfa-setup code').textContent()).trim()
  await page.getByLabel('Authenticator code', { exact: true }).fill(totp(secret))
  await page.getByRole('button', { name: 'Verify access', exact: true }).click()
  const initial = dashboardResponse(page)
  await tab.click()
  const firstRead = await initial
  const { authorization } = await firstRead.request().allHeaders()
  assert.ok(authorization)
  const headers = { Authorization: authorization, 'Content-Type': 'application/json' }
  const baseline = new Map((await firstRead.json()).map(row => [row.operation, row]))

  const request = () => fetch(new URL('/api/files/download', app), {
    method: 'POST', headers, body: JSON.stringify({ file: unrelatedFile, ignored: email }),
  })
  const concurrent = await Promise.all(Array.from({ length: 6 }, request))
  assert.deepEqual(concurrent.map(response => response.status), Array(6).fill(404))
  let limited
  for (let attempt = 0; attempt < 2; attempt++) {
    sql(`insert into sectalk_private.limits(actor,action,bucket,hits)
      values('${staff}','v6_file_download',date_trunc('minute',now()),80)
      on conflict(actor,action) do update set bucket=excluded.bucket,hits=excluded.hits;`)
    limited = await request()
    if (limited.status === 429) break
  }
  assert.equal(limited.status, 429)
  const ice = await fetch(new URL('/api/ice', app))
  assert.equal(ice.status, 401)
  const billing = await fetch(new URL('/api/billing/action', app), { method: 'POST' })
  assert.ok([401, 503].includes(billing.status))

  const panel = page.getByRole('region', { name: 'Operational metrics' })
  const refresh = panel.getByRole('button', { name: 'Refresh operations' })
  let summaries = []
  for (let attempt = 0; attempt < 15; attempt++) {
    await delay(200)
    const response = dashboardResponse(page)
    await refresh.click()
    summaries = await (await response).json()
    const next = summaries.find(row => row.operation === 'file_download_grant')
    if (next?.client_errors >= (baseline.get('file_download_grant')?.client_errors ?? 0) + 7
      && summaries.some(row => row.operation === 'call_ice')
      && summaries.some(row => row.operation === 'billing_action')) break
  }
  const entry = summaries.find(row => row.operation === 'file_download_grant')
  assert.ok(entry?.client_errors >= (baseline.get('file_download_grant')?.client_errors ?? 0) + 7)
  assert.ok(entry.throttled >= (baseline.get('file_download_grant')?.throttled ?? 0) + 1)
  assert.ok(entry.peak_in_flight >= 2)
  assert.ok(entry.p95_band >= entry.p50_band)
  assert.ok(summaries.find(row => row.operation === 'call_ice')?.client_errors >= (baseline.get('call_ice')?.client_errors ?? 0) + 1)
  if (billing.status === 503) {
    assert.ok(summaries.find(row => row.operation === 'billing_action')?.unavailable >=
      (baseline.get('billing_action')?.unavailable ?? 0) + 1)
  }
  for (const row of summaries) assert.deepEqual(Object.keys(row).sort(), [
    'client_errors', 'operation', 'p50_band', 'p95_band', 'peak_in_flight', 'requests', 'server_errors', 'throttled', 'unavailable',
  ])
  assert.ok(!JSON.stringify(summaries).includes(email) && !JSON.stringify(summaries).includes(unrelatedFile))
  await panel.getByRole('row', { name: /Authorize download/ }).waitFor()
  await panel.getByRole('columnheader', { name: 'Peak concurrency' }).waitFor()
  const weekly = dashboardResponse(page)
  await page.getByRole('button', { name: '7 days', exact: true }).click()
  assert.equal((await weekly).status(), 200)
  console.log('Operational metrics passed with real API traffic, enforced throttling, concurrent requests, and real staff TOTP.')
} finally {
  await browser?.close()
  if (staff) {
    sql(`delete from sectalk_private.limits where actor='${staff}';
      delete from sectalk_private.staff where user_id='${staff}';`)
    data(await admin.auth.admin.deleteUser(staff))
  }
}
