import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHmac, randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const client = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY, options)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const handle = 'threatqa_' + randomUUID().slice(0, 8)
const email = handle + '@example.org'
const password = randomUUID() + '1!Q'
const cases = Array.from({ length: 5 }, () => ({
  reporter: randomUUID(), subject: randomUUID(), chat: randomUUID(), report: randomUUID(),
}))
let staffId
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

const accountIds = cases.flatMap(({ reporter, subject }) => [reporter, subject])
const quoteList = values => values.map(value => "'" + value + "'").join(',')

try {
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  staffId = user.id
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: 'Threat Trends QA' }))
  sql(`
    begin;
    insert into sectalk_private.staff values('${staffId}');
    insert into auth.users(id,email) values
      ${accountIds.map(id => `('${id}','${id}@example.invalid')`).join(',')};
    insert into public.st_profiles(id,handle,name) values
      ${accountIds.map(id => `('${id}','thrt_${id.slice(0, 13).replace('-', '')}','Private report participant')`).join(',')};
    insert into public.st_chats(id,member_a,member_b,requester,status) values
      ${cases.map(({ chat, reporter, subject }) => `('${chat}',least('${reporter}'::uuid,'${subject}'::uuid),
        greatest('${reporter}'::uuid,'${subject}'::uuid),'${reporter}','accepted')`).join(',')};
    insert into public.st_reports(id,chat_id,reporter,subject,category,details,evidence,created_at) values
      ${cases.map(({ chat, reporter, subject, report }) => `('${report}','${chat}','${reporter}','${subject}',
        'threat','Private synthetic report details','Private synthetic shared evidence',
        date_trunc('week',now(),'UTC')-interval '7 weeks')`).join(',')};
    insert into sectalk_private.audit(actor,report_id,action,note,created_at) values
      ${cases.map(({ report }) => `('${staffId}','${report}','warn','Private synthetic moderation note',
        date_trunc('week',now(),'UTC')-interval '7 weeks'+interval '1 day')`).join(',')};
    commit;
  `)
  assert.equal((await client.rpc('st_v6_threat_trends', { p_category: 'threat' })).error?.code, '42501')

  browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
  const page = await browser.newPage()
  await page.goto(app.href)
  await page.getByLabel('Email address', { exact: true }).fill(email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation', { name: 'SecTalk features' }).getByRole('button', { name: 'Safety', exact: true }).click()
  const tab = page.getByRole('button', { name: 'Threat trends', exact: true })
  await page.getByRole('button', { name: 'Staff console', exact: true }).click()
  assert.equal(await tab.count(), 0)
  await page.getByRole('button', { name: 'Set up authenticator' }).click()
  const secret = (await page.locator('.mfa-setup code').textContent()).trim()
  await page.getByLabel('Authenticator code', { exact: true }).fill(totp(secret))
  await page.getByRole('button', { name: 'Verify access', exact: true }).click()

  const trends = page.waitForResponse(response => response.url().endsWith('/rpc/st_v6_threat_trends'))
  await tab.click()
  const response = await trends
  assert.equal(response.status(), 200)
  const weeks = await response.json()
  assert.equal(weeks.length, 8)
  for (const row of weeks) assert.deepEqual(Object.keys(row).sort(), ['actioned', 'reports', 'week_start'])
  const seededWeek = weeks[6]
  assert.equal(seededWeek.reports, 5)
  assert.equal(seededWeek.actioned, 5)
  const panel = page.getByRole('region', { name: 'Threat trends' })
  const weekRow = panel.getByRole('row').filter({ has: page.locator('time[datetime="' + seededWeek.week_start + '"]') })
  await weekRow.waitFor()
  assert.deepEqual(await weekRow.getByRole('cell').allTextContents(), ['5', '5'])
  assert.equal(await panel.getByText('Private synthetic shared evidence').count(), 0)

  await panel.getByLabel('Report category').selectOption('sexual_content')
  await panel.getByRole('table', { name: /Unwanted nudity or sexual content/ }).waitFor()
  assert.deepEqual(await weekRow.getByRole('cell').allTextContents(), ['Below threshold', 'Below threshold'])
  console.log('Threat trends browser passed with real TOTP, fixed weekly aggregates, category selection, and suppressed counts.')
} finally {
  await browser?.close()
  const reports = quoteList(cases.map(({ report }) => report))
  sql(`delete from sectalk_private.audit where report_id in (${reports});
    delete from public.st_reports where id in (${reports});
    delete from public.st_chats where id in (${quoteList(cases.map(({ chat }) => chat))});
    delete from auth.users where id in (${quoteList(accountIds)});
    ${staffId ? `delete from sectalk_private.staff where user_id='${staffId}';` : ''}`)
  if (staffId) data(await admin.auth.admin.deleteUser(staffId))
}
