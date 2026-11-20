// Local QA only. Uses genuine browser TOTP and aggregate-only RPC responses.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHmac, randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = {auth: {persistSession: false, autoRefreshToken: false}}
const admin = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const password = randomUUID() + '1!Q'
const suffix = randomUUID().slice(0, 8)
assert.match(suffix, /^[a-f0-9]{8}$/)

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}
async function account(role) {
  const handle = 'overview_' + role + '_' + suffix
  const email = handle + '@example.invalid'
  const {user} = data(await admin.auth.admin.createUser({email, password, email_confirm: true}))
  const client = createClient(supabase.origin, publicKey, options)
  data(await client.auth.signInWithPassword({email, password}))
  data(await client.rpc('st_save_profile', {p_handle: handle, p_name: 'Private fixture profile'}))
  assert.match(user.id, /^[a-f0-9-]{36}$/)
  return {id: user.id, email, client}
}
function totp(secret) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bits = [...secret.toUpperCase().replace(/=+$/, '')].map(character =>
    alphabet.indexOf(character).toString(2).padStart(5, '0')).join('')
  const key = Buffer.from(bits.match(/.{8}/g).map(part => Number.parseInt(part, 2)))
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)))
  const mac = createHmac('sha1', key).update(counter).digest()
  return String((mac.readUInt32BE(mac.at(-1) & 15) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}

const [staff, member] = await Promise.all([account('staff'), account('member')])
execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-v', 'ON_ERROR_STOP=1',
  '-U', 'postgres', '-d', 'postgres'], {input: `
begin;
insert into sectalk_private.staff(user_id) values ('${staff.id}');
insert into sectalk_private.st_v6_incident_responders(user_id,role) values ('${staff.id}','responder');
insert into sectalk_private.st_v6_security_incidents(id,title,severity,status,created_by,assigned_to)
  values(gen_random_uuid(),'Private assigned incident','high','contained','${member.id}','${staff.id}'),
    (gen_random_uuid(),'Private unrelated incident','critical','open','${member.id}','${member.id}');

create temporary table overview_people as select n,gen_random_uuid() as id from generate_series(1,12) n;
insert into auth.users(id,email) select id,'overview-${suffix}-'||n||'@example.invalid' from overview_people;
insert into public.st_profiles(id,handle,name) select id,'ov_${suffix}_'||n,'Private participant fixture' from overview_people;
create temporary table overview_cases as
  select gen_random_uuid() as chat,gen_random_uuid() as report,a.id as reporter,b.id as subject
  from overview_people a join overview_people b on b.n=a.n+6 where a.n<=6;
insert into public.st_chats(id,member_a,member_b,requester,status)
  select chat,least(reporter,subject),greatest(reporter,subject),reporter,'accepted' from overview_cases;
insert into public.st_reports(id,reporter,subject,chat_id,category,details,status,created_at)
  select report,reporter,subject,chat,'threat','Private fixture report detail','resolved',
    date_trunc('week',now(),'UTC')-interval '3 days' from overview_cases;
insert into sectalk_private.audit(actor,report_id,action,note,created_at)
  select '${staff.id}',report,a.action,'Private action reason',now()-a.age
  from overview_cases cross join (values('viewed',interval '40 minutes'),('reviewing',interval '30 minutes'),
    ('resolved',interval '10 minutes')) a(action,age);
insert into public.st_reports(reporter,subject,chat_id,category,details,status)
  select reporter,subject,chat,'threat','Private queue report',r.status
  from (select * from overview_cases limit 1) c cross join (values('open'),('reviewing')) r(status);
commit;`})
assert.equal((await staff.client.rpc('st_v6_security_center_overview')).error?.code, '42501')
assert.equal((await member.client.rpc('st_v6_security_center_overview')).error?.code, '42501')

const browser = await chromium.launch({executablePath: process.env.SECTALK_TEST_BROWSER})
try {
  const page = await browser.newPage()
  await page.goto(new URL('/#account', app).href)
  await page.getByLabel('Email address', {exact: true}).fill(staff.email)
  await page.getByLabel('Password', {exact: true}).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation', {name: 'SecTalk features'}).getByRole('button', {name: 'Safety', exact: true}).click()
  assert.equal(await page.getByRole('button', {name: 'Security overview', exact: true}).count(), 0)
  await page.getByRole('button', {name: 'Staff console', exact: true}).click()
  await page.getByRole('button', {name: 'Set up authenticator', exact: true}).click()
  const secret = (await page.locator('.mfa-setup code').textContent()).trim()
  await page.getByLabel('Authenticator code', {exact: true}).fill(totp(secret))
  await page.getByRole('button', {name: 'Verify access', exact: true}).click()

  const read = page.waitForResponse(response => response.ok() && response.url().endsWith('/rpc/st_v6_security_center_overview'))
  await page.getByRole('button', {name: 'Security overview', exact: true}).click()
  const snapshot = await (await read).json()
  assert.deepEqual(Object.keys(snapshot).sort(),
    ['as_of','incident_scope','open_cases','open_incidents','queue_depth','response_times','reviewing_cases','trend'])
  assert.equal(snapshot.open_incidents, 1)
  assert.equal(snapshot.incident_scope, 'assigned_or_created')
  assert.equal(snapshot.queue_depth, snapshot.open_cases + snapshot.reviewing_cases)
  assert.ok(snapshot.open_cases >= 1)
  assert.ok(snapshot.response_times.acknowledgement.samples >= 6)
  assert.ok(snapshot.response_times.resolution.samples >= 6)
  assert.ok(snapshot.response_times.resolution.minutes > 0)
  assert.equal(snapshot.trend.length, 8)
  assert.ok(snapshot.trend.at(-1).reports >= 5)
  assert.doesNotMatch(JSON.stringify(snapshot), /Private|@|[0-9a-f]{8}-[0-9a-f-]{27}/i)
  const overview = page.getByRole('region', {name: 'Security overview'})
  await overview.getByText('Assigned to you or created by you', {exact: true}).waitFor()
  await overview.getByText('Mean time to acknowledge (MTTA)', {exact: true}).waitFor()
  await overview.getByText('Mean time to resolve (MTTR)', {exact: true}).waitFor()
  await overview.getByRole('table').waitFor()
  assert.equal(await overview.getByRole('row').count(), 9)
  console.log('Passed genuine staff TOTP, scoped security counts, completed response durations and safe risk trend.')
} finally {
  await browser.close()
}
