// Run against the isolated loopback app and Supabase stack.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const serviceKey = process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const admin = createClient(supabase.origin, serviceKey, options)
const password = randomUUID() + '1!Q'
const suffix = randomUUID().slice(0, 8)

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

async function account(handlePrefix) {
  const handle = handlePrefix + '_' + suffix
  const email = handle + '@example.org'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(supabase.origin, publicKey, options)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: handle }))
  return { id: user.id, handle, email, client }
}
const owner = await account('settings_owner')
const peer = await account('settings_peer')
const clean = await account('settings_clean')
const chat = data(await owner.client.rpc('st_request', { p_handle: peer.handle }))
data(await peer.client.rpc('st_respond', { p_chat: chat, p_accept: true }))
for (const [actor, body] of [[owner, 'own export message'], [peer, 'peer private message']]) {
  data(await actor.client.rpc('st_send', { p_chat: chat, p_id: randomUUID(), p_body: body }))
}
const workspace = data(await owner.client.rpc('st_v2_create_workspace', { p_name: 'Synthetic retained dependency' }))
data(await owner.client.from('st_v6_saved_searches').insert({query:'My export query',kind:'direct'}))
data(await peer.client.from('st_v6_saved_searches').insert({query:'Private peer search',kind:'direct'}))
const hold = randomUUID()
function fixture(sql) {
  execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres'], { input: sql })
}

const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
const button = (page, name) => page.getByRole('button', { name, exact: true })
const form = (page, name) => page.getByRole('region', { name })
async function signIn(page, person) {
  await page.goto(new URL('/#account', app).href, { waitUntil: 'domcontentloaded' })
  await page.getByLabel('Email address', { exact: true }).fill(person.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation', { name: 'SecTalk features' }).getByRole('button', { name: 'Profile', exact: true }).click()
}
async function theme(page, expected, motion) {
  await page.waitForFunction(({ expected, motion }) => document.documentElement.dataset.userTheme === expected &&
    (document.documentElement.dataset.userMotion || '') === motion, { expected, motion })
}
async function selectTheme(page, value, reduced) {
  const appearance = form(page, 'Account appearance')
  await appearance.getByLabel('Color theme').selectOption(value)
  await appearance.getByRole('checkbox', { name: 'Reduce motion' }).setChecked(reduced)
  await button(appearance, 'Save appearance').click()
  await appearance.getByText('Appearance saved for your account.').waitFor()
  await theme(page, value, reduced ? 'reduce' : 'system')
}
async function requestDeletion(page, buttonName = 'Delete my account') {
  await button(page, buttonName).click()
  await page.getByLabel('Type DELETE ACCOUNT to confirm').fill('DELETE ACCOUNT')
  await page.getByLabel('Current password').fill(password)
  await button(page, 'Confirm account deletion').click()
}
try {
  const a = await browser.newPage({ acceptDownloads: true })
  const b = await browser.newPage()
  await signIn(a, owner)
  await a.getByLabel('Display name', { exact: true }).fill('Verified settings profile')
  const profileSaved = a.waitForResponse(r => r.ok() && r.url().includes('/rpc/st_save_profile'))
  await button(a, 'Save profile').click()
  await profileSaved
  await button(a, 'Security').click()
  await button(a, 'Set up authenticator').waitFor()
  await button(a, 'Devices and sessions').click()
  await form(a, 'Devices and sessions').getByText('This device', { exact: true }).waitFor()
  await button(a, 'Open notification settings').click()
  await button(a, 'Preferences').click()
  const dm = a.getByRole('group', { name: 'Alert categories' }).getByRole('checkbox', { name: 'Direct messages', exact: true })
  await dm.waitFor()
  const desired = !data(await owner.client.rpc('st_v6_notification_preferences')).dm
  const response = a.waitForResponse(r => r.ok() && r.url().endsWith('/rpc/st_v6_set_notification_preference'))
  await dm.click()
  await response
  assert.equal(data(await owner.client.rpc('st_v6_notification_preferences')).dm, desired)
  await a.getByRole('navigation', { name: 'SecTalk features' }).getByRole('button', { name: 'Profile', exact: true }).click()
  await button(a, 'Open billing settings').click()
  await a.getByRole('heading', { name: 'Billing', exact: true }).waitFor()
  await a.getByRole('heading', { name: 'Free', exact: true }).waitFor()
  await a.getByRole('navigation', { name: 'SecTalk features' }).getByRole('button', { name: 'Profile', exact: true }).click()
  const appearance = button(a, 'Appearance')
  await appearance.focus()
  await appearance.press('Enter')
  await selectTheme(a, 'light', true)
  assert.equal(await a.locator('html').evaluate(element => getComputedStyle(element).colorScheme), 'light')
  await signIn(b, owner)
  await theme(b, 'light', 'reduce')
  await button(b, 'Appearance').click()
  await selectTheme(b, 'high-contrast', false)
  assert.equal(await b.locator('body').evaluate(element => getComputedStyle(element).backgroundColor), 'rgb(0, 0, 0)')
  await selectTheme(b, 'dark', false)
  await a.reload({ waitUntil: 'domcontentloaded' })
  await theme(a, 'dark', 'system')
  await a.getByRole('navigation', { name: 'SecTalk features' }).getByRole('button', { name: 'Profile', exact: true }).click()
  await button(a, 'Privacy and data').click()
  await button(a, 'Export my data').click()
  await a.getByLabel('Current password').fill(password)
  const pendingDownload = a.waitForEvent('download')
  await button(a, 'Verify and download export').click()
  const stream = await (await pendingDownload).createReadStream()
  const chunks = []
  for await (const chunk of stream) chunks.push(chunk)
  const exported = JSON.parse(Buffer.concat(chunks).toString('utf8'))
  assert.equal(exported.profile.name, 'Verified settings profile')
  assert.equal(exported.profile.accountId, owner.id)
  assert.equal(exported.appearance.theme, 'dark')
  assert.match(JSON.stringify(exported.authoredMessages), /own export message/)
  assert.deepEqual(exported.personalSettings.savedSearches.map(search=>search.query),['My export query'])
  assert.ok(exported.personalSettings.currentWorkspaces.some(scope=>scope.id===workspace&&scope.role==='owner'))
  assert.doesNotMatch(JSON.stringify(exported), /peer private message|Private peer search|access_token|refresh_token/)
  await requestDeletion(a)
  await a.getByRole('list',{name:'Deletion requirements'}).getByText('You own a workspace.',{exact:false}).waitFor()
  await button(a, 'Cancel deletion request').click()
  await a.getByLabel('Current password').fill(password)
  await button(a, 'Confirm cancellation').click()
  await button(a, 'Delete my account').waitFor()
  await button(a, 'Appearance').click()
  await selectTheme(a, 'light', true)
  await a.getByRole('button', { name: 'Sign out', exact: true }).first().press('Enter')
  fixture("insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by) values('" + hold + "','" + workspace + "','" + clean.id + "','Synthetic preservation test','" + owner.id + "');")
  await signIn(a, clean)
  await theme(a, 'dark', 'system')
  await button(a, 'Privacy and data').click()
  await requestDeletion(a)
  await form(a, 'Account privacy and data').locator('time').waitFor()
  await a.getByRole('list',{name:'Deletion requirements'}).getByText('Some workspace or group messages are retained',{exact:false}).waitFor()
  await requestDeletion(a, 'Retry account deletion')
  await a.getByText('Your request is still pending because the account has retained records or dependencies.', { exact: true }).waitFor()
  assert.ok(!(await admin.auth.admin.getUserById(clean.id)).error, 'active hold kept the account intact')
  fixture("update sectalk_private.st_v6_workspace_holds set released_at=now(),released_by='" + owner.id + "',release_reason='Synthetic authorized release' where id='" + hold + "';")
  await requestDeletion(a, 'Retry account deletion')
  await a.getByLabel('Email address', { exact: true }).waitFor()
  assert.ok((await admin.auth.admin.getUserById(clean.id)).error, 'eligible account was removed from Auth')
  assert.ok((await clean.client.rpc('st_v7_personal_deletion', { p_owner: clean.id })).error, 'the old access token was denied')
  console.log('passed: native settings navigation, real preference persistence and export, request/cancel, eligible account and session deletion')
} finally {
  await browser.close()
  fixture("delete from sectalk_private.st_v6_workspace_holds where id='" + hold + "';")
  await Promise.allSettled([owner, peer, clean].map(person => admin.auth.admin.deleteUser(person.id)))
}
