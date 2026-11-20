// Run against the isolated loopback app and Supabase stack.
import assert from 'node:assert/strict'
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
const owner = await account('family_owner')
const member = await account('family_member')
const outsider = await account('not_family')
const kind = process.env.SECTALK_MANAGED_SCHOOL === '1' ? 'school' : 'family'
const scopeName = kind + ' oversight ' + suffix
const fileFixture = kind === 'family' && process.env.SECTALK_FAMILY_FILE_TEST === '1'
const file = randomUUID()
const filename = 'family-synthetic-' + suffix + '.txt'
const sharePassword = 'synthetic-family-' + suffix
let filePeer, oldToken
const workspace = data(await owner.client.rpc('st_v6_create_typed_workspace', {
  p_id: randomUUID(), p_name: scopeName, p_type: kind,
}))
data(await owner.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: member.handle }))
const invite = data(await member.client.from('st_v2_invites').select('id').eq('workspace_id', workspace).single())
data(await member.client.rpc('st_v2_reply_invite', { p_invite: invite.id, p_accept: true }))

const share = token => fetch(new URL('/api/files/share', app), {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ token, password: sharePassword, action: 'view' }),
})
const createShare = () => member.client.rpc('st_v6_create_file_share', {
  p_file: file, p_password: sharePassword, p_seconds: 900, p_downloads: 2,
})
if (fileFixture) {
  filePeer = await account('family_file')
  const chat = data(await member.client.rpc('st_request', { p_handle: filePeer.handle }))
  data(await filePeer.client.rpc('st_respond', { p_chat: chat, p_accept: true }))
  const bytes = Buffer.from('Private synthetic Family attachment.')
  data(await member.client.rpc('st_v5_stage_file', { p_chat: chat, p_id: file, p_filename: filename, p_bytes: bytes.length }))
  const login = data(await member.client.auth.getSession()).session
  const authorization = 'Bearer ' + login.access_token
  assert.equal((await fetch(new URL('/api/files/upload?file=' + file, app), {
    method: 'POST', headers: { Authorization: authorization, 'Content-Type': 'text/plain' }, body: bytes,
  })).status, 200)
  assert.equal((await fetch(new URL('/api/files/publish', app), {
    method: 'POST', headers: { Authorization: authorization, 'Content-Type': 'application/json' },
    body: JSON.stringify({ file, caption: '', mime: 'text/plain' }),
  })).status, 200)
  oldToken = data(await createShare())
  assert.equal((await share(oldToken)).status, 200)
}
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
const button = (scope, name) => scope.getByRole('button', { name, exact: true })
const nav = page => page.getByRole('navigation', { name: 'SecTalk features' })
const panel = page => page.getByRole('region', { name: 'Managed accounts' })
async function open(person) {
  const page = await browser.newPage()
  await page.goto(new URL('/#account', app).href, { waitUntil: 'domcontentloaded' })
  await page.getByLabel('Email address', { exact: true }).fill(person.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await openPeople(page)
  return page
}
async function openPeople(page) {
  await button(nav(page), 'Workspaces').click()
  await button(page, kind === 'family' ? 'Family' : 'People').click()
  await panel(page).waitFor()
}
async function tryContact(page, handle) {
  await button(nav(page), 'Friends').click()
  await button(page, 'Use a handle').click()
  await page.getByLabel('SecTalk handle', { exact: true }).fill(handle)
  const reply = page.waitForResponse(result => result.url().endsWith('/rpc/st_request'))
  await button(page, 'Send request').click()
  return reply
}

try {
  const a = await open(owner)
  const b = await open(member)
  assert.equal(await button(panel(b), 'Propose managed oversight').count(), 0)
  await panel(a).getByRole('combobox', { name: /Workspace member/ }).selectOption(member.id)
  await button(panel(a), 'Propose managed oversight').click()
  await panel(a).getByText('Oversight proposal sent.', { exact: true }).waitFor()
  assert.equal(await panel(a).getByText(/Trusted devices \d/).count(), 0)

  await button(panel(b), 'Refresh managed accounts').click()
  await panel(b).getByText(/^Pending consent/).waitFor()
  await panel(b).getByRole('heading', { name: kind === 'school' ? /Teacher supervisor/ : /Family guardian/ }).waitFor()
  if (fileFixture) {
    assert.equal(await b.getByRole('region', { name: 'Family dashboard' }).count(), 1)
    assert.equal(await panel(b).getByRole('checkbox', { name: 'Include public attachment-link protection' }).isChecked(), true)
  }
  await button(panel(b), 'Accept oversight and contact restriction').click()
  await panel(b).getByText('Managed oversight is active.', { exact: true }).waitFor()
  if (fileFixture) {
    await b.getByText('Public attachment links blocked', { exact: true }).waitFor()
    await b.getByText('No recent trusted-device sign-in', { exact: true }).waitFor()
    assert.equal((await share(oldToken)).status, 404)
    assert.equal((await createShare()).error?.code, '42501')
    await button(panel(a), 'Refresh managed accounts').click()
    const guard = a.getByRole('region', { name: 'Family sharing and device health' })
    await button(guard, 'Allow public attachment links').click()
    await guard.getByText('Public attachment links allowed', { exact: true }).waitFor()
    assert.equal((await share(oldToken)).status, 200)
    await button(guard, 'Block public attachment links').click()
    await guard.getByText('Public attachment links blocked', { exact: true }).waitFor()
    await button(panel(b), 'Refresh managed accounts').click()
    const memberGuard = b.getByRole('region', { name: 'Family sharing and device health' })
    await button(memberGuard, 'Withdraw file-link consent').click()
    await memberGuard.getByText('File-link protection has not been approved', { exact: true }).waitFor()
    assert.ok(data(await createShare()))
    await button(memberGuard, 'Enable Family file-link protection').click()
    await memberGuard.getByText('Public attachment links blocked', { exact: true }).waitFor()
    await button(nav(b), 'Files').click()
    await b.getByRole('region', { name: 'Chat files' }).locator('.release-row').filter({ hasText: filename })
      .getByRole('button', { name: 'View details' }).click()
    const details = b.getByRole('dialog', { name: 'Attachment details' })
    await details.getByText('Share links', { exact: true }).click()
    await details.getByLabel('Share password').fill(sharePassword)
    const blockedLink = b.waitForResponse(response => response.url().endsWith('/rpc/st_v6_create_file_share'))
    await button(details, 'Create share link').click()
    assert.equal((await blockedLink).status(), 403)
    assert.equal(await details.getByLabel('New share link').count(), 0)
    await b.keyboard.press('Escape')
    await details.waitFor({ state: 'hidden' })
  }
  const denied = await tryContact(b, outsider.handle)
  assert.equal(denied.status(), 403)
  assert.equal((await denied.json()).code, '42501')
  assert.equal((await outsider.client.rpc('st_request', { p_handle: member.handle })).error?.code, '42501')
  assert.equal((await outsider.client.rpc('st_v7_managed_account', { p_workspace: workspace })).error?.code, '42501')
  await button(panel(a), 'Refresh managed accounts').click()
  await panel(a).getByText('Trusted devices 0', { exact: true }).waitFor()
  const relationship = data(await owner.client.rpc('st_v7_managed_account', { p_workspace: workspace })).relationships[0]
  assert.deepEqual(Object.keys(relationship).sort(), [
    'changedAt', 'id', 'participant', 'restrictContacts', 'state', 'supervisor', 'verifiedDevices',
  ])
  await button(panel(a), 'Allow new outside contacts').click()
  await panel(a).getByText('New outside contacts are allowed.', { exact: true }).waitFor()
  await button(panel(a), 'Restrict new outside contacts').click()
  await panel(a).getByText('New outside contacts are restricted.', { exact: true }).waitFor()
  assert.equal((await tryContact(b, outsider.handle)).status(), 403)

  await openPeople(b)
  await button(panel(b), 'End managed oversight').click()
  await panel(b).getByText('Managed oversight ended.', { exact: true }).waitFor()
  await button(panel(a), 'Refresh managed accounts').click()
  await panel(a).getByText(/^Ended/).waitFor()
  assert.equal(await panel(a).getByText('Trusted devices 0', { exact: true }).count(), 0)
  assert.equal((await tryContact(b, outsider.handle)).status(), 200)
  if (fileFixture) console.log('Family file defaults blocked real creation/redemption and returned access on consent withdrawal.')
  console.log('Passed native ' + kind + ' proposal, independent consent, new contact restriction and participant revocation.')
} finally {
  await browser.close()
  await Promise.allSettled([owner, member, outsider, filePeer].filter(Boolean).map(person => admin.auth.admin.deleteUser(person.id)))
}
