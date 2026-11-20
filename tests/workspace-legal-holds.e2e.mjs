import assert from 'node:assert/strict'
import { createHmac, randomUUID } from 'node:crypto'
import { setTimeout } from 'node:timers/promises'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const suffix = randomUUID().slice(0, 8)
const password = randomUUID() + '1!Q'

function data(result) {
  assert.equal(result.error, null, result.error?.message)
  return result.data
}

async function account(role) {
  const handle = 'hold_' + role + '_' + suffix
  const name = 'Governance ' + role
  const email = handle + '@example.org'
  data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(supabase.origin, publicKey, options)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: name }))
  return { client, handle, name, email }
}

function totp(encoded) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bits = [...encoded.toUpperCase().replace(/=+$/, '')]
    .map(character => alphabet.indexOf(character).toString(2).padStart(5, '0')).join('')
  const key = Buffer.from(bits.match(/.{8}/g).map(group => parseInt(group, 2)))
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)))
  const value = createHmac('sha1', key).update(counter).digest()
  return String((value.readUInt32BE(value.at(-1) & 15) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}

const [owner, member] = await Promise.all([account('owner'), account('member')])
const workspace = data(await owner.client.rpc('st_v2_create_workspace', { p_name: 'Governance ' + suffix }))
data(await owner.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: member.handle }))
const invite = data(await member.client.from('st_v2_invites').select('id').eq('workspace_id', workspace).single())
data(await member.client.rpc('st_v2_reply_invite', { p_invite: invite.id, p_accept: true }))
const room = randomUUID()
const roomName = 'Legal test room'
data(await owner.client.rpc('st_v6_room_create', {
  p_id: room, p_workspace: workspace, p_name: roomName, p_kind: 'public', p_template: 'blank',
}))
data(await member.client.rpc('st_v6_room_membership', { p_room: room, p_action: 'join' }))
const post = randomUUID()
const original = 'Scoped preservation fixture ' + suffix
data(await member.client.rpc('st_v6_room_post', { p_room: room, p_id: post, p_body: original }))

const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
try {
  const nav = page => page.getByRole('navigation', { name: 'SecTalk features' })
  const button = (scope, name) => scope.getByRole('button', { name, exact: true })
  async function open(person) {
    const page = await browser.newPage()
    await page.goto(new URL('/#account', app).href)
    await page.getByLabel('Email address', { exact: true }).fill(person.email)
    await page.getByLabel('Password', { exact: true }).fill(password)
    await page.locator('button.submit-auth').click()
    await button(nav(page), 'Workspaces').click()
    await page.getByRole('group', { name: 'Workspace sections' }).waitFor()
    return page
  }
  const [ownerPage, memberPage] = await Promise.all([open(owner), open(member)])
  assert.equal(await button(memberPage, 'Governance').count(), 0)
  assert.equal((await member.client.rpc('st_v6_workspace_hold_state', { p_workspace: workspace })).error?.code, '42501')
  await button(ownerPage, 'Governance').click()
  await ownerPage.getByText('Set up an authenticator in Profile → Security to manage legal holds.').waitFor()

  await button(nav(ownerPage), 'Profile').click()
  await button(ownerPage, 'Security').click()
  await button(ownerPage, 'Set up authenticator').click()
  const secret = (await ownerPage.locator('.mfa-setup code').textContent()).trim()
  await ownerPage.getByLabel('Authenticator code', { exact: true }).fill(totp(secret))
  await button(ownerPage, 'Verify authenticator').click()
  await ownerPage.getByRole('heading', { name: 'Recovery codes', exact: true }).waitFor()
  await button(nav(ownerPage), 'Workspaces').click()
  await button(ownerPage, 'Governance').click()
  const governance = ownerPage.getByRole('region', { name: 'Legal holds' })
  await governance.getByLabel('Minimum days before scheduled room deletion').fill('14')
  await button(governance, 'Save room retention').click()
  await governance.getByText('Room retention policy saved.', { exact: true }).waitFor()
  await governance.getByText('Place a preservation hold', { exact: true }).click()
  await governance.getByLabel('Room scope').selectOption(room)
  await governance.getByLabel('Preservation reason').fill('Verified scoped preservation fixture.')
  await button(governance, 'Place hold').click()
  await governance.getByText('Preservation hold placed.', { exact: true }).waitFor()

  await button(nav(memberPage), 'Search').click()
  await button(memberPage.getByRole('group', { name: 'Search categories' }), 'Room posts').click()
  await memberPage.getByLabel('Search terms').fill(original)
  let searchRequests = 0
  memberPage.on('response', response => {
    if (response.url().endsWith('/rpc/st_v6_search') && response.ok()) searchRequests++
  })
  await memberPage.getByRole('button', { name: 'Search SecTalk', exact: true }).last().click()
  const visibleOriginal = memberPage.getByRole('article').getByText(original, { exact: true })
  await visibleOriginal.waitFor()
  for (let attempt = 0; searchRequests < 2 && attempt < 35; attempt++) await setTimeout(100)
  assert.ok(searchRequests >= 2, 'Search refresh did not confirm the Realtime subscription')
  data(await owner.client.rpc('st_v6_room_post_action', { p_room: room, p_post: post, p_action: 'redact' }))
  await visibleOriginal.waitFor({ state: 'detached', timeout: 5000 })
  const removed = data(await member.client.from('st_v6_room_posts').select('body').eq('room_id', room).eq('id', post).single())
  assert.equal(removed.body, 'Message removed')
  const search = data(await member.client.rpc('st_v6_search', { p_query: original, p_kind: 'room', p_filters: {} }))
  assert.deepEqual(search, [])

  await button(nav(ownerPage), 'Rooms').click()
  const directory = ownerPage.getByRole('region', { name: 'Room directory' })
  await directory.getByRole('button', { name: new RegExp(roomName) }).click()
  const settings = ownerPage.getByRole('group', { name: 'Room tabs' })
  await button(settings, 'Settings').click()
  await directory.getByRole('combobox', { name: 'Classification' }).selectOption('restricted')
  await button(directory, 'Save classification').click()
  await directory.getByText('Restricted classification', { exact: true }).waitFor()
  assert.equal(await button(directory, 'Allow message forwarding').isDisabled(), true)
  await button(nav(memberPage), 'Rooms').click()
  const memberDirectory = memberPage.getByRole('region', { name: 'Room directory' })
  await memberDirectory.getByRole('button', { name: new RegExp(roomName) }).click()
  await memberDirectory.getByText('Restricted classification', { exact: true }).waitFor()
  assert.equal(await button(memberDirectory, 'Save classification').count(), 0)
  ownerPage.once('dialog', dialog => dialog.accept())
  await button(ownerPage, 'Archive room').click()
  await button(ownerPage, 'Restore room').waitFor()
  await button(ownerPage, 'Schedule room deletion').click()
  await ownerPage.getByText('This room will become eligible for permanent deletion after 14 days, subject to active preservation holds.').waitFor()
  await button(ownerPage, 'Confirm scheduled deletion').click()
  await ownerPage.getByText('A preservation hold is delaying deletion.', { exact: true }).waitFor()
  await button(ownerPage, 'Cancel scheduled deletion').click()
  await button(ownerPage, 'Schedule room deletion').waitFor()
  await button(ownerPage, 'Restore room').click()
  await button(ownerPage, 'Archive room').waitFor()
  await button(nav(ownerPage), 'Workspaces').click()
  await button(ownerPage, 'Governance').click()
  await button(governance, 'Release hold').click()
  await governance.getByLabel('Release reason').fill('Verified release of the test scope.')
  await button(governance, 'Confirm release').click()
  await governance.getByRole('heading', { name: 'Released hold' }).waitFor()
  await governance.getByText('Verified release of the test scope.').waitFor()
  console.log('Passed workspace governance boundaries, real authenticator, scoped hold, room policy, scheduled deletion and restore.')
} finally {
  await browser.close()
}
