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
const owner = await account('org_owner')
const member = await account('org_member')
const workspace = data(await owner.client.rpc('st_v2_create_workspace', { p_name: 'Original Organization' }))
const room = randomUUID()
data(await owner.client.rpc('st_v6_room_create', { p_id: room, p_workspace: workspace, p_name: 'Retention fixture', p_kind: 'public', p_template: 'blank' }))
data(await owner.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: member.handle }))
const invite = data(await member.client.from('st_v2_invites').select('id').eq('workspace_id', workspace).single())
data(await member.client.rpc('st_v2_reply_invite', { p_invite: invite.id, p_accept: true }))

const domain = 'verification-fixture.example.invalid'
const { createSocket } = await import('node:dgram')
const dns = createSocket('udp4')
let txt = 'wrong synthetic challenge'
let requests = 0
dns.on('message', (packet, sender) => {
  let offset = 12
  const labels = []
  while (offset < packet.length && packet[offset] > 0 && packet[offset] <= 63) {
    const size = packet[offset++]
    labels.push(packet.subarray(offset, offset + size).toString('ascii'))
    offset += size
  }
  if (offset + 5 > packet.length) return
  if (labels.join('.') !== '_sectalk-verification.' + domain || packet.readUInt16BE(offset + 1) !== 16) return
  requests++
  const header = Buffer.alloc(12)
  packet.copy(header, 0, 0, 2)
  header.writeUInt16BE(0x8180, 2)
  header.writeUInt16BE(1, 4)
  header.writeUInt16BE(1, 6)
  const chunks = [txt.slice(0, 12), txt.slice(12)].map(value => Buffer.concat([Buffer.from([Buffer.byteLength(value)]), Buffer.from(value)]))
  const payload = Buffer.concat(chunks)
  const answer = Buffer.alloc(12)
  answer.writeUInt16BE(0xc00c, 0)
  answer.writeUInt16BE(16, 2)
  answer.writeUInt16BE(1, 4)
  answer.writeUInt32BE(0, 6)
  answer.writeUInt16BE(payload.length, 10)
  dns.send(Buffer.concat([header, packet.subarray(12, offset + 5), answer, payload]), sender.port, sender.address)
})
await new Promise((resolve, reject) => dns.once('error', reject).bind(35443, '127.0.0.1', resolve))

const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
const nav = page => page.getByRole('navigation', { name: 'SecTalk features' })
const button = (scope, name) => scope.getByRole('button', { name, exact: true })
async function open(person) {
  const page = await browser.newPage()
  await page.goto(new URL('/#account', app).href, { waitUntil: 'domcontentloaded' })
  await page.getByLabel('Email address', { exact: true }).fill(person.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await button(nav(page), 'Workspaces').click()
  return page
}

try {
  const a = await open(owner)
  await button(a, 'Organization settings').click()
  const org = a.getByRole('region', { name: 'Organization settings' })
  await org.getByText(/Operator-attested deployment region/).waitFor()
  await org.getByText('local-qa', { exact: true }).waitFor()
  await org.getByLabel('Organization name').fill('Updated Organization')
  await org.getByLabel('Brand accent').selectOption('violet')
  await org.getByLabel('Default room retirement retention (days)').fill('17')
  await org.getByLabel('Preferred data region').selectOption('eu')
  await button(org, 'Save organization settings').click()
  await org.getByText('Organization settings saved.', { exact: true }).waitFor()
  const heading = a.getByRole('heading', { name: 'Updated Organization', exact: true })
  await heading.waitFor()
  assert.equal(await heading.locator('span').evaluate(element => getComputedStyle(element).backgroundColor), 'rgb(117, 83, 168)')
  const retention = data(await owner.client.rpc('st_v6_room_retirement', { p_room: room }))
  assert.equal(retention.retention_days, 17)
  await org.getByText(/^Effective workspace default: 17 days/).waitFor()
  assert.equal(data(await owner.client.rpc('st_v7_org_settings', { p_workspace: workspace })).region, 'eu')
  await a.reload({ waitUntil: 'domcontentloaded' })
  await button(nav(a), 'Workspaces').click()
  await button(a, 'Organization settings').click()
  await org.getByText(/^Effective workspace default: 17 days/).waitFor()
  await org.getByText('local-qa', { exact: true }).waitFor()
  assert.equal(await org.getByLabel('Preferred data region').inputValue(), 'eu')
  assert.equal((await member.client.rpc('st_v7_org_settings', { p_workspace: workspace })).error?.code, '42501')
  const b = await open(member)
  await b.getByRole('heading', { name: 'Updated Organization', exact: true }).waitFor()
  assert.equal(await button(b, 'Organization settings').count(), 0)

  await org.getByLabel('Domain name', { exact: true }).fill(domain)
  await button(org, 'Start DNS verification').click()
  await org.getByText('DNS challenge ready.', { exact: true }).waitFor()
  const key = org.locator('code').filter({ hasText: /^sectalk=/ })
  txt = await key.textContent()
  assert.match(txt, /^sectalk=[a-f0-9-]{36}$/)
  const expected = txt
  txt = 'wrong synthetic value'
  const check = button(org, 'Check DNS record')
  await check.click()
  await org.getByRole('alert').filter({ hasText: 'The required TXT value is not published yet.' }).waitFor()
  txt = expected
  await check.click()
  await org.getByText('Domain verified.', { exact: true }).waitFor()
  assert.equal(requests, 2)
  const verified = data(await owner.client.rpc('st_v7_org_settings', { p_workspace: workspace })).domains[0]
  assert.equal(verified.domain, domain)
  assert.ok(verified.verifiedAt)
  assert.equal(verified.challenge, null)
  await button(org, 'Remove domain').click()
  await org.getByText('Domain removed.', { exact: true }).waitFor()
  assert.deepEqual(data(await owner.client.rpc('st_v7_org_settings', { p_workspace: workspace })).domains, [])
  console.log('Passed native owner branding, member read-only branding, live retirement policy, region preference and real TXT verification.')
} finally {
  dns.close()
  await browser.close()
  await Promise.allSettled([owner, member].map(person => admin.auth.admin.deleteUser(person.id)))
}
