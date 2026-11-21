// Run against an isolated loopback Web build and Supabase fixture.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.hostname, '127.0.0.1')
const { SECTALK_STORAGE_TEST_PUBLIC_KEY: key, SECTALK_STORAGE_TEST_SERVICE_KEY: serviceKey } = process.env
assert.ok(key && serviceKey)
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(supabase.href, serviceKey, options)
const password = randomUUID() + '1!Q'
const fixture = randomUUID().slice(0, 8)
const users = []
let browser

function data(result) {
  if (result.error) throw result.error
  return result.data
}

async function account(role) {
  const name = 'Call history ' + role
  const handle = 'call_' + role + '_' + fixture
  const email = handle + '@example.org'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  users.push(user.id)
  const client = createClient(supabase.href, key, options)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: name }))
  return { client, name, handle, email }
}

async function openChat(person, peer) {
  const page = await browser.newPage({ locale: 'en-US' })
  await page.routeWebSocket(/\/realtime\/v1\/websocket/, socket => socket.close({ code: 1011 }))
  await page.goto(app.href)
  await page.getByLabel('Email address', { exact: true }).fill(person.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await page.locator('.chat-item').filter({ hasText: peer.name }).click()
  return page
}

try {
  const caller = await account('caller')
  const callee = await account('callee')
  const chat = data(await caller.client.rpc('st_request', { p_handle: callee.handle }))
  data(await callee.client.rpc('st_respond', { p_chat: chat, p_accept: true }))
  const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
  browser = await chromium.launch({
    executablePath: process.env.SECTALK_TEST_BROWSER,
    args: ['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream'],
  })
  // Simulate a missed video call to exercise the normal Call back control.
  const missed = data(await caller.client.rpc('st_place_call', { p_chat: chat, p_video: true }))
  data(await admin.from('st_calls').update({ expires_at: new Date(Date.now() - 1000).toISOString() }).eq('id', missed))
  const [outgoing, incoming] = await Promise.all([openChat(caller, callee), openChat(callee, caller)])
  const calls = page => page.getByRole('navigation', { name: 'SecTalk features' }).getByRole('button', { name: 'Calls', exact: true })
  await Promise.all([calls(outgoing).click(), calls(incoming).click()])
  await incoming.getByRole('group', { name: 'Call history' }).getByRole('button', { name: 'Missed', exact: true }).click()
  const missedRow = incoming.locator('.report-row').filter({ hasText: 'Incoming video' })
  await missedRow.getByRole('button', { name: 'Call back ' + caller.name, exact: true }).click()
  await incoming.getByRole('group', { name: 'Call history' }).getByRole('button', { name: 'Video', exact: true }).click()
  const callback = incoming.locator('.report-row').filter({ hasText: 'Outgoing video' })
  await callback.getByText('Ringing', { exact: true }).waitFor()
  const ringing = outgoing.getByRole('region', { name: 'Video call', exact: true })
  await ringing.getByRole('button', { name: 'Decline', exact: true }).click()
  await callback.getByText('Declined', { exact: true }).waitFor({ timeout: 10000 })
  const incomingCallback = outgoing.locator('.report-row').filter({ hasText: 'Incoming video' })
  await incomingCallback.getByText('Declined', { exact: true }).waitFor({ timeout: 10000 })
  console.log('Both call history views showed the video callback outcome with Realtime disconnected.')
} finally {
  await browser?.close()
  for (const id of users) await admin.auth.admin.deleteUser(id)
}
