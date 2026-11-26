// Run against the disposable local app and Supabase, using Chromium fake media.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const database = new URL(process.env.SECTALK_STORAGE_TEST_URL)
for (const url of [app, database]) assert.equal(url.hostname, '127.0.0.1')

const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const browser = await chromium.launch({
  executablePath: process.env.SECTALK_TEST_BROWSER,
  args: ['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream'],
})
const auth = { persistSession: false, autoRefreshToken: false }
const admin = createClient(database.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, { auth })
const suffix = randomUUID().slice(0, 8)
const password = randomUUID() + '!Qa9'
const pageErrors = []

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

async function account(role) {
  const name = 'Messenger QA ' + role
  const handle = 'three_' + role.toLowerCase() + '_' + suffix
  const email = handle + '@example.org'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(database.origin, process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY, { auth })
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: name }))
  return { name, email, handle, client, id: user.id }
}

function navigation(page) {
  return page.getByRole('navigation', { name: 'SecTalk features' })
}

async function open(person) {
  const context = await browser.newContext({
    viewport: { width: 1536, height: 940 },
    locale: 'en-US',
    permissions: ['camera', 'microphone'],
  })
  const page = await context.newPage()
  page.on('pageerror', error => pageErrors.push(error.message))
  await page.addInitScript(() => {
    const Peer = window.RTCPeerConnection
    window.fixturePeers = []
    window.RTCPeerConnection = class extends Peer {
      constructor(config) {
        // Verify actual local media transport without contacting a public ICE server.
        super({ ...config, iceServers: [], iceTransportPolicy: 'all' })
        window.fixturePeers.push(this)
      }
    }
  })
  await page.goto(new URL('/#account', app).href)
  await page.getByLabel('Email address', { exact: true }).fill(person.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  const response = page.waitForResponse(item => item.url() === new URL('/api/auth/sign-in', app).href)
  await page.locator('button.submit-auth').click()
  assert.equal((await response).status(), 200, 'Password sign-in for ' + person.name)
  const acceptRules = page.getByRole('button', { name: 'Accept and continue', exact: true })
  await navigation(page).or(acceptRules).first().waitFor()
  if (await acceptRules.isVisible()) {
    await page.getByRole('checkbox', { name: 'I accept the SecTalk Community Rules.' }).check()
    await acceptRules.click()
  }
  await navigation(page).waitFor()
  return page
}

async function openChat(page, person) {
  await page.locator('.chat-item').filter({ hasText: person.name }).click()
  await page.getByRole('textbox', { name: 'Write a message' }).waitFor()
}

async function send(page, text) {
  await page.getByRole('textbox', { name: 'Write a message' }).fill(text)
  await page.getByRole('button', { name: 'Send message', exact: true }).click()
  await page.getByText(text, { exact: true }).waitFor()
}

async function verifyMedia(page, kinds) {
  await page.waitForFunction(async media => {
    const peer = window.fixturePeers.findLast(item => item.connectionState === 'connected')
    if (!peer) return false
    const stats = [...(await peer.getStats()).values()]
    return media.every(kind => stats.some(row => row.type === 'inbound-rtp' && row.kind === kind && row.bytesReceived > 0) &&
      stats.some(row => row.type === 'outbound-rtp' && row.kind === kind && row.bytesSent > 0))
  }, kinds)
}

async function call(from, to, outsider, mode) {
  await from.getByRole('button', { name: 'Start ' + mode.toLowerCase() + ' call', exact: true }).click()
  const incoming = to.getByRole('region', { name: mode + ' call', exact: true })
  const outgoing = from.getByRole('region', { name: mode + ' call', exact: true })
  await incoming.getByText(mode + ' · Incoming call', { exact: true }).waitFor()
  assert.equal(await outsider.getByRole('button', { name: 'Answer', exact: true }).count(), 0)
  await incoming.getByRole('button', { name: 'Answer', exact: true }).click()
  const kinds = mode === 'Video' ? ['audio', 'video'] : ['audio']
  await Promise.all([verifyMedia(from, kinds), verifyMedia(to, kinds)])
  await outgoing.getByRole('button', { name: 'Mute microphone', exact: true }).click()
  await outgoing.getByRole('button', { name: 'Unmute', exact: true }).click()
  if (mode === 'Video') {
    await outgoing.getByRole('button', { name: 'Turn camera off', exact: true }).click()
    await outgoing.getByRole('button', { name: 'Turn camera on', exact: true }).click()
  }
  await outgoing.getByRole('button', { name: 'Hang up', exact: true }).click()
  await Promise.all([incoming.waitFor({ state: 'hidden' }), outgoing.waitFor({ state: 'hidden' })])
}

try {
  const [first, second, third] = await Promise.all([account('Avery'), account('Blair'), account('Casey')])
  const firstChat = data(await first.client.rpc('st_request', { p_handle: second.handle }))
  data(await second.client.rpc('st_respond', { p_chat: firstChat, p_accept: true }))
  const secondChat = data(await second.client.rpc('st_request', { p_handle: third.handle }))
  data(await third.client.rpc('st_respond', { p_chat: secondChat, p_accept: true }))
  const [avery, blair, casey] = await Promise.all([open(first), open(second), open(third)])
  await Promise.all([openChat(avery, second), openChat(blair, first), openChat(casey, second)])
  const firstMessage = 'Private first thread ' + suffix
  await send(avery, firstMessage)
  await blair.getByText(firstMessage, { exact: true }).waitFor()
  assert.equal(await casey.getByText(firstMessage, { exact: true }).count(), 0)
  assert.deepEqual(data(await third.client.from('st_messages').select('id').eq('chat_id', firstChat)), [])
  const answer = 'Reply from the second person ' + suffix
  await send(blair, answer)
  await avery.getByText(answer, { exact: true }).waitFor()
  console.log('Three real password logins and bidirectional direct messaging passed. The third user could not read the first thread.')

  await call(avery, blair, casey, 'Audio')
  console.log('Two browser audio call passed with media in both directions, mute, and hang-up.')
  await openChat(blair, third)
  const secondMessage = 'Private second thread ' + suffix
  await send(casey, secondMessage)
  await blair.getByText(secondMessage, { exact: true }).waitFor()
  assert.equal(await avery.getByText(secondMessage, { exact: true }).count(), 0)
  await call(casey, blair, avery, 'Video')
  console.log('Two browser video call passed with audio and video in both directions, camera toggle, and hang-up.')

  await blair.locator('.message').filter({ hasText: secondMessage })
    .getByRole('button', { name: 'Report message', exact: true }).click()
  const report = blair.getByRole('dialog', { name: 'Report this message', exact: true })
  await report.getByLabel('Report category', { exact: true }).selectOption('harassment')
  await report.getByLabel(/Details/).fill('Synthetic messenger review ' + suffix)
  await report.getByRole('button', { name: 'Submit report', exact: true }).click()
  const receipt = blair.getByRole('status').filter({ hasText: 'Report submitted. Ticket ' })
  await receipt.waitFor()
  const ticket = (await receipt.textContent()).match(/Ticket ([a-f0-9-]{36})\./)?.[1]
  assert.ok(ticket, 'The app returned a native report ticket')
  await navigation(blair).getByRole('button', { name: 'Safety', exact: true }).click()
  await blair.getByRole('group', { name: 'My report scopes', exact: true }).getByRole('button', { name: 'Chat reports', exact: true }).click()
  await blair.getByLabel('Filter recent reports by ticket number', { exact: true }).fill(ticket)
  await blair.getByRole('region', { name: 'My chat reports', exact: true }).getByRole('button', { name: /Harassment/ }).click()
  await blair.getByRole('heading', { name: 'Report timeline', exact: true }).waitFor()
  await blair.getByText('Report received', { exact: true }).waitFor()
  assert.deepEqual(data(await third.client.rpc('st_v5_report_timeline', { p_report: ticket })), [])
  assert.deepEqual(data(await first.client.rpc('st_v5_report_timeline', { p_report: ticket })), [])
  console.log('Report creation, ticket lookup, receipt timeline and privacy passed.')

  const sections = ['Inbox', 'Friends', 'Calls', 'Safety', 'Group chats', 'Search', 'Notifications',
    'Workspaces', 'Rooms', 'Tasks', 'Calendar', 'Meetings', 'Files', 'Billing', 'Profile']
  for (const name of sections) {
    const button = navigation(casey).getByRole('button', { name, exact: true })
    await button.click()
    await button.and(casey.locator('[aria-current="page"]')).waitFor()
  }
  await casey.getByRole('button', { name: 'Sign out', exact: true }).click()
  await casey.getByRole('heading', { name: 'Sign in to SecTalk', exact: true }).waitFor()
  assert.deepEqual(pageErrors, [], 'No unhandled page errors')
  console.log('All 15 desktop feature tabs opened, and sign-out passed.')
} finally {
  await browser.close()
}
