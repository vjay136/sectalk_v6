import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
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
const keyword = 'Glyphword' + suffix
const password = randomUUID() + '1!Q'

function data(result) {
  assert.equal(result.error, null, result.error?.message)
  return result.data
}

async function account(role) {
  const handle = 'fts_' + role + '_' + suffix
  const email = handle + '@example.org'
  data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(supabase.origin, publicKey, options)
  const { session } = data(await client.auth.signInWithPassword({ email, password }))
  const name = role === 'host' ? keyword + ' Host' : 'Search tester ' + role
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: name }))
  return { client, handle, email, name, token: session.access_token }
}

const [host, peer, outsider] = await Promise.all([account('host'), account('peer'), account('other')])
const workspace = data(await host.client.rpc('st_v2_create_workspace', { p_name: 'Search ' + suffix }))
const room = randomUUID()
const roomName = keyword + ' discussion'
data(await host.client.rpc('st_v6_room_create', {
  p_id: room, p_workspace: workspace, p_name: roomName, p_kind: 'private', p_template: 'blank',
}))
const chat = data(await host.client.rpc('st_request', { p_handle: peer.handle }))
data(await peer.client.rpc('st_respond', { p_chat: chat, p_accept: true }))
data(await host.client.rpc('st_send', { p_chat: chat, p_id: randomUUID(), p_body: keyword + ' private, conversation' }))
const file = randomUUID()
const filename = keyword + '.txt'
const bytes = Buffer.from('Isolated search fixture.')
data(await host.client.rpc('st_v5_stage_file', { p_chat: chat, p_id: file, p_filename: filename, p_bytes: bytes.length }))
const authorization = { Authorization: 'Bearer ' + host.token }
assert.equal((await fetch(new URL('/api/files/upload?file=' + file, app), {
  method: 'POST', headers: { ...authorization, 'Content-Type': 'text/plain' }, body: bytes,
})).status, 200)
assert.equal((await fetch(new URL('/api/files/publish', app), {
  method: 'POST', headers: { ...authorization, 'Content-Type': 'application/json' },
  body: JSON.stringify({ file, caption: '', mime: 'text/plain' }),
})).status, 200)

const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
try {
  async function openSearch(person) {
    const page = await browser.newPage()
    await page.goto(new URL('/#account', app).href)
    await page.getByLabel('Email address', { exact: true }).fill(person.email)
    await page.getByLabel('Password', { exact: true }).fill(password)
    await page.locator('button.submit-auth').click()
    await page.getByRole('navigation', { name: 'SecTalk features' }).getByRole('button', { name: 'Search', exact: true }).click()
    return page
  }

  async function search(page, category, query) {
    await page.getByRole('group', { name: 'Search categories' }).getByRole('button', { name: category, exact: true }).click()
    await page.getByLabel('Search terms').fill(query)
    const result = page.waitForResponse(response => response.url().endsWith('/rpc/st_v6_search'))
    await page.getByRole('button', { name: 'Search SecTalk', exact: true }).last().click()
    assert.equal((await result).status(), 200)
  }

  const [hostPage, peerPage, outsiderPage] = await Promise.all([openSearch(host), openSearch(peer), openSearch(outsider)])
  await search(hostPage, 'Rooms', keyword.slice(2))
  await hostPage.getByRole('heading', { name: roomName, exact: true }).waitFor()
  await hostPage.getByRole('button', { name: 'Open room', exact: true }).click()
  await hostPage.getByRole('region', { name: 'Room directory' }).getByRole('button', { name: new RegExp(roomName) }).waitFor()
  await search(peerPage, 'Direct messages', 'private conversation')
  await peerPage.getByText(keyword + ' private, conversation', { exact: true }).waitFor()
  await search(peerPage, 'Files', keyword.slice(2))
  await peerPage.getByRole('heading', { name: filename, exact: true }).waitFor()
  await search(peerPage, 'People', host.name)
  await peerPage.getByRole('article').getByText('@' + host.handle, { exact: true }).waitFor()
  await search(outsiderPage, 'All content', keyword)
  await outsiderPage.getByText('No matching items.', { exact: true }).waitFor()
  console.log('Passed token and fragment search, categorized room/file/person results, navigation and outsider denial.')
} finally {
  await browser.close()
}
