// Native Edge search and authenticator-gated queue controls on disposable local services.
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
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const password = randomUUID() + '1!Q'
const suffix = randomUUID().slice(0, 8)

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

async function account(prefix) {
  const handle = prefix + '_' + suffix
  const email = handle + '@example.invalid'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(supabase.origin, publicKey, options)
  const { session } = data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: handle }))
  assert.match(user.id, /^[a-f0-9-]{36}$/)
  return { id: user.id, session, client, email, handle }
}

function sql(statement) {
  return execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-v', 'ON_ERROR_STOP=1',
    '-At', '-U', 'postgres', '-d', 'postgres'], { input: statement, encoding: 'utf8', windowsHide: true }).trim()
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

const [author, peer, outsider, operator] = await Promise.all([
  account('sqi_author'), account('sqi_peer'), account('sqi_other'), account('sqi_operator'),
])
sql("insert into sectalk_private.staff(user_id) values ('" + operator.id + "');"
  + "insert into sectalk_private.st_v6_queue_operators(account_id) values ('" + operator.id + "');")
assert.equal((await peer.client.rpc('st_v7_search_index_operation', { p_action: 'status' })).error?.code, '42501')
assert.equal((await operator.client.rpc('st_v7_search_index_operation', { p_action: 'rebuild' })).error?.code, '42501')
const chat = data(await author.client.rpc('st_request', { p_handle: peer.handle }))
data(await peer.client.rpc('st_respond', { p_chat: chat, p_accept: true }))
sql('select sectalk_private.st_v7_search_work(500) from generate_series(1,22);')
const id = randomUUID()
const first = 'Queue fixture: violet' + suffix + ', lantern.'
const next = 'Queue fixture: amber' + suffix + ', window.'
data(await author.client.rpc('st_send', { p_chat: chat, p_id: id, p_body: first }))

const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
try {
  const nav = page => page.getByRole('navigation', { name: 'SecTalk features' })
  async function signIn(person, section) {
    const page = await browser.newPage({ locale: 'en-US' })
    await page.goto(new URL('/#account', app).href)
    await page.getByLabel('Email address', { exact: true }).fill(person.email)
    await page.getByLabel('Password', { exact: true }).fill(password)
    await page.locator('button.submit-auth').click()
    await nav(page).getByRole('button', { name: section, exact: true }).click()
    return page
  }
  const [operatorPage, peerPage, outsiderPage] = await Promise.all([
    signIn(operator, 'Safety'), signIn(peer, 'Search'), signIn(outsider, 'Search'),
  ])
  await operatorPage.getByRole('button', { name: 'Queue operations', exact: true }).click()
  await operatorPage.getByRole('heading', { name: 'Verify staff access' }).waitFor()
  await operatorPage.getByRole('button', { name: 'Set up authenticator', exact: true }).click()
  const secret = (await operatorPage.locator('.mfa-setup code').textContent()).trim()
  await operatorPage.getByLabel('Authenticator code', { exact: true }).fill(totp(secret))
  await operatorPage.getByRole('button', { name: 'Verify access', exact: true }).click()
  const queue = operatorPage.getByRole('region', { name: 'Queue operations' })
  await queue.getByRole('button', { name: 'Managed search index', exact: true }).click()
  const index = queue.getByRole('region', { name: 'Managed search index', exact: true })

  async function operate(label, action) {
    const actionResponse = operatorPage.waitForResponse(response =>
      response.url().endsWith('/rpc/st_v7_search_index_operation') &&
      response.request().postDataJSON().p_action === action)
    await index.getByRole('button', { name: label, exact: true }).click()
    const response = await actionResponse
    assert.equal(response.status(), 200)
    const snapshot = await response.json()
    assert.deepEqual(Object.keys(snapshot).sort(), ['finished_at', 'mode', 'pending', 'processed', 'scanned'])
    return snapshot
  }
  assert.equal((await operate('Backfill missing entries', 'backfill')).mode, 'backfill')
  await index.getByText(/Backfill in progress/).waitFor()
  const worker = await operate('Process search batch', 'process')
  assert.ok(worker.processed >= 0 && worker.processed <= 200 && worker.scanned >= 0 && worker.scanned <= 200)
  await index.getByText(/Processed [0-9]+ queued updates and scanned [0-9]+ sources/).waitFor()
  sql('select sectalk_private.st_v7_search_work(500) from generate_series(1,22);')
  assert.equal((await operate('Refresh search index status', 'status')).mode, null)
  assert.equal((await operate('Rebuild managed search', 'rebuild')).mode, 'rebuild')
  await index.getByText(/Rebuild in progress/).waitFor()
  await operate('Process search batch', 'process')
  sql('select sectalk_private.st_v7_search_work(500) from generate_series(1,22);')
  assert.equal(sql("select count(*) from sectalk_private.st_v7_search_document where kind='direct' and object_id='" + id + "';"), '1')

  async function search(page, terms, text) {
    await page.getByRole('group', { name: 'Search categories' }).getByRole('button', { name: 'Direct messages', exact: true }).click()
    await page.getByLabel('Search terms').fill(terms)
    const response = page.waitForResponse(result => result.url().endsWith('/rpc/st_v6_search'))
    await page.getByRole('button', { name: 'Search SecTalk', exact: true }).last().click()
    assert.equal((await response).status(), 200)
    await page.getByText(text, { exact: true }).waitFor()
  }
  await search(peerPage, 'violet' + suffix + ' lantern', first)
  await search(outsiderPage, 'violet' + suffix + ' lantern', 'No matching items.')
  data(await author.client.rpc('st_v2_edit_message', { p_message: id, p_body: next }))
  await search(peerPage, 'violet' + suffix + ' lantern', 'No matching items.')
  await search(peerPage, 'amber' + suffix + ' window', next)
  data(await author.client.rpc('st_v5_message_action', { p_message: id, p_action: 'revoke' }))
  await search(peerPage, 'amber' + suffix + ' window', 'No matching items.')
  console.log('PASS: native operator MFA, backfill and rebuild controls, bounded processing, indexed phrase search, live edits, revocation and outsider denial')
} finally {
  await browser.close()
}
