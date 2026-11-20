import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { setTimeout } from 'node:timers/promises'
import { createClient } from '@supabase/supabase-js'
import { verifyStaffPanel } from './workspace-admin-fixture.mjs'

const origin = new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
const app = new URL(process.env.SECTALK_STORAGE_TEST_APP).origin
assert.equal(origin, 'http://127.0.0.1:55321')
assert.equal(new URL(app).hostname, '127.0.0.1')
const key = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const service = createClient(origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const suffix = randomUUID().slice(0,8)
const password = randomUUID() + '!1A'
const users = []
let browser
function data(result) {
  if (result.error) throw result.error
  return result.data
}
function sql(statement) {
  return execFileSync('docker', ['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'], { input: statement, encoding: 'utf8', windowsHide: true }).trim()
}
async function account(role) {
  const handle = 'dqa_' + role + '_' + suffix
  const name = 'Device QA ' + role + ' ' + suffix
  const email = handle + '@example.invalid'
  const { user } = data(await service.auth.admin.createUser({ email, password, email_confirm: true }))
  users.push(user.id)
  const client = createClient(origin, key, options)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: name }))
  return { id: user.id, email, handle, name, client }
}
async function until(check, duration = 30000) {
  const deadline = Date.now() + duration
  while (Date.now() < deadline) {
    const result = await check()
    if (result) return result
    await setTimeout(200)
  }
  throw new Error('Timed out waiting for the device command')
}
const nav = page => page.getByRole('navigation', { name: 'SecTalk features' })
const trust = page => page.getByRole('region', { name: 'Device trust', exact: true })
const current = page => trust(page).getByRole('article').filter({ hasText: 'This registered device' })
async function submitLogin(page, account) {
  await page.getByLabel('Email address', { exact: true }).fill(account.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
}
async function login(page, account) {
  await submitLogin(page,account)
  await nav(page).waitFor()
}
async function registry(page) {
  await nav(page).getByRole('button', { name: 'Profile', exact: true }).click()
  await page.getByRole('button', { name: 'Devices and sessions', exact: true }).click()
  await trust(page).waitFor()
}
async function register(page) {
  await trust(page).getByRole('button', { name: 'Register this device', exact: true }).click()
  await current(page).getByText('Known', { exact: true }).waitFor()
}
async function inspect(page, accountId) {
  return page.evaluate(id => new Promise((resolve, reject) => {
    const request = indexedDB.open('sectalk-device-identity')
    request.onerror = () => reject(request.error)
    request.onsuccess = () => {
      const database = request.result
      const transaction = database.transaction(['identities','command-receipts'])
      const identity = transaction.objectStore('identities').get(id)
      const receipts = transaction.objectStore('command-receipts').count()
      transaction.oncomplete = () => {
        database.close()
        resolve({ id: identity.result?.id ?? null, protectedKeys: Boolean(identity.result?.signing.privateKey &&
          identity.result?.agreement.privateKey), receipts: receipts.result })
      }
      transaction.onerror = () => reject(transaction.error)
    }
  }), accountId)
}
function browserToken(page) {
  return page.evaluate(() => {
    const sessionKey = Object.keys(localStorage).find(key => /^sb-.+-auth-token$/.test(key))
    return JSON.parse(localStorage.getItem(sessionKey)).access_token
  })
}
async function clientFor(page) {
  const token = await browserToken(page)
  return createClient(origin, key, { ...options, global: { headers: { Authorization: 'Bearer ' + token } } })
}
async function tryRebind(page, owner, replacement = null) {
  return page.evaluate(async ({ owner, origin, key, token, replacement }) => {
    const local = await new Promise((resolve, reject) => {
      const request = indexedDB.open('sectalk-device-identity')
      request.onerror = () => reject(request.error)
      request.onsuccess = () => {
        const database = request.result
        const transaction = database.transaction('identities')
        const identity = transaction.objectStore('identities').get(owner)
        transaction.oncomplete = () => { database.close();resolve(identity.result) }
        transaction.onerror = () => reject(transaction.error)
      }
    })
    const base64url = buffer => btoa(String.fromCharCode(...new Uint8Array(buffer)))
      .replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'')
    const [signing,agreement] = await Promise.all([local.signing,local.agreement].map(pair =>
      crypto.subtle.exportKey('raw',pair.publicKey).then(base64url)))
    const device = replacement ?? local.id
    const headers = { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' }
    const begin = await fetch(origin + '/rest/v1/rpc/st_v7_begin_device_bundle', {
      method: 'POST', headers: { ...headers, apikey: key },
      body: JSON.stringify({ p_device: device, p_signing: signing, p_agreement: agreement }),
    })
    if (!begin.ok) throw new Error('Expected challenge issuance before testing the native binding guard')
    const challenge = await begin.json()
    const sign = transcript => crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},local.signing.privateKey,
      new TextEncoder().encode(JSON.stringify(transcript))).then(base64url)
    const [signature,binding] = await Promise.all([
      sign(['sectalk-device-bundle-v1',owner,device,signing,agreement]),
      sign(['sectalk-device-session-v1',owner,device,challenge.session,challenge.challenge,challenge.nonce,signing,agreement]),
    ])
    return (await fetch('/api/account/devices/bundle', { method: 'POST', headers,
      body: JSON.stringify({ challenge: challenge.challenge, signature, binding }),
    })).status
  }, { owner, origin, key, token: await browserToken(page), replacement })
}
async function confirm(card, label) {
  await card.getByRole('button', { name: label, exact: true }).click()
  await card.getByLabel('Case reference and reason', { exact: true }).fill('QA-203 verified device action ' + label)
  const request = card.page().waitForResponse(response => response.url().endsWith('/rpc/st_v7_operator_device_action'))
  await card.getByRole('button', { name: 'Confirm ' + label.toLowerCase(), exact: true }).click()
  const response = await request
  assert.equal(response.ok(), true, response.ok() ? '' : await response.text())
  assert.equal(await response.json(), true)
}

try {
  const [operator,target,protectedStaff] = await Promise.all(['operator','target','staff'].map(account))
  sql("insert into sectalk_private.st_v7_account_operators values('" + operator.id + "','operator');"
    + "insert into sectalk_private.staff values('" + protectedStaff.id + "');")
  const inventory = client => client.rpc('st_v7_operator_device_inventory', { p_owner: target.id })
  const status = async device => data(await target.client.rpc('st_v7_list_device_commands')).find(row => row.device === device)
  assert.equal((await inventory(operator.client)).error?.code, '42501')
  assert.equal((await inventory(target.client)).error?.code, '42501')
  browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
  const [controller,devicePage,sibling] = await Promise.all([browser.newPage(),browser.newPage(),browser.newPage()])
  await Promise.all([controller,devicePage,sibling].map(page => page.goto(app)))
  await Promise.all([login(controller,operator),login(devicePage,target),login(sibling,target)])
  await Promise.all([registry(devicePage),registry(sibling)])
  await register(devicePage)
  await register(sibling)
  const [first,second] = await Promise.all([inspect(devicePage,target.id),inspect(sibling,target.id)])
  assert.ok(first.protectedKeys && second.protectedKeys && first.id !== second.id)
  await current(devicePage).getByRole('button', { name: 'Trust device', exact: true }).click()
  await current(devicePage).getByLabel('Current password', { exact: true }).fill(password)
  await current(devicePage).getByRole('button', { name: 'Confirm trust device', exact: true }).click()
  await current(devicePage).getByText('Trusted', { exact: true }).waitFor()
  const stale = await clientFor(devicePage)
  const safe = await clientFor(sibling)

  await nav(controller).getByRole('button', { name: 'Safety', exact: true }).click()
  await controller.getByRole('group', { name: 'Safety center sections' }).getByRole('button', { name: 'Account administration', exact: true }).click()
  await verifyStaffPanel(controller)
  const accountPanel = controller.getByRole('region', { name: 'Account administration', exact: true })
  await accountPanel.getByLabel('Name or handle', { exact: true }).fill(target.handle)
  await accountPanel.getByRole('button', { name: 'Search accounts', exact: true }).click()
  await accountPanel.getByRole('button', { name: target.name + ' (@' + target.handle + ')', exact: true }).click()
  const devicePanel = controller.getByRole('region', { name: 'Operator device inventory' })
  await devicePanel.getByText('Registered devices', { exact: true }).click()
  const card = devicePanel.getByRole('article').filter({ has: controller.getByRole('heading', { name: 'Device ' + first.id.slice(0,8), exact: true }) })
  const secondCard = devicePanel.getByRole('article').filter({ has: controller.getByRole('heading', { name: 'Device ' + second.id.slice(0,8), exact: true }) })
  await secondCard.getByText('known', { exact: true }).waitFor()
  assert.equal(await secondCard.getByRole('button', { name: 'Mark as managed', exact: true }).count(), 0)
  const adminClient = await clientFor(controller)
  assert.equal((await adminClient.rpc('st_v7_operator_device_inventory', { p_owner: protectedStaff.id })).error?.code, '42501')
  assert.equal((await adminClient.rpc('st_v7_operator_device_action', {
    p_owner: protectedStaff.id, p_device: first.id, p_action: 'wipe', p_reason: 'QA-203 protected target attempt',
  })).error?.code, '42501')
  const observed = data(await inventory(adminClient))
  assert.equal(observed.length, 2)
  assert.ok(observed.every(row => !['signing_key','agreement_key','receipt'].some(field => field in row)))

  await confirm(card, 'Mark as managed')
  await card.getByText('managed', { exact: true }).waitFor()
  await confirm(card, 'Clear managed flag')
  await card.getByText('trusted', { exact: true }).waitFor()
  await confirm(card, 'Revoke device sessions')
  await devicePage.getByLabel('Email address', { exact: true }).waitFor()
  await card.getByText(/revoke · acknowledged/).waitFor()
  assert.ok((await inspect(devicePage,target.id)).protectedKeys)
  assert.equal(data(await stale.rpc('st_v7_current_session_valid')), false)
  assert.ok((await stale.from('st_profiles').select('id').eq('id',target.id)).error)
  assert.equal(data(await safe.rpc('st_v7_current_session_valid')), true)
  await login(devicePage,target)
  await registry(devicePage)
  const registerAgain = trust(devicePage).getByRole('button', { name: 'Register this device', exact: true })
  const rebound = current(devicePage).getByText('Trusted', { exact: true })
  await registerAgain.or(rebound).first().waitFor()
  if (await registerAgain.isVisible()) await registerAgain.click()
  await rebound.waitFor()

  await devicePage.context().setOffline(true)
  await confirm(card, 'Wipe local device keys')
  await card.getByText(/wipe · pending/).waitFor()
  assert.ok((await inspect(devicePage,target.id)).protectedKeys)
  const pending = await status(first.id)
  assert.equal(pending.operator_wipe_pending, true)
  await registry(sibling)
  await trust(sibling).getByText('An account operator requested this wipe. Contact support to cancel it before delivery.', { exact: true }).waitFor()
  assert.equal(data(await target.client.rpc('st_v7_issue_device_command', {
    p_device: first.id, p_action: 'cancel', p_command: pending.command,
  })), false)
  await confirm(card, 'Cancel pending wipe')
  assert.equal((await status(first.id)).locked, false)
  assert.ok((await inspect(devicePage,target.id)).protectedKeys)
  await confirm(card, 'Wipe local device keys')
  await card.getByText(/wipe · pending/).waitFor()

  const commandEndpoint = '**/api/account/devices/commands'
  await devicePage.route(commandEndpoint, route => route.request().postDataJSON()?.mode === 'ack' ? route.abort() : route.continue())
  await devicePage.context().setOffline(false)
  await card.getByText(/wipe · delivered/).waitFor()
  await until(async () => {
    const result = await inspect(devicePage,target.id)
    return !result.protectedKeys && result.receipts === 1
  })
  await devicePage.unroute(commandEndpoint)
  await devicePage.reload()
  await card.getByText(/wipe · acknowledged/).waitFor()
  await until(async () => (await inspect(devicePage,target.id)).receipts === 0)
  assert.deepEqual(await inspect(devicePage,target.id), { id: null, protectedKeys: false, receipts: 0 })
  assert.deepEqual(await inspect(sibling,target.id), second)
  assert.equal(data(await safe.rpc('st_v7_current_session_valid')), true)
  await card.getByText('Recent operator actions', { exact: true }).click()
  await card.getByText('QA-203 verified device action Cancel pending wipe', { exact: true }).waitFor()
  assert.equal(sql("select count(*) from sectalk_private.st_v7_operator_device_audit where owner='" + target.id
    + "' and actor='" + operator.id + "' and device='" + first.id + "';"), '6')
  assert.ok(Number(sql("select count(*) from sectalk_private.st_v7_account_admin_audit where target='" + target.id
    + "' and actor='" + operator.id + "' and action='session_revoked';")) >= 2)
  const media = new URL('/api/ice?call=' + randomUUID(),app)
  const mediaAuth = { headers: { Authorization: 'Bearer ' + await browserToken(sibling) } }
  assert.notEqual((await fetch(media,mediaAuth)).status,401)
  await confirm(secondCard, 'Block registered device')
  await secondCard.getByText('blocked', { exact: true }).waitFor()
  await sibling.getByLabel('Email address', { exact: true }).waitFor()
  assert.equal((await fetch(media,mediaAuth)).status,401)
  assert.deepEqual(await inspect(sibling,target.id), second)
  await submitLogin(sibling,target)
  await sibling.getByRole('heading', { name: 'This registered device is blocked', exact: true }).waitFor()
  assert.equal(await nav(sibling).count(),0)
  assert.equal(await sibling.getByRole('button', { name: 'Verify and unlock device', exact: true }).count(),0)
  assert.equal(await tryRebind(sibling,target.id),409)
  assert.equal(await tryRebind(sibling,target.id,randomUUID()),409)
  assert.equal(data(await target.client.rpc('st_v7_set_device_trust', {
    p_device: second.id, p_state: 'trusted',
  })),false)
  assert.equal(sql("select count(*) from sectalk_private.st_v7_operator_device_audit where owner='" + target.id
    + "' and device='" + second.id + "' and action='block_device';"), '1')
} finally {
  await browser?.close()
  for (const user of users) sql("delete from sectalk_private.st_v7_operator_device_audit where owner='" + user
    + "' or actor='" + user + "'; delete from sectalk_private.st_v7_account_admin_audit where target='" + user
    + "' or actor='" + user + "'; delete from sectalk_private.staff where user_id='" + user
    + "'; delete from auth.users where id='" + user + "';")
}
console.log('Passed operator inventory, scoped session revocation, management flags, signed offline key wipe, permanent device blocking and durable audit.')
