// Run against the isolated loopback app with QA VAPID configuration.
import assert from 'node:assert/strict'
import { createECDH, randomBytes, randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const suffix = randomUUID().slice(0, 8)
const handle = 'push_test_' + suffix
const email = handle + '@example.org'
const password = randomUUID() + '1!Q'

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}
data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
const client = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY, options)
data(await client.auth.signInWithPassword({ email, password }))
data(await client.rpc('st_save_profile', { p_handle: handle, p_name: handle }))
assert.equal((await fetch(new URL('/api/push/subscription', app))).status, 401)
assert.equal((await fetch(new URL('/api/push/dispatch', app), { method: 'POST' })).status, 401)
const dispatch = await fetch(new URL('/api/push/dispatch', app), {
  method: 'POST',
  headers: { Authorization: 'Bearer ' + process.env.SECTALK_PUSH_DISPATCH_SECRET },
})
assert.equal(dispatch.status, 200)
assert.deepEqual(await dispatch.json(), { processed: 0 })
const session = data(await client.auth.getSession()).session
const rejected = await fetch(new URL('/api/push/subscription', app), {
  method: 'POST',
  headers: { Authorization: 'Bearer ' + session.access_token, 'Content-Type': 'application/json' },
  body: JSON.stringify({ endpoint: 'https://127.0.0.1/unsafe', keys: { p256dh: 'invalid', auth: 'invalid' } }),
})
assert.equal(rejected.status, 400)

const device = createECDH('prime256v1')
device.generateKeys()
const subscription = {
  endpoint: 'https://fcm.googleapis.com/fcm/send/loopback-test-' + suffix,
  keys: { p256dh: device.getPublicKey().toString('base64url'), auth: randomBytes(16).toString('base64url') },
}
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
try {
  const context = await browser.newContext({ permissions: ['notifications'] })
  await context.addInitScript(input => {
    const subscribed = {
      endpoint: input.endpoint,
      toJSON: () => input,
      unsubscribe: async () => { sessionStorage.removeItem('fake-push-enabled'); return true },
    }
    PushManager.prototype.getSubscription = async () => sessionStorage.getItem('fake-push-enabled') ? subscribed : null
    PushManager.prototype.subscribe = async options => {
      if (!options.userVisibleOnly || options.applicationServerKey.byteLength !== 65) throw new Error('VAPID subscription options missing')
      sessionStorage.setItem('fake-push-enabled', 'true')
      return subscribed
    }
  }, subscription)
  const page = await context.newPage()
  const cdp = await context.newCDPSession(page)
  const serviceWorker = new Promise(resolve => {
    cdp.on('ServiceWorker.workerRegistrationUpdated', ({ registrations }) => {
      const registration = registrations.find(entry => entry.scopeURL === app.href && !entry.isDeleted)
      if (registration) resolve(registration.registrationId)
    })
  })
  await cdp.send('ServiceWorker.enable')
  await page.goto(new URL('/#account', app).href)
  await page.getByLabel('Email address', { exact: true }).fill(email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  const nav = page.getByRole('navigation', { name: 'SecTalk features' })
  await nav.getByRole('button', { name: 'Notifications', exact: true }).click()
  await page.getByRole('button', { name: 'Preferences', exact: true }).click()
  const settings = page.getByRole('region', { name: 'Browser push' })
  const start = settings.getByRole('button', { name: 'Turn on browser push' })
  await start.click()
  await settings.getByText('Browser push turned on.', { exact: true }).waitFor()

  await cdp.send('ServiceWorker.deliverPushMessage', {
    origin: app.origin,
    registrationId: await serviceWorker,
    data: JSON.stringify({ v: 1, title: 'private title', body: 'private message', url: 'https://example.org/untrusted' }),
  })
  await page.waitForFunction(async () => {
    const registration = await navigator.serviceWorker.ready
    return (await registration.getNotifications({ tag: 'sectalk-update' })).some(notification =>
      notification.title === 'SecTalk' && notification.body === 'You have a new alert. Open SecTalk to view it.')
  })
  await settings.getByRole('button', { name: 'Turn off browser push' }).click()
  await settings.getByText('Browser push turned off.', { exact: true }).waitFor()
  assert.equal(await page.evaluate(() => sessionStorage.getItem('fake-push-enabled')), null)
  console.log('Passed browser opt-in, authenticated APIs, service-worker generic push, and unsubscribe.')
} finally {
  await browser.close()
}
