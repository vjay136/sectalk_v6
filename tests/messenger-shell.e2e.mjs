import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const database = new URL(process.env.SECTALK_STORAGE_TEST_URL)
for (const url of [app, database]) assert.equal(url.hostname, '127.0.0.1')

const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
const auth = { persistSession: false, autoRefreshToken: false }
const admin = createClient(database.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, { auth })
const password = randomUUID() + '!Qa9'
const users = []

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

async function account(name) {
  const handle = 'ui_' + randomUUID().slice(0, 8)
  const email = handle + '@example.org'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  users.push(user.id)
  const client = createClient(database.origin, process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY, { auth })
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: name }))
  return { client, handle, email }
}

async function signIn(page, person) {
  await page.goto(new URL('/#account', app).href)
  await page.getByLabel('Email address', { exact: true }).fill(person.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.getByLabel('Password', { exact: true }).press('Enter')
  const navigation = page.getByRole('navigation', { name: 'SecTalk features' })
  await navigation.waitFor()
  return navigation
}

async function assertFocused(locator) {
  assert.equal(await locator.evaluate(element => element === document.activeElement), true)
}

try {
  const sender = await account('Shell Sender')
  const peer = await account('Shell Recipient')
  const chat = data(await sender.client.rpc('st_request', { p_handle: peer.handle }))
  data(await peer.client.rpc('st_respond', { p_chat: chat, p_accept: true }))
  const mobile = await browser.newPage({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true })
  const mobileNav = await signIn(mobile, sender)
  const more = mobileNav.getByRole('button', { name: 'More', exact: true })
  const notifications = mobileNav.getByRole('button', { name: 'Notifications', exact: true })
  await notifications.waitFor({ state: 'hidden' })
  await more.press('Enter')
  assert.equal(await more.getAttribute('aria-expanded'), 'true')
  const groupChats = mobileNav.getByRole('button', { name: 'Group chats', exact: true })
  await mobile.keyboard.press('Tab')
  await assertFocused(groupChats)
  await mobile.keyboard.press('Escape')
  await notifications.waitFor({ state: 'hidden' })
  await assertFocused(more)
  await more.press('Enter')
  await notifications.press('Enter')
  await notifications.waitFor({ state: 'hidden' })
  await assertFocused(more)
  await mobile.getByRole('heading', { name: 'Notifications', exact: true }).waitFor()
  for (const label of ['Calls', 'Inbox']) {
    const tab = mobileNav.getByRole('button', { name: label, exact: true })
    await tab.press('Enter')
    assert.equal(await tab.getAttribute('aria-current'), 'page')
  }
  const conversation = mobile.getByRole('button', { name: /Shell Recipient/ })
  await conversation.click()
  const composer = mobile.getByRole('textbox', { name: 'Write a message' })
  const message = 'Messenger shell QA ' + randomUUID().slice(0, 8)
  await composer.fill(message)
  await mobile.getByRole('button', { name: 'Send message' }).click()
  await mobile.getByText(message, { exact: true }).waitFor()
  await mobile.getByRole('button', { name: 'Back to inbox' }).click()
  await conversation.waitFor()
  assert.equal(await composer.isVisible(), false)

  const desktop = await browser.newPage({ viewport: { width: 1440, height: 900 } })
  const desktopNav = await signIn(desktop, sender)
  assert.equal(await desktopNav.getByRole('button', { name: 'More', exact: true }).isVisible(), false)
  await desktopNav.getByRole('button', { name: 'Notifications', exact: true }).click()
  await desktop.getByRole('heading', { name: 'Notifications', exact: true }).waitFor()
  await desktopNav.getByRole('button', { name: 'Inbox', exact: true }).click()
  await desktop.getByRole('button', { name: /Shell Recipient/ }).click()
  await desktop.getByText(message, { exact: true }).waitFor()
  await desktop.getByRole('textbox', { name: 'Write a message' }).waitFor()
  console.log('Verified mobile More keyboard navigation, primary tabs, sending a message, and desktop inbox persistence.')
} finally {
  await browser.close()
  await Promise.allSettled(users.map(id => admin.auth.admin.deleteUser(id)))
}
