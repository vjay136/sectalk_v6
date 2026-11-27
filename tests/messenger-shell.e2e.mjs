import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { join } from 'node:path'
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
const screenshots = process.env.SECTALK_SHELL_SCREENSHOTS

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
  const peer = await account('Shell Recipient Long Display Name')
  const chat = data(await sender.client.rpc('st_request', { p_handle: peer.handle }))
  data(await peer.client.rpc('st_respond', { p_chat: chat, p_accept: true }))
  const mobile = await browser.newPage({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true })
  const mobileNav = await signIn(mobile, sender)
  const more = mobileNav.getByRole('button', { name: 'More', exact: true })
  const notifications = mobileNav.getByRole('button', { name: 'Notifications', exact: true })
  await notifications.waitFor({ state: 'hidden' })
  await more.press('Enter')
  assert.equal(await more.getAttribute('aria-expanded'), 'true')
  if (screenshots) await mobile.screenshot({path: join(screenshots, 'sectalk-more.png')})
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
  for (const [label, panel] of [['Calls', '.calls-page'], ['Safety', '.safety-page']]) {
    await mobileNav.getByRole('button', { name: label, exact: true }).click()
    const section = mobile.locator(panel)
    await section.waitFor()
    for (const width of [320, 360, 390]) {
      await mobile.setViewportSize({width, height: 844})
      assert.ok(await section.evaluate(element => element.scrollWidth <= element.clientWidth), label + ' overflow at ' + width + 'px')
      if (label === 'Calls') {
        const filters = section.getByRole('group', {name:'Call history'})
        assert.ok(await filters.evaluate(element => element.scrollWidth <= element.clientWidth), 'Call filters overflow at ' + width + 'px')
      }
    }
    if (screenshots) await mobile.screenshot({path: join(screenshots, 'sectalk-' + label.toLowerCase() + '.png')})
  }
  await mobileNav.getByRole('button', { name: 'Inbox', exact: true }).press('Enter')
  await mobile.getByRole('button', { name: 'Search across SecTalk', exact: true }).click()
  await mobile.getByRole('heading', { name: 'Search', exact: true }).waitFor()
  await mobileNav.getByRole('button', { name: 'Inbox', exact: true }).click()
  const conversation = mobile.getByRole('button', { name: /Shell Recipient/ })
  await conversation.click()
  const tools = mobile.getByRole('button', { name: 'Conversation tools', exact: true })
  const preferences = mobile.getByRole('button', { name: 'Chat settings', exact: true })
  await tools.waitFor()
  for (const width of [320, 360, 390]) {
    await mobile.setViewportSize({width, height: 844})
    const header = mobile.locator('.conversation-header')
    const bounds = await header.boundingBox()
    assert.ok(bounds && bounds.height < 80, 'The chat header stays compact at ' + width + 'px')
    assert.ok(await header.evaluate(element => element.scrollWidth <= element.clientWidth), 'Chat header overflow at ' + width + 'px')
    assert.ok(await mobile.getByRole('button', { name: 'Start audio call', exact: true }).isVisible())
    assert.ok(await mobile.getByRole('button', { name: 'Start video call', exact: true }).isVisible())
    assert.equal(await mobile.getByRole('button', { name: 'Report contact', exact: true }).isVisible(), false)
    assert.ok(await mobile.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth))
  }
  await tools.click()
  await mobile.getByRole('button', { name: 'Report contact', exact: true }).waitFor()
  if (screenshots) await mobile.screenshot({path: join(screenshots, 'sectalk-chat-tools.png')})
  await tools.press('Escape')
  await mobile.getByRole('button', { name: 'Report contact', exact: true }).waitFor({state:'hidden'})
  await preferences.click()
  await mobile.getByRole('button', { name: 'Chat quiet hours', exact: true }).waitFor()
  await preferences.click()
  await mobile.getByRole('button', { name: 'Chat quiet hours', exact: true }).waitFor({state:'hidden'})
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
  console.log('Verified mobile navigation, compact chat controls at 320, 360 and 390 px, sending a message, and desktop inbox persistence.')
} finally {
  await browser.close()
  await Promise.allSettled(users.map(id => admin.auth.admin.deleteUser(id)))
}
