import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { totpCode } from './workspace-admin-fixture.mjs'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const project = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.origin, 'http://127.0.0.1:3484')
assert.equal(project.origin, 'http://127.0.0.1:55321')

const auth = { persistSession: false, autoRefreshToken: false }
const admin = createClient(project.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, { auth })
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const password = randomUUID() + '!Qa7'
const accounts = []
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER,
  args: ['--use-fake-ui-for-media-stream','--use-fake-device-for-media-stream'] })
const androidEndpoint = process.env.SECTALK_ANDROID_CDP
if (androidEndpoint) assert.equal(new URL(androidEndpoint).origin, 'http://127.0.0.1:9248')
let android

function data(result) {
  assert.equal(result.error, null, result.error?.message)
  return result.data
}

function staff(id, add) {
  assert.match(id, /^[0-9a-f-]{36}$/)
  const query = add
    ? "insert into sectalk_private.staff(user_id) values ('" + id + "')"
    : "delete from sectalk_private.staff where user_id='" + id + "'"
  execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-Xq', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres'],
    { input: query, windowsHide: true })
}

async function account(role) {
  const handle = 'label_' + role + '_' + randomUUID().slice(0, 6)
  const email = handle + '@example.org'
  const name = 'Safety QA ' + role
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  accounts.push(user.id)
  const client = createClient(project.origin, publicKey, { auth })
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: name }))
  return { client, email, handle, id: user.id, name }
}

async function open(person, contact, mobile = false) {
  const context = mobile && android ? android.contexts()[0] : await browser.newContext({
    viewport: mobile ? { width: 390, height: 844 } : { width: 1440, height: 940 },
  })
  const page = await context.newPage()
  await page.goto(app.href)
  if (mobile && android) {
    await page.bringToFront()
    await page.evaluate(() => localStorage.clear())
    await page.reload()
  }
  await page.getByLabel('Email address', { exact: true }).fill(person.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  const navigation = page.getByRole('navigation', { name: 'SecTalk features' })
  const accept = page.getByRole('button', { name: 'Accept and continue', exact: true })
  await navigation.or(accept).first().waitFor()
  if (await accept.isVisible()) {
    await page.getByRole('checkbox', { name: 'I accept the SecTalk Community Rules.' }).check()
    await accept.click()
  }
  await navigation.waitFor()
  await page.locator('.chat-item').filter({ hasText: contact.name }).click()
  return page
}

let moderator
try {
  android = androidEndpoint ? await chromium.connectOverCDP(androidEndpoint) : null
  const [author, reporter, recipient] = await Promise.all([account('author'), account('reporter'), account('recipient')])
  moderator = await account('moderator')
  staff(moderator.id, true)
  const enrollment = data(await moderator.client.auth.mfa.enroll({ factorType: 'totp' }))
  data(await moderator.client.auth.mfa.challengeAndVerify({
    factorId: enrollment.id, code: await totpCode(enrollment.totp.secret),
  }))

  const source = data(await reporter.client.rpc('st_request', { p_handle: author.handle }))
  const destination = data(await reporter.client.rpc('st_request', { p_handle: recipient.handle }))
  data(await author.client.rpc('st_respond', { p_chat: source, p_accept: true }))
  data(await recipient.client.rpc('st_respond', { p_chat: destination, p_accept: true }))
  const text = 'Synthetic advisory review ' + randomUUID()
  data(await author.client.rpc('st_send', { p_chat: source, p_id: randomUUID(), p_body: text }))

  const [observer, downstream] = await Promise.all([open(reporter, author), open(recipient, reporter, true)])
  await observer.getByText(text, { exact: true }).waitFor()
  await observer.getByRole('button', {name:'Message safety: No active warning',exact:true}).waitFor()
  await observer.getByRole('button', { name: 'Report message', exact: true }).click()
  const reportForm = observer.getByRole('dialog', { name: 'Report this message' })
  await reportForm.getByRole('combobox', { name: 'Report category' }).selectOption('phishing')
  await reportForm.locator('textarea').fill('Private report evidence from the synthetic test.')
  const submission = observer.waitForResponse(response => response.url().endsWith('/rpc/st_v5_report'))
  await reportForm.getByRole('button', { name: 'Submit report' }).click()
  const reportResult = await submission
  assert.equal(reportResult.status(), 200)
  const ticket = await reportResult.json()
  assert.match(ticket, /^[0-9a-f-]{36}$/)
  await observer.getByText('You reported this message · In review', { exact: true }).waitFor()
  await observer.getByRole('button', {name:'Message safety: You reported this message · In review',exact:true}).waitFor()
  const fingerprint = createHash('sha256').update(text).digest('hex')
  const lookup = () => recipient.client.rpc('st_be_safe_lookup', { p_fingerprint: fingerprint, p_links: [], p_handle: null })
  assert.deepEqual(data(await lookup()).categories, [])

  await observer.locator('.message-menu > summary').click()
  await observer.getByRole('button', { name: 'Forward message', exact: true }).click()
  const forward = observer.getByRole('dialog', { name: 'Forward message' })
  await forward.getByLabel('Forward to').selectOption(destination)
  await forward.getByRole('button', { name: 'Forward', exact: true }).click()
  await downstream.getByText(text, { exact: true }).waitFor()
  await downstream.getByText('Forwarded', { exact: true }).waitFor()
  assert.equal(await downstream.getByText('You reported this message · In review').count(), 0)

  const note = 'Private moderator review of synthetic evidence.'
  data(await moderator.client.rpc('st_v8_resolve_direct_report', {
    p_report: ticket, p_action: 'resolved', p_staff_note: note, p_reporter_summary: 'The test report was reviewed.',
  }))
  const chain = data(await moderator.client.rpc('st_report_propagation', { p_report: ticket }))
  assert.equal(chain.original_name, author.name)
  assert.equal(chain.forward_count, 1)
  data(await moderator.client.rpc('st_set_report_advisory', {
    p_report: ticket, p_verdict: 'warning', p_category: 'fraud', p_note: note,
  }))
  await downstream.getByText('Moderator warning · Fraud', { exact: true }).waitFor()
  const confirmed = downstream.getByRole('button', {name:'Message safety: Confirmed warning · Fraud',exact:true})
  assert.equal(await confirmed.getAttribute('data-severity'),'red')
  assert.equal(await downstream.getByText(note, { exact: true }).count(), 0)
  await confirmed.click()
  const details = downstream.getByRole('dialog', {name:'Message details'})
  await details.getByText('Forwarded to this conversation by', {exact:true}).waitFor()
  assert.equal(await details.getByText(reporter.name,{exact:true}).count(),1)
  assert.equal(await details.getByText(author.name,{exact:true}).count(),0)
  assert.equal(await details.getByText('1',{exact:true}).count(),2)
  await downstream.keyboard.press('Escape')

  const navigation = observer.getByRole('navigation', { name: 'SecTalk features' })
  await navigation.getByRole('button', { name: 'Safety', exact: true }).click()
  await observer.getByRole('button', { name: 'Be Safe', exact: true }).click()
  const beSafe = observer.getByRole('region', { name: 'Be Safe lookup' })
  const checkRecords = beSafe.getByRole('button', { name: 'Check safety records' })
  await beSafe.getByLabel('Exact message text').fill(text)
  const query = observer.waitForRequest(request => request.url().endsWith('/rpc/st_be_safe_lookup'))
  await checkRecords.click()
  assert.equal((await query).postDataJSON().p_fingerprint,fingerprint)
  assert.ok(!(await query).postData().includes(text),'Pasted message text left the browser')
  await beSafe.getByText('Fraud or scam', { exact: true }).waitFor()
  await beSafe.getByRole('button', { name: 'Links', exact: true }).click()
  await beSafe.getByLabel('Web addresses').fill('https://example.org/test?private=fixture#fragment')
  await checkRecords.click()
  await beSafe.getByText('https://example.org/test', { exact: true }).waitFor()
  assert.equal(await beSafe.getByRole('link').count(),0)
  await beSafe.getByRole('button', { name: 'Username', exact: true }).click()
  await beSafe.getByLabel('SecTalk username').fill('@'+author.handle)
  await checkRecords.click()
  await beSafe.getByRole('heading', { name: 'No matching warning' }).waitFor()

  data(await moderator.client.rpc('st_set_report_advisory', {
    p_report: ticket, p_verdict: 'remove', p_category: null, p_note: note,
  }))
  await downstream.getByText('Moderator warning · Fraud', { exact: true }).waitFor({ state: 'hidden' })
  await downstream.getByRole('button', {name:'Message safety: No active warning',exact:true}).waitFor()
  assert.deepEqual(data(await lookup()).categories, [])
  console.log('Verified reporting, forwarded message labels, private staff origin tracking, and live label retraction' +
    (android ? ' with the downstream user in Chrome on the Android emulator.' : ' in desktop and mobile-width Edge sessions.'))
  if (android) {
    await navigation.getByRole('button', { name: 'Inbox', exact: true }).click()
    await observer.locator('.chat-item').filter({hasText:recipient.name}).click()
    for (const mode of ['Audio','Video']) {
      await observer.getByRole('button',{name:'Start '+mode.toLowerCase()+' call',exact:true}).click()
      const incoming = downstream.getByRole('region',{name:mode+' call',exact:true})
      await incoming.getByRole('button',{name:'Answer',exact:true}).waitFor()
      assert.ok(await incoming.evaluate(element => {
        const bounds = element.getBoundingClientRect()
        return bounds.top===0 && bounds.left===0 && Math.abs(bounds.width-innerWidth)<=1 && Math.abs(bounds.height-innerHeight)<=1
      }), mode+' call fills the Android Chrome viewport')
      await incoming.getByRole('button',{name:'Decline',exact:true}).click()
      await incoming.waitFor({state:'hidden'})
    }
    console.log('Verified incoming audio and video full-screen presentation and decline on Android Chrome.')
    await downstream.getByRole('button', { name: 'Back to inbox' }).click()
    const nav = downstream.getByRole('navigation', { name: 'SecTalk features' })
    const more = nav.getByRole('button', { name: 'More', exact: true })
    const primary = ['Inbox', 'Friends', 'Calls', 'Safety']
    const secondary = ['Group chats', 'Search', 'Notifications', 'Workspaces', 'Rooms',
      'Tasks', 'Calendar', 'Meetings', 'Files', 'Billing', 'Profile']
    for (const label of [...primary, ...secondary]) {
      if (secondary.includes(label)) await more.click()
      await nav.getByRole('button', { name: label, exact: true }).click()
      await nav.locator('button[aria-current="page"]').getByText(label, { exact: true }).waitFor({ state: 'attached' })
      assert.ok(await downstream.evaluate(() => document.documentElement.scrollWidth <= innerWidth), label + ' overflows the Android viewport')
    }
    console.log('Opened all 15 Android navigation tabs without horizontal overflow.')
  }
} finally {
  await android?.close()
  await browser.close()
  if (moderator) staff(moderator.id, false)
  for (const id of accounts) await admin.auth.admin.deleteUser(id)
}
