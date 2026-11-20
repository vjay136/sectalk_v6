import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { setTimeout } from 'node:timers/promises'
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
const password = randomUUID() + '1!Q'
const mailbox = new URL(process.env.SECTALK_INVITATION_TEST_MAIL || 'http://127.0.0.1:55425')
assert.equal(mailbox.hostname, '127.0.0.1')

function data(result) {
  assert.equal(result.error, null, result.error?.message)
  return result.data
}

async function account(prefix) {
  const handle = prefix + '_' + suffix
  const email = handle + '@example.org'
  data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(supabase.origin, publicKey, options)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: handle }))
  return { email, client }
}

async function deliveredInvitation(email) {
  const search = new URL('/api/v1/search', mailbox)
  search.searchParams.set('query', 'to:' + email)
  for (let attempt = 0; attempt < 20; attempt++) {
    const response = await fetch(search)
    assert.equal(response.status, 200)
    const { messages } = await response.json()
    const entry = messages?.find(message => message.Subject === 'Your SecTalk workspace invitation')
    if (entry) {
      const detail = await fetch(new URL('/api/v1/message/' + entry.ID, mailbox))
      assert.equal(detail.status, 200)
      return detail.json()
    }
    await setTimeout(250)
  }
  throw new Error('No SMTP workspace invitation reached the isolated inbox')
}

const [owner, recipient, other] = await Promise.all([
  account('link_owner'), account('link_recipient'), account('link_other'),
])
const workspaceName = 'Link invite ' + suffix
const workspace = data(await owner.client.rpc('st_v2_create_workspace', { p_name: workspaceName }))
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })

try {
  async function signIn(person, url) {
    const page = await browser.newPage()
    await page.goto(url)
    await page.getByLabel('Email address', { exact: true }).fill(person.email)
    await page.getByLabel('Password', { exact: true }).fill(password)
    await page.locator('button.submit-auth').click()
    await page.getByRole('navigation', { name: 'SecTalk features' }).waitFor()
    return page
  }

  const ownerPage = await signIn(owner, new URL('/#account', app).href)
  await ownerPage.getByRole('navigation', { name: 'SecTalk features' })
    .getByRole('button', { name: 'Workspaces', exact: true }).click()
  await ownerPage.getByRole('button', { name: 'People', exact: true }).click()
  await ownerPage.getByText('Email invitation links', { exact: true }).click()
  await ownerPage.getByLabel('Allowed email domains').fill('example.org')
  await ownerPage.getByRole('button', { name: 'Save invitation policy' }).click()
  await ownerPage.getByText('Invitation domain policy saved.', { exact: true }).waitFor()
  await ownerPage.getByLabel('Invited email').fill(recipient.email)
  await ownerPage.getByRole('button', { name: 'Create single-use link' }).click()
  const inviteField = ownerPage.getByLabel('Invitation link', { exact: true })
  await inviteField.waitFor()
  const invite = new URL(await inviteField.inputValue())
  assert.equal(invite.origin, app.origin)
  assert.equal(invite.pathname, '/invite')
  assert.equal(invite.search, '')
  const token = new URLSearchParams(invite.hash.slice(1)).get('link')
  assert.match(token, /^[a-f0-9]{48}$/)
  const draft = new URL(await ownerPage.getByRole('link', { name: 'Open email draft' }).getAttribute('href'))
  assert.equal(decodeURIComponent(draft.pathname), recipient.email)
  assert.equal(draft.searchParams.get('body'), invite.href)

  const body = JSON.stringify({ workspace, email: recipient.email, hours: 24 })
  const endpoint = new URL('/api/workspaces/invitations', app)
  const anonymous = await fetch(endpoint, { method: 'POST', body })
  assert.equal(anonymous.status, 401)
  const otherToken = data(await other.client.auth.getSession()).session.access_token
  const unauthorized = await fetch(endpoint, {
    method: 'POST', body, headers: { Authorization: 'Bearer ' + otherToken },
  })
  assert.equal(unauthorized.status, 403)
  await ownerPage.getByRole('button', { name: 'Send invitation email' }).click()
  await ownerPage.getByText('Invitation email sent.', { exact: true }).waitFor()
  const message = await deliveredInvitation(recipient.email)
  const mailed = new URL(message.Text.match(/https?:[^\s]+\/invite#link=[a-f0-9]{48}/)?.[0])
  assert.equal(mailed.origin, app.origin)
  assert.equal(mailed.href, await inviteField.inputValue())

  const wrongPage = await signIn(other, invite.href)
  await wrongPage.getByRole('button', { name: 'Accept invitation link' }).click()
  await wrongPage.getByRole('alert').filter({ hasText: 'This invitation is unavailable.' }).waitFor()
  assert.equal(new URL(wrongPage.url()).hash.includes(token), false)

  const recipientPage = await signIn(recipient, mailed.href)
  await recipientPage.getByRole('button', { name: 'Accept invitation link' }).click()
  await recipientPage.getByText('Workspace invitation accepted.', { exact: true }).waitFor()
  const recipientId = data(await recipient.client.auth.getUser()).user.id
  const member = data(await recipient.client.from('st_v2_members').select('workspace_id')
    .eq('workspace_id', workspace).eq('user_id', recipientId).single())
  assert.equal(member.workspace_id, workspace)
  const mailedToken = new URLSearchParams(mailed.hash.slice(1)).get('link')
  assert.ok((await recipient.client.rpc('st_v6_workspace_link_accept', { p_token: mailedToken })).error)
  console.log('Passed link creation, SMTP delivery, unauthenticated and unauthorized denial, verified acceptance and replay denial.')
} finally {
  await browser.close()
}
