// Run against the isolated loopback app and Supabase stack.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const serviceKey = process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const admin = createClient(supabase.origin, serviceKey, options)
const password = randomUUID() + '1!Q'
const suffix = randomUUID().slice(0, 8)

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

async function account(handlePrefix) {
  const handle = handlePrefix + '_' + suffix
  const email = handle + '@example.org'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(supabase.origin, publicKey, options)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: handle }))
  return { id: user.id, handle, email, client }
}
const owner = await account('email_owner')
const member = await account('email_member')
const recipients = await Promise.all(['r1', 'r2', 'r3', 'r4'].map(account))
const organization = 'Invitation design ' + suffix
const workspace = data(await owner.client.rpc('st_v2_create_workspace', { p_name: organization }))
data(await owner.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: member.handle }))
const invite = data(await member.client.from('st_v2_invites').select('id').eq('workspace_id', workspace).single())
data(await member.client.rpc('st_v2_reply_invite', { p_invite: invite.id, p_accept: true }))

const button = (scope, name) => scope.getByRole('button', { name, exact: true })
const nav = page => page.getByRole('navigation', { name: 'SecTalk features' })
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
async function open(person) {
  const page = await browser.newPage()
  await page.goto(new URL('/#account', app).href, { waitUntil: 'domcontentloaded' })
  await page.getByLabel('Email address', { exact: true }).fill(person.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await button(nav(page), 'Workspaces').click()
  await page.getByRole('heading', { name: organization, exact: true }).waitFor()
  return page
}
async function delivered(email) {
  const search = new URL('http://127.0.0.1:55425/api/v1/search')
  search.searchParams.set('query', 'to:' + email)
  for (let attempt = 0; attempt < 20; attempt++) {
    const { messages } = await (await fetch(search)).json()
    if (messages?.length) return (await fetch('http://127.0.0.1:55425/api/v1/message/' + messages[0].ID)).json()
    await new Promise(resolve => setTimeout(resolve, 200))
  }
  throw new Error('The isolated inbox did not receive the invitation')
}
try {
  const a = await open(owner)
  const b = await open(member)
  assert.equal(await button(b, 'Organization settings').count(), 0)
  assert.equal((await member.client.rpc('st_v7_workspace_email_template', { p_workspace: workspace })).error?.code, '42501')
  const scope = a.getByRole('region', { name: 'Workspace invitation email template' })
  async function settings() { await button(a, 'Organization settings').click() }
  async function publish(subject, body) {
    await scope.getByLabel('Invitation subject').fill(subject)
    await scope.getByLabel('Invitation message').fill(body)
    await button(scope, 'Publish invitation template').click()
    await scope.getByText('Invitation email version published.', { exact: true }).waitFor()
  }
  async function send(person) {
    await button(a, 'People').click()
    const inviteDetails = a.locator('details').filter({ has: a.getByText('Email invitation links', { exact: true }) })
    if (!await inviteDetails.evaluate(element => element.open)) await inviteDetails.locator('summary').click()
    await inviteDetails.getByLabel('Invited email').fill(person.email)
    await button(inviteDetails, 'Send invitation email').click()
    await inviteDetails.getByText('Invitation email sent.', { exact: true }).waitFor()
    const mail = await delivered(person.email)
    assert.equal(mail.From.Address, 'invitation@example.invalid')
    assert.match(mail.Text, /http:\/\/127\.0\.0\.1:3546\/invite#link=[a-f0-9]{48}/)
    assert.match(mail.Text, /This link can be used once and expires on/)
    assert.ok(!mail.HTML, 'only unformatted text is delivered')
    return mail
  }

  await settings()
  const preview = scope.getByRole('region', { name: 'Invitation email preview' })
  await scope.getByLabel('Invitation subject').fill('Welcome to {{organization}}')
  await scope.getByLabel('Invitation message').fill('You are invited to {{organization}}.')
  await preview.getByText('Welcome to ' + organization, { exact: true }).waitFor()
  const previewBody = await preview.locator('pre').innerText()
  assert.equal(previewBody.split('\n')[0], 'You are invited to ' + organization + '.')
  await publish('Welcome to {{organization}}', 'You are invited to {{organization}}.')
  const first = await send(recipients[0])
  assert.equal(first.Subject, 'Welcome to ' + organization)
  assert.equal(first.Text.split(/\r?\n/)[0], previewBody.split('\n')[0])

  await settings()
  await publish('Second {{organization}} template', 'Second authorized version.')
  assert.equal((await send(recipients[1])).Subject, 'Second ' + organization + ' template')

  await settings()
  await scope.getByLabel('Restore a version').selectOption('1')
  await button(scope, 'Restore invitation template').click()
  await scope.getByText('Invitation email version restored.', { exact: true }).waitFor()
  assert.equal((await send(recipients[2])).Subject, first.Subject)

  await settings()
  await scope.getByLabel('Restore a version').selectOption('0')
  await button(scope, 'Restore invitation template').click()
  await scope.getByText('Invitation email version restored.', { exact: true }).waitFor()
  assert.equal((await send(recipients[3])).Subject, 'Your SecTalk workspace invitation')
  console.log('Passed native template publishing, identical preview copy, local SMTP delivery, version restore, and default restore.')
} finally {
  await browser.close()
  await Promise.allSettled([owner, member, ...recipients].map(person => admin.auth.admin.deleteUser(person.id)))
}
