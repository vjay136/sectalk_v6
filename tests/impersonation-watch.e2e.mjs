import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const credentials = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, credentials)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const suffix = randomUUID().slice(0, 8)
const password = randomUUID() + '1!Q'

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

async function createAccount(name, stem) {
  const handle = stem + '_' + suffix
  const email = handle + '@example.org'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY, credentials)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: name }))
  return { id: user.id, email, handle, name, client }
}

const [owner, candidate] = await Promise.all([
  createAccount('Avery Eagle', 'avery_eagle'),
  createAccount('\u0391very Eagle', 'avery_eag1e'),
])
const workspace = data(await owner.client.rpc('st_v2_create_workspace', { p_name: 'Identity review ' + suffix }))
data(await owner.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: candidate.handle }))
const invite = data(await candidate.client.from('st_v2_invites').select('id').eq('workspace_id', workspace).single())
data(await candidate.client.rpc('st_v2_reply_invite', { p_invite: invite.id, p_accept: true }))
assert.equal((await candidate.client.rpc('st_v6_impersonation_watch_list', { p_workspace: workspace })).error?.code, '42501')

const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
try {
  async function enter(person) {
    const page = await browser.newPage()
    await page.goto(new URL('/#account', app).href)
    await page.getByLabel('Email address', { exact: true }).fill(person.email)
    await page.getByLabel('Password', { exact: true }).fill(password)
    await page.locator('button.submit-auth').click()
    await page.getByRole('navigation', { name: 'SecTalk features' }).getByRole('button', { name: 'Workspaces', exact: true }).click()
    return page
  }

  const [managerPage, memberPage] = await Promise.all([enter(owner), enter(candidate)])
  const watchTab = page => page.getByRole('button', { name: 'Impersonation watch', exact: true })
  await managerPage.getByRole('group', { name: 'Workspace sections', exact: true }).waitFor()
  await memberPage.getByRole('group', { name: 'Workspace sections', exact: true }).waitFor()
  assert.equal(await watchTab(memberPage).count(), 0)
  await watchTab(managerPage).click()
  const panel = managerPage.getByRole('region', { name: 'Impersonation watch', exact: true })
  await panel.getByLabel('Protected member', { exact: true }).selectOption(owner.id)
  await panel.getByLabel('Watch category', { exact: true }).selectOption('vip')
  await panel.getByRole('button', { name: 'Save protected member', exact: true }).click()
  await panel.getByText('Similar-looking display name', { exact: true }).waitFor()
  await panel.getByText('Similar-looking username', { exact: true }).waitFor()
  assert.deepEqual(data(await owner.client.rpc('st_v6_impersonation_watch_list', { p_workspace: workspace })),
    [{ member_id: owner.id, tier: 'vip' }])
  await panel.getByRole('button', { name: 'Remove from watch list', exact: true }).click()
  await panel.getByText('No protected members yet.', { exact: true }).waitFor()
  await panel.getByText('No similar profiles found in the active workspace roster.', { exact: true }).waitFor()
  console.log('Passed manager watch list access, workspace lookalike signals, and removing a watched member.')
} finally {
  await browser.close()
}
