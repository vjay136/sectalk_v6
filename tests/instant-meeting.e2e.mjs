// Run against the isolated loopback app and Supabase stack.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.hostname, '127.0.0.1')
const key = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const serviceKey = process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
assert.ok(key && serviceKey)
const options = { auth:{ persistSession:false, autoRefreshToken:false } }
const admin = createClient(supabase.href,serviceKey,options)
const suffix = randomUUID().slice(0,8)
const password = randomUUID() + '1!Q'

function data(result) {
  if(result.error) throw new Error(result.error.message)
  return result.data
}

async function account(name) {
  const handle = name.toLowerCase() + '_' + suffix
  const email = handle + '@example.org'
  data(await admin.auth.admin.createUser({ email,password,email_confirm:true }))
  const client = createClient(supabase.href,key,options)
  const { user } = data(await client.auth.signInWithPassword({ email,password }))
  data(await client.rpc('st_save_profile',{ p_handle:handle,p_name:name }))
  return { client,email,handle,id:user.id }
}

const host = await account('InstantHost')
const member = await account('InstantMember')
const workspace = data(await host.client.rpc('st_v2_create_workspace',{ p_name:'Instant meeting browser workspace' }))
data(await host.client.rpc('st_v2_invite',{ p_workspace:workspace,p_handle:member.handle }))
const invite = data(await member.client.from('st_v2_invites').select('id').eq('workspace_id',workspace).single())
data(await member.client.rpc('st_v2_reply_invite',{ p_invite:invite.id,p_accept:true }))

const browser = await chromium.launch({ executablePath:process.env.SECTALK_TEST_BROWSER })
try {
  async function open(person) {
    const page = await browser.newPage()
    await page.goto(new URL('/#account',app).href)
    await page.getByLabel('Email address',{ exact:true }).fill(person.email)
    await page.getByLabel('Password',{ exact:true }).fill(password)
    await page.locator('button.submit-auth').click()
    await page.getByRole('navigation',{ name:'SecTalk features' }).waitFor()
    return page
  }
  const [hostPage,memberPage] = await Promise.all([open(host),open(member)])
  const feature = (page,name)=>page.getByRole('navigation',{ name:'SecTalk features' }).getByRole('button',{ name,exact:true })
  await feature(hostPage,'Meetings').click()
  await feature(memberPage,'Meetings').click()
  assert.equal(await memberPage.getByRole('button',{ name:'Meet now',exact:true }).count(),0)
  await feature(memberPage,'Notifications').click()
  await memberPage.getByRole('heading',{ name:'Notifications',exact:true }).waitFor()

  const title = 'Instant workspace check ' + suffix
  await hostPage.getByRole('button',{ name:'Meet now',exact:true }).click()
  await hostPage.getByRole('heading',{ name:'Start a meeting now',exact:true }).waitFor()
  await hostPage.locator('select[name="workspace"]').selectOption(workspace)
  await hostPage.getByLabel('Title',{ exact:true }).fill(title)
  await hostPage.locator('select[name="duration"]').selectOption('30')
  const started = hostPage.waitForResponse(response=>response.url().endsWith('/rpc/st_v6_start_instant_meeting'))
  await hostPage.getByRole('button',{ name:'Start meeting',exact:true }).click()
  const response = await started
  assert.equal(response.status(),200)
  const meeting = await response.json()
  await hostPage.getByRole('heading',{ name:title,exact:true }).waitFor()
  await hostPage.getByRole('button',{ name:'End meeting',exact:true }).waitFor()
  assert.equal(data(await host.client.rpc('st_v3_media_access',{ p_meeting:meeting })),true)

  const notice = memberPage.locator('article').filter({ hasText:title })
  await notice.getByText('A workspace meeting has started',{ exact:true }).waitFor()
  await notice.getByRole('button',{ name:'View meeting',exact:true }).click()
  await memberPage.getByRole('heading',{ name:title,exact:true }).waitFor()
  await memberPage.getByRole('button',{ name:'Request admission',exact:true }).click()
  await memberPage.getByText('Waiting for the host to admit you',{ exact:true }).waitFor()
  assert.equal(data(await member.client.rpc('st_v3_media_access',{ p_meeting:meeting })),false)
  await hostPage.getByRole('button',{ name:'Admit all eligible attendees',exact:true }).click()
  await hostPage.getByText('Admitted 1 attendee.',{ exact:true }).waitFor()
  await memberPage.getByText('Waiting for the host to admit you',{ exact:true }).waitFor({ state:'detached' })
  assert.equal(data(await member.client.rpc('st_v3_media_access',{ p_meeting:meeting })),true)

  const concurrent = { p_id:randomUUID(),p_workspace:workspace,p_title:'Concurrent instant fixture',p_minutes:15 }
  const created = await Promise.all([
    host.client.rpc('st_v6_start_instant_meeting',concurrent),
    host.client.rpc('st_v6_start_instant_meeting',concurrent),
  ])
  for(const result of created) assert.equal(data(result),concurrent.p_id)
  const notices = data(await member.client.from('st_v3_notifications').select('id').eq('meeting_id',concurrent.p_id))
  assert.equal(notices.length,1)
  console.log('Passed instant meeting creation, live notification, lobby admission and concurrent retry.')
} finally {
  await browser.close()
}
