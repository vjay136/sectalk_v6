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
const owner = await account('policy_owner')
const member = await account('policy_member')
const workspace = data(await owner.client.rpc('st_v2_create_workspace', { p_name: 'Eight policies ' + suffix }))
data(await owner.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: member.handle }))
const invite = data(await member.client.from('st_v2_invites').select('id').eq('workspace_id', workspace).single())
data(await member.client.rpc('st_v2_reply_invite', { p_invite: invite.id, p_accept: true }))
const { verifyStaffPanel } = await import('./workspace-admin-fixture.mjs')
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
const button = (scope,name) => scope.getByRole('button', { name, exact:true })
const nav = page => page.getByRole('navigation', { name:'SecTalk features' })
async function open(person){
  const page=await browser.newPage()
  await page.goto(new URL('/#account',app).href,{waitUntil:'domcontentloaded'})
  await page.getByLabel('Email address',{exact:true}).fill(person.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await button(nav(page),'Workspaces').click()
  return page
}
try{
  const a=await open(owner)
  const b=await open(member)
  const sections=page=>page.getByRole('group',{name:'Workspace sections'})
  assert.equal(await button(sections(b),'Policies').count(),0)
  await button(sections(a),'Policies').click()
  const surface=a.getByRole('region',{name:'Workspace policies'})
  await verifyStaffPanel(surface)
  const choices=[
    ['Messaging',async pane=>pane.getByLabel('Allowed emoji').selectOption('off'),{set:'off',limit:8}],
    ['Files',async pane=>pane.getByRole('checkbox',{name:'Allow workspace file access history'}).check(),{history:true}],
    ['Calls',async pane=>pane.getByRole('checkbox',{name:'Pause recurring meetings'}).check(),{paused:true}],
    ['AI',async pane=>pane.getByRole('checkbox',{name:'Enable managed AI'}).uncheck(),{enabled:false,consent:true,threshold:1,days:30}],
    ['Retention',async pane=>pane.getByLabel('Room retirement days',{exact:true}).fill('21'),{days:21}],
    ['Sharing',async pane=>pane.getByLabel('File egress').selectOption('block'),{mode:'block'}],
    ['DLP',async pane=>pane.getByLabel('Health record identifiers').selectOption('block'),{pii:'allow',phi:'block',payment_card:'allow',credential:'allow'}],
    ['External access',async pane=>pane.getByLabel('Allowed email domains',{exact:true}).fill('Example.Invalid'),{domains:['example.invalid']}],
  ]
  for(const [name,change,expected] of choices){
    await button(surface.getByRole('group',{name:'Policy areas'}),name).click()
    const pane=surface.getByRole('region',{name:name+' policy',exact:true})
    await pane.getByText('Current revision 0',{exact:true}).waitFor()
    await change(pane)
    const effect=pane.getByRole('region',{name:'Policy preview'})
    await button(pane,'Preview proposed policy').click()
    await effect.getByText('Preview validated against the live policy. No settings were saved.',{exact:true}).waitFor()
    await pane.getByText('Current revision 0',{exact:true}).waitFor()
    const applied=a.waitForResponse(response=>response.ok()&&response.url().endsWith('/rpc/st_v7_workspace_policies')
      &&response.request().postDataJSON().p_action==='apply')
    await button(effect,'Apply policy').click()
    assert.deepEqual((await (await applied).json()).current,expected)
    await pane.getByText('Current revision 1',{exact:true}).waitFor()
    await pane.getByLabel('Earlier revision').selectOption('0')
    await button(pane,'Preview earlier revision').click()
    await button(effect,'Restore earlier revision').click()
    await pane.getByText('Policy revision restored.',{exact:true}).waitFor()
    await pane.getByText('Current revision 2',{exact:true}).waitFor()
  }
  console.log('Passed every native workspace policy preview, apply and rollback in Edge with fresh owner TOTP.')
}finally{
  await browser.close()
  await Promise.allSettled([owner,member].map(person=>admin.auth.admin.deleteUser(person.id)))
}
