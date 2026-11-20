// Run against the isolated loopback app and Supabase stack.
import assert from 'node:assert/strict'
import {randomUUID} from 'node:crypto'
import {createClient} from '@supabase/supabase-js'
import { fixtureAuthenticator } from './workspace-admin-fixture.mjs'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname,'127.0.0.1')
assert.equal(supabase.hostname,'127.0.0.1')
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const serviceKey = process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
assert.ok(publicKey && serviceKey)
const {chromium} = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const options = {auth:{persistSession:false,autoRefreshToken:false}}
const service = createClient(supabase.href,serviceKey,options)
const suffix = randomUUID().slice(0,8)
const password = randomUUID()+'1!Q'

function data(result) {
  if(result.error)throw new Error(result.error.message)
  return result.data
}

async function account(name) {
  const handle = name.toLowerCase()+'_'+suffix
  const email = handle+'@example.org'
  const client = createClient(supabase.href,publicKey,options)
  const {user} = data(await service.auth.admin.createUser({email,password,email_confirm:true}))
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:name}))
  return {id:user.id,client,email,handle,name}
}

const [owner,admin,member] = await Promise.all([account('ChannelOwner'),account('ChannelAdmin'),account('ChannelMember')])
const workspace = data(await owner.client.rpc('st_v2_create_workspace',{p_name:'Channel workspace '+suffix}))
for(const person of [admin,member]) {
  data(await owner.client.rpc('st_v2_invite',{p_workspace:workspace,p_handle:person.handle}))
  const invite = data(await person.client.from('st_v2_invites').select('id').eq('workspace_id',workspace).single())
  data(await person.client.rpc('st_v2_reply_invite',{p_invite:invite.id,p_accept:true}))
}
await fixtureAuthenticator(owner.client)
data(await owner.client.rpc('st_v2_set_member',{p_workspace:workspace,p_member:admin.id,p_role:'admin'}))
const channelName = 'channel-lifecycle-'+suffix
const channel = data(await owner.client.rpc('st_v2_create_channel',{p_workspace:workspace,p_name:channelName}))
const history = 'Channel history before the visibility change'
data(await owner.client.rpc('st_v2_post',{p_channel:channel,p_id:randomUUID(),p_body:history}))

const browser = await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
try {
  async function open(person) {
    const page = await browser.newPage()
    await page.goto(new URL('/#account',app).href)
    await page.getByLabel('Email address',{exact:true}).fill(person.email)
    await page.getByLabel('Password',{exact:true}).fill(password)
    await page.locator('button.submit-auth').click()
    await page.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Rooms',exact:true}).click()
    await page.getByRole('button',{name:'Workspace channels',exact:true}).click()
    const select = page.getByRole('combobox',{name:/^Channel/}).first()
    await select.selectOption(channel)
    return {page,select,panel:page.getByRole('region',{name:'#'+channelName,exact:true})}
  }

  async function revealSettings(panel) {
    const settings = panel.locator('details').filter({hasText:'Channel settings'})
    await settings.waitFor()
    if(!await settings.evaluate(element=>element.open))await settings.getByText('Channel settings',{exact:true}).click()
  }

  const [manager,participant] = await Promise.all([open(admin),open(member)])
  manager.page.on('dialog',dialog=>dialog.accept())
  await manager.panel.getByText(history,{exact:true}).waitFor()
  await participant.panel.getByText(history,{exact:true}).waitFor()
  assert.equal(await participant.panel.getByText('Channel settings',{exact:true}).count(),0)
  await revealSettings(manager.panel)
  await manager.panel.getByText('Channel owner '+owner.name,{exact:true}).waitFor()
  await manager.panel.getByRole('button',{name:'Make channel private',exact:true}).click()
  await manager.panel.getByText('Private',{exact:true}).waitFor()
  await manager.panel.getByText(history,{exact:true}).waitFor({state:'detached'})
  await participant.panel.getByText(history,{exact:true}).waitFor({state:'detached',timeout:25000})
  await revealSettings(manager.panel)

  await manager.panel.getByRole('form',{name:'Add private channel member'}).getByRole('combobox').selectOption(member.id)
  await manager.panel.getByRole('button',{name:'Add channel member',exact:true}).click()
  const added = manager.panel.getByRole('listitem').filter({hasText:'add member'})
  await added.getByText('Member '+member.name,{exact:true}).waitFor()
  await manager.panel.getByRole('form',{name:'Transfer channel ownership'}).getByRole('combobox').selectOption(member.id)
  await manager.panel.getByRole('button',{name:'Transfer ownership',exact:true}).click()
  await manager.panel.getByText('Channel owner '+member.name,{exact:true}).waitFor()
  await manager.panel.getByText('Previous owner '+owner.name,{exact:true}).waitFor()
  await participant.select.selectOption(channel)
  await participant.panel.getByText(history,{exact:true}).waitFor()
  await participant.panel.getByText('Channel settings',{exact:true}).waitFor()

  await manager.panel.getByRole('button',{name:'Archive channel',exact:true}).click()
  await manager.page.getByRole('button',{name:'Archived channels',exact:true,pressed:true}).waitFor()
  await manager.panel.getByText('Private · Archived',{exact:true}).waitFor()
  await revealSettings(manager.panel)
  await manager.panel.getByRole('button',{name:'Restore channel',exact:true}).click()
  await manager.page.getByRole('button',{name:'Active channels',exact:true,pressed:true}).waitFor()
  await revealSettings(manager.panel)
  await manager.panel.getByText('archive',{exact:true}).waitFor()
  await manager.panel.getByText('restore',{exact:true}).waitFor()
  assert.equal(await manager.panel.getByText(history,{exact:true}).count(),0)
  console.log('Passed legacy channel visibility, ownership, archive, restore, membership audit and message isolation in browser.')
} finally {
  await browser.close()
}
