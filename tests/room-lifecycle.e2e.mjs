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

const [owner,admin,member] = await Promise.all([account('LifecycleOwner'),account('LifecycleAdmin'),account('LifecycleMember')])
const workspace = data(await owner.client.rpc('st_v2_create_workspace',{p_name:'Lifecycle workspace '+suffix}))
for(const person of [admin,member]) {
  data(await owner.client.rpc('st_v2_invite',{p_workspace:workspace,p_handle:person.handle}))
  const invite = data(await person.client.from('st_v2_invites').select('id').eq('workspace_id',workspace).single())
  data(await person.client.rpc('st_v2_reply_invite',{p_invite:invite.id,p_accept:true}))
}
await fixtureAuthenticator(owner.client)
data(await owner.client.rpc('st_v2_set_member',{p_workspace:workspace,p_member:admin.id,p_role:'admin'}))
const room = randomUUID()
const roomName = 'Lifecycle room '+suffix
const secret = 'Room history from before the visibility change'
data(await owner.client.rpc('st_v6_room_create',{p_id:room,p_workspace:workspace,p_name:roomName,p_kind:'public',p_template:'blank'}))
data(await owner.client.rpc('st_v6_room_post',{p_room:room,p_id:randomUUID(),p_body:secret}))
data(await member.client.rpc('st_v6_room_membership',{p_room:room,p_action:'join'}))

const browser = await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
try {
  async function open(person) {
    const page = await browser.newPage()
    await page.goto(new URL('/#account',app).href)
    await page.getByLabel('Email address',{exact:true}).fill(person.email)
    await page.getByLabel('Password',{exact:true}).fill(password)
    await page.locator('button.submit-auth').click()
    await page.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Rooms',exact:true}).click()
    const directory = page.getByRole('region',{name:'Room directory',exact:true})
    const roomButton = directory.getByRole('button',{name:new RegExp(roomName)})
    await roomButton.click()
    return {page,directory,roomButton,panel:directory.getByRole('region',{name:roomName,exact:true})}
  }

  const [manager,participant] = await Promise.all([open(admin),open(member)])
  const tabs = panel=>panel.getByRole('group',{name:'Room tabs'})
  const tab = (panel,name)=>tabs(panel).getByRole('button',{name,exact:true})
  manager.page.on('dialog',dialog=>dialog.accept())
  await manager.panel.getByText('Current owner '+owner.name,{exact:true}).waitFor()
  assert.equal(await tab(manager.panel,'Messages').count(),0)
  await participant.panel.getByText(secret,{exact:true}).waitFor()
  assert.equal(await tab(participant.panel,'Settings').count(),0)
  assert.equal(await tab(participant.panel,'Audit').count(),0)

  await manager.panel.getByRole('button',{name:'Make room private',exact:true}).click()
  await manager.panel.getByRole('button',{name:'Make room workspace-wide',exact:true}).waitFor()
  assert.equal(await manager.panel.getByRole('button',{name:'Join room',exact:true}).count(),0)
  await manager.panel.getByRole('combobox',{name:/New room owner/}).selectOption(member.id)
  await manager.panel.getByRole('button',{name:'Transfer ownership',exact:true}).click()
  await manager.panel.getByText('Current owner '+member.name,{exact:true}).waitFor()

  await tab(manager.panel,'Audit').click()
  await manager.panel.getByText('membership join',{exact:true}).waitFor()
  const transfer = manager.panel.getByRole('listitem').filter({hasText:'membership transfer_owner'})
  await transfer.getByText('Member '+member.name,{exact:true}).waitFor()
  await transfer.getByText('Previous owner '+owner.name,{exact:true}).waitFor()
  await manager.panel.getByText('Workspace-wide → Private',{exact:true}).waitFor()
  await tab(manager.panel,'Settings').click()
  await manager.panel.getByRole('button',{name:'Archive room',exact:true}).click()
  await manager.directory.getByRole('button',{name:'Archived rooms',exact:true,pressed:true}).waitFor()
  await tab(manager.panel,'Settings').click()
  await manager.panel.getByRole('button',{name:'Restore room',exact:true}).click()
  await manager.directory.getByRole('button',{name:'Active rooms',exact:true,pressed:true}).waitFor()
  await tab(manager.panel,'Audit').click()
  await manager.panel.getByText('room archive',{exact:true}).waitFor()
  await manager.panel.getByText('room restore',{exact:true}).waitFor()
  assert.equal(await manager.panel.getByText(secret,{exact:true}).count(),0)
  console.log('Passed room visibility, ownership transfer, archive, restore, membership audit and private content isolation in browser.')
} finally {
  await browser.close()
}
