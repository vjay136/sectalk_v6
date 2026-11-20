// Run against the isolated loopback app and Supabase stack.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname,'127.0.0.1')
assert.equal(supabase.hostname,'127.0.0.1')
const key = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const serviceKey = process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
assert.ok(key && serviceKey)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const options = {auth:{persistSession:false,autoRefreshToken:false}}
const admin = createClient(supabase.href,serviceKey,options)
const suffix = randomUUID().slice(0,8)
const password = randomUUID() + '1!Q'

function data(result) {
  if(result.error)throw new Error(result.error.message)
  return result.data
}

async function account(label) {
  const handle = label.toLowerCase() + '_' + suffix
  const email = handle + '@example.org'
  data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  const client = createClient(supabase.href,key,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:label}))
  return {client,email,handle}
}

const owner = await account('RoomOwner')
const member = await account('RoomMember')
const workspace = data(await owner.client.rpc('st_v2_create_workspace',{p_name:'Room template workspace'}))
data(await owner.client.rpc('st_v2_invite',{p_workspace:workspace,p_handle:member.handle}))
const invite = data(await member.client.from('st_v2_invites').select('id').eq('workspace_id',workspace).single())
data(await member.client.rpc('st_v2_reply_invite',{p_invite:invite.id,p_accept:true}))

const browser = await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
try {
  async function open(person) {
    const page = await browser.newPage()
    await page.goto(new URL('/#account',app).href)
    await page.getByLabel('Email address',{exact:true}).fill(person.email)
    await page.getByLabel('Password',{exact:true}).fill(password)
    await page.locator('button.submit-auth').click()
    await page.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Rooms',exact:true}).click()
    return page
  }
  const [ownerPage,memberPage] = await Promise.all([open(owner),open(member)])
  const directory = page=>page.getByRole('region',{name:'Room directory',exact:true})
  const title = label=>label + ' template room ' + suffix
  for(const [label,kinds,description] of [
    ['Class',['private'],/15-second posting interval/],
    ['Incident',['admin'],/owners and admins can access/],
    ['Family',['private'],/household plans/],
    ['Project',['public','private'],/goals, ownership, and milestones/],
  ]){
    const area = directory(ownerPage)
    await area.getByText('Create a room',{exact:true}).click()
    await area.getByLabel('Room name',{exact:true}).fill(title(label))
    await area.getByLabel('Room template').selectOption({label})
    await area.getByText(description).waitFor()
    const kind = area.getByLabel('Room type')
    assert.deepEqual(await kind.locator('option').evaluateAll(options=>options.map(option=>option.value)),kinds)
    assert.equal(await kind.inputValue(),kinds[0])
    const started = ownerPage.waitForResponse(response=>response.url().endsWith('/rpc/st_v6_room_create'))
    await area.getByRole('button',{name:'Create room',exact:true}).click()
    assert.equal((await started).status(),200)
    const panel = area.getByRole('region',{name:title(label),exact:true})
    await panel.getByText(new RegExp(label+' starter')).waitFor()
    await panel.getByRole('group',{name:'Room tabs'}).getByRole('button',{name:'Pins',exact:true}).click()
    await panel.getByText(new RegExp(label+' starter')).waitFor()
  }
  const memberDirectory = directory(memberPage)
  await memberDirectory.getByRole('button',{name:new RegExp(title('Project'))}).click()
  const projectPanel = memberDirectory.getByRole('region',{name:title('Project'),exact:true})
  await projectPanel.getByRole('button',{name:'Join room',exact:true}).waitFor()
  assert.equal(await projectPanel.getByText(/Project starter/).count(),0)
  for(const label of ['Class','Incident','Family']){
    assert.equal(await memberDirectory.getByRole('button',{name:new RegExp(title(label))}).count(),0)
  }
  assert.equal(await memberDirectory.getByText('Create a room',{exact:true}).count(),0)
  await projectPanel.getByRole('button',{name:'Join room',exact:true}).click()
  await projectPanel.getByRole('group',{name:'Room tabs'}).getByRole('button',{name:'Pins',exact:true}).click()
  await projectPanel.getByText(/Project starter/).waitFor()
  console.log('Passed four room template previews, pinned starters, visibility and project admission.')
} finally {
  await browser.close()
}
