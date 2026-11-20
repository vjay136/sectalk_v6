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

const owner = await account('ThreadOwner')
const author = await account('ThreadAuthor')
const workspace = data(await owner.client.rpc('st_v2_create_workspace',{p_name:'Thread integrity workspace'}))
data(await owner.client.rpc('st_v2_invite',{p_workspace:workspace,p_handle:author.handle}))
const invite = data(await author.client.from('st_v2_invites').select('id').eq('workspace_id',workspace).single())
data(await author.client.rpc('st_v2_reply_invite',{p_invite:invite.id,p_accept:true}))
const title = 'Browser thread integrity '+suffix
const room = data(await owner.client.rpc('st_v6_room_create',{
  p_workspace:workspace,p_id:randomUUID(),p_name:title,p_kind:'public',p_template:'blank'
}))
data(await author.client.rpc('st_v6_room_membership',{p_room:room,p_action:'join'}))
const root = randomUUID()
data(await author.client.rpc('st_v6_room_post',{p_room:room,p_id:root,p_body:'Original thread topic'}))
data(await owner.client.rpc('st_v6_room_post',{p_room:room,p_id:randomUUID(),p_body:'Existing thread reply',p_parent:root}))
data(await owner.client.rpc('st_v6_room_settings',{p_room:room,p_action:'pin',p_post:root}))

const browser = await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
try {
  async function open(person) {
    const page = await browser.newPage()
    await page.goto(new URL('/#account',app).href)
    await page.getByLabel('Email address',{exact:true}).fill(person.email)
    await page.getByLabel('Password',{exact:true}).fill(password)
    await page.locator('button.submit-auth').click()
    await page.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Rooms',exact:true}).click()
    await page.getByRole('region',{name:'Room directory',exact:true}).getByRole('button',{name:new RegExp(title)}).click()
    const panel = page.getByRole('region',{name:title,exact:true})
    await panel.getByRole('button',{name:'Open thread (1)',exact:true}).click()
    await panel.getByText('Existing thread reply',{exact:true}).waitFor()
    return {page,panel}
  }
  const [host,member] = await Promise.all([open(owner),open(author)])
  const original = member.panel.locator('article').filter({hasText:'Original thread topic'})
  await member.panel.getByRole('button',{name:'Follow thread',exact:true}).click()
  await member.panel.getByRole('button',{name:'Original thread topic (1)',exact:true}).waitFor()
  await original.getByText('Room message actions',{exact:true}).click()
  await original.getByRole('button',{name:'Edit message',exact:true}).click()
  await original.getByLabel('Edit room message').fill('Edited thread topic')
  await original.getByRole('button',{name:'Save edit',exact:true}).click()
  await member.panel.getByRole('button',{name:'Edited thread topic (1)',exact:true}).waitFor()

  const edited = host.panel.locator('article').filter({hasText:'Edited thread topic'})
  await edited.getByText('Edited',{exact:true}).waitFor()
  await edited.getByText('Room message actions',{exact:true}).click()
  host.page.once('dialog', dialog=>void dialog.accept())
  await edited.getByRole('button',{name:'Redact message',exact:true}).click()
  await member.panel.getByRole('button',{name:'Message removed (1)',exact:true}).waitFor()
  await member.panel.locator('article').filter({hasText:'Message removed'}).waitFor()
  await member.panel.getByText('Existing thread reply',{exact:true}).waitFor()
  assert.equal(await member.panel.getByText('Edited thread topic',{exact:true}).count(),0)
  await member.panel.getByRole('button',{name:'Unfollow thread',exact:true}).waitFor()
  await host.panel.getByRole('group',{name:'Room tabs'}).getByRole('button',{name:'Pins',exact:true}).click()
  await host.panel.getByText('No pinned messages.',{exact:true}).waitFor()
  console.log('Passed live room parent edit and redaction, preserving reply, count and follow and clearing the pin.')
} finally {
  await browser.close()
}
