// Run against the isolated loopback app and Supabase stack.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.hostname, '127.0.0.1')
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const serviceKey = process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
assert.ok(publicKey && serviceKey)
const clientOptions = { auth:{ persistSession:false,autoRefreshToken:false } }
const admin = createClient(supabase.href,serviceKey,clientOptions)
const suffix = randomUUID().slice(0,8)
const password = randomUUID() + '1!Q'

function data(result) {
  if(result.error)throw new Error(result.error.message)
  return result.data
}

async function account(name) {
  const handle = name.toLowerCase() + '_' + suffix
  const email = handle + '@example.org'
  data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  const client = createClient(supabase.href,publicKey,clientOptions)
  const {user} = data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:name}))
  return {client,email,handle,id:user.id}
}

const owner = await account('PresenceOwner')
const peer = await account('PresencePeer')
const outside = await account('PresenceOther')
const chat = data(await owner.client.rpc('st_request',{p_handle:peer.handle}))
data(await peer.client.rpc('st_respond',{p_chat:chat,p_accept:true}))

const browser = await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
try {
  async function open(person) {
    const page = await browser.newPage()
    await page.goto(new URL('/#account',app).href)
    await page.getByLabel('Email address',{exact:true}).fill(person.email)
    await page.getByLabel('Password',{exact:true}).fill(password)
    await page.locator('button.submit-auth').click()
    await page.getByRole('navigation',{name:'SecTalk features'}).waitFor()
    return page
  }
  const [ownerPage,peerPage] = await Promise.all([open(owner),open(peer)])
  await peerPage.locator('.chat-item').filter({hasText:'PresenceOwner'}).click()
  await ownerPage.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Profile',exact:true}).click()
  await ownerPage.getByRole('button',{name:'Availability',exact:true}).click()
  const availability = ownerPage.getByLabel(/Availability for approved contacts/)
  const status = peerPage.locator('[aria-label="Contact availability"]')
  await status.filter({hasText:/^Offline$/}).waitFor()
  for(const [value,label] of [['online','Online'],['away','Away'],['busy','Busy'],['offline','Offline']]){
    await availability.selectOption(value)
    await status.filter({hasText:new RegExp('^'+label+'$')}).waitFor({timeout:9000})
    assert.equal(data(await outside.client.from('st_v3_presence').select('user_id').eq('user_id',owner.id)).length,0)
  }

  await ownerPage.close()
  data(await admin.from('st_v3_presence').update({state:'online',expires_at:new Date(Date.now()+4500).toISOString()}).eq('user_id',owner.id))
  await status.filter({hasText:/^Online$/}).waitFor({timeout:4000})
  await status.filter({hasText:/^Offline$/}).waitFor({timeout:7000})
  assert.equal(data(await peer.client.from('st_v3_presence').select('user_id').eq('user_id',owner.id)).length,0)

  data(await owner.client.rpc('st_v3_set_presence',{p_state:'away'}))
  await status.filter({hasText:/^Away$/}).waitFor({timeout:9000})
  data(await owner.client.rpc('st_set_block',{p_chat:chat,p_block:true}))
  await status.filter({hasText:/^Offline$/}).waitFor({timeout:9000})
  assert.equal(data(await peer.client.from('st_v3_presence').select('user_id').eq('user_id',owner.id)).length,0)
  data(await owner.client.rpc('st_set_block',{p_chat:chat,p_block:false}))
  await status.filter({hasText:/^Away$/}).waitFor({timeout:9000})
  console.log('Passed presence states, private live updates, access removal and stale expiry in two browsers.')
} finally {
  await browser.close()
}
