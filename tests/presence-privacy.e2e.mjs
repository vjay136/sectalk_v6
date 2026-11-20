// Run against the isolated loopback app and Supabase stack.
import assert from 'node:assert/strict'
import {randomUUID} from 'node:crypto'
import {createClient} from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.hostname, '127.0.0.1')
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const serviceKey = process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
assert.ok(publicKey && serviceKey)
const {chromium} = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const options = {auth:{persistSession:false,autoRefreshToken:false}}
const service = createClient(supabase.href,serviceKey,options)
const suffix = randomUUID().slice(0,8)
const password = randomUUID() + '1!Q'

function data(result) {
  if(result.error) throw new Error(result.error.message)
  return result.data
}

async function account(name) {
  const handle = name.toLowerCase() + '_' + suffix
  const email = handle + '@example.org'
  data(await service.auth.admin.createUser({email,password,email_confirm:true}))
  const client = createClient(supabase.href,publicKey,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:name}))
  return {client,email,handle}
}

const [owner,peer] = await Promise.all([account('PrivacyOwner'),account('PrivacyPeer')])
const chat = data(await owner.client.rpc('st_request',{p_handle:peer.handle}))
data(await peer.client.rpc('st_respond',{p_chat:chat,p_accept:true}))
data(await owner.client.rpc('st_v2_create_workspace',{p_name:'Privacy workspace ' + suffix}))
data(await owner.client.rpc('st_v5_profile_details_save',{p_status:'Available for the project',p_refresh_photo:false}))
data(await owner.client.rpc('st_v5_set_last_seen',{p_enabled:true}))

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
  const nav = ownerPage.getByRole('navigation',{name:'SecTalk features'})
  async function openAvailability() {
    await nav.getByRole('button',{name:'Profile',exact:true}).click()
    await ownerPage.getByRole('button',{name:'Availability',exact:true}).click()
  }

  await peerPage.locator('.chat-item').filter({hasText:'PrivacyOwner'}).click()
  await openAvailability()
  const state = ownerPage.getByLabel(/Availability for approved contacts/)
  const sharing = ownerPage.getByRole('checkbox',{name:'Share availability and status with approved contacts'})
  const contactState = peerPage.getByLabel('Contact availability')
  const customStatus = peerPage.getByText('Available for the project',{exact:true})
  async function expectState(label) {
    await contactState.filter({hasText:new RegExp('^'+label+'$')}).waitFor({timeout:9000})
  }

  await state.selectOption('online')
  await ownerPage.bringToFront()
  const heartbeat = ownerPage.waitForResponse(response => response.ok() && response.url().endsWith('/rpc/st_v3_ping'))
  await ownerPage.evaluate(() => window.dispatchEvent(new Event('online')))
  await heartbeat
  await expectState('Online')
  await customStatus.waitFor()
  await sharing.click()
  await expectState('Offline')
  await customStatus.waitFor({state:'detached',timeout:9000})
  assert.equal(data(await peer.client.rpc('st_v5_last_seen',{p_chat:chat})),null)
  await sharing.click()
  await expectState('Online')
  await state.selectOption('invisible')
  await expectState('Offline')
  await customStatus.waitFor({state:'detached',timeout:9000})

  await nav.getByRole('button',{name:'Workspaces',exact:true}).click()
  await ownerPage.getByRole('button',{name:'People',exact:true}).click()
  const workspacePolicy = ownerPage.getByRole('form',{name:'Workspace availability policy'})
  await workspacePolicy.getByLabel('Availability sharing').selectOption('required')
  await workspacePolicy.getByRole('button',{name:'Save availability policy'}).click()
  await workspacePolicy.locator('select option:checked').filter({hasText:'Require sharing'}).waitFor({state:'attached'})
  await openAvailability()
  await ownerPage.getByText(/Your availability stays private until you choose a state/).waitFor()
  assert.equal(await state.locator('option[value=invisible]').count(),0)
  assert.equal(await sharing.count(),0)
  await expectState('Offline')
  await state.selectOption('away')
  await expectState('Away')
  await customStatus.waitFor()
  console.log('Passed account privacy, Invisible, and owner-enforced workspace policy across two browsers.')
} finally {
  await browser.close()
}
