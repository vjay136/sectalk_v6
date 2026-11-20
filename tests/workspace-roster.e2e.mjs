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
const service = createClient(supabase.href, serviceKey, options)
const suffix = randomUUID().slice(0,8)
const password = randomUUID() + '1!Q'

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

async function account(name) {
  const handle = name.toLowerCase() + '_' + suffix
  const email = handle + '@example.org'
  const client = createClient(supabase.href, publicKey, options)
  data(await service.auth.admin.createUser({email,password,email_confirm:true}))
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:name}))
  return {client,email,handle,name}
}

const [owner, member] = await Promise.all([account('RosterOwner'),account('RosterMember')])
const tenantName = 'Roster workspace ' + suffix
const workspace = data(await owner.client.rpc('st_v2_create_workspace',{p_name:tenantName}))
const browser = await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})

try {
  async function open(person) {
    const page = await browser.newPage()
    await page.goto(new URL('/#account',app).href)
    await page.getByLabel('Email address',{exact:true}).fill(person.email)
    await page.getByLabel('Password',{exact:true}).fill(password)
    await page.locator('button.submit-auth').click()
    await page.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Workspaces',exact:true}).click()
    return page
  }

  const ownerPage = await open(owner)
  await ownerPage.getByText('Import invitations from CSV',{exact:true}).click()
  await ownerPage.getByLabel('CSV file',{exact:true}).setInputFiles({
    name:'roster.csv',mimeType:'text/csv',
    buffer:Buffer.from('\ufeff"handle"\r\n"' + member.handle.toUpperCase() + '"\r\n' + member.handle + '\r\nmissing_' + suffix),
  })
  await ownerPage.getByRole('button',{name:'Send invitations',exact:true}).click()
  await ownerPage.getByText('1 of 2 invitations sent.',{exact:true}).waitFor()
  await ownerPage.getByText('@missing_' + suffix + ' · Unavailable or already invited',{exact:true}).waitFor()

  const memberPage = await open(member)
  await memberPage.getByRole('button',{name:'Join',exact:true}).click()
  const switcher = memberPage.getByRole('combobox',{name:'Active workspace'})
  await switcher.getByRole('option',{name:tenantName,exact:true}).waitFor({state:'attached'})
  assert.equal(await switcher.inputValue(), workspace)

  await ownerPage.getByRole('form',{name:'Suspend ' + member.name,exact:true}).getByRole('button',{name:'Suspend access'}).click()
  await ownerPage.getByText('Suspended',{exact:true}).waitFor()
  await switcher.waitFor({state:'detached',timeout:25000})

  await ownerPage.getByRole('form',{name:'Restore ' + member.name,exact:true}).getByRole('button',{name:'Restore access'}).click()
  await ownerPage.getByText('Suspended',{exact:true}).waitFor({state:'detached'})
  await switcher.getByRole('option',{name:tenantName,exact:true}).waitFor({state:'attached',timeout:25000})
  assert.equal(await switcher.inputValue(), workspace)
  console.log('Passed CSV invitation, browser acceptance, tenant suspension and restore.')
} finally {
  await browser.close()
}
