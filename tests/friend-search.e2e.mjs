// Run with an isolated app and Supabase project that have the discovery migration.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname,'127.0.0.1')
assert.equal(supabase.hostname,'127.0.0.1')
const serviceKey = process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
assert.ok(serviceKey)
const admin = createClient(supabase.href,serviceKey,{auth:{persistSession:false,autoRefreshToken:false}})
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const suffix = randomUUID().slice(0,8)
const users = [
  { handle:'finder_'+suffix, name:'Discovery Tester', publish:true },
  { handle:'birch_'+suffix, name:'Birch Zinnia '+suffix, publish:true },
  { handle:'cedar_'+suffix, name:'Cedar Zinnia '+suffix, publish:false },
]

const browser = await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
try {
  const pages = await Promise.all(users.map(async(user,index)=>{
    const email = user.handle+'@example.org'
    const password = randomUUID()+'1!Q'
    const {error} = await admin.auth.admin.createUser({email,password,email_confirm:true})
    if(error)throw error
    const context = await browser.newContext({viewport:{width:index===0?390:1050,height:844}})
    const page = await context.newPage()
    await page.goto(app.href)
    await page.getByLabel('Email address',{exact:true}).fill(email)
    await page.getByLabel('Password',{exact:true}).fill(password)
    await page.locator('button.submit-auth').click()
    await page.getByRole('heading',{name:'Set up your profile',exact:true}).waitFor()
    await page.getByLabel('Display name',{exact:true}).fill(user.name)
    await page.getByLabel('Handle',{exact:true}).fill(user.handle)
    await page.getByRole('button',{name:'Save profile',exact:false}).click()
    await page.getByRole('heading',{name:'Choose your interests',exact:true}).waitFor()
    await page.getByRole('combobox',{name:'Stage',exact:true}).selectOption('professional')
    await page.getByRole('button',{name:'Study fields',exact:true}).click()
    await page.getByLabel('Find a category',{exact:true}).fill('Cybersecurity')
    await page.getByRole('button',{name:'Cybersecurity',exact:true}).click()
    if(user.publish){
      await page.getByLabel('Appear in Find Friends',{exact:true}).check()
      await page.getByLabel('I am 18 or older',{exact:true}).check()
      if(index===1)await page.getByLabel('Show me in Online now',{exact:true}).check()
    }
    await page.getByRole('button',{name:'Save and continue',exact:true}).click()
    await page.getByRole('button',{name:'Find Friends',exact:true}).first().click()
    await page.getByRole('heading',{name:'Find Friends',exact:true}).waitFor()
    return page
  }))
  const [finder, onlinePeer, privateUser] = pages
  await privateUser.getByRole('heading',{name:'Discovery is off',exact:true}).waitFor()
  await privateUser.getByRole('group',{name:'Find Friends sections'}).getByRole('button',{name:'Use a handle',exact:true}).click()
  await privateUser.getByLabel('SecTalk handle',{exact:true}).waitFor()

  const field = finder.getByLabel('Search people',{exact:true})
  const submit = finder.getByRole('search',{name:'Find people'}).getByRole('button',{name:'Search',exact:true})
  await submit.waitFor()
  const visible = finder.getByRole('heading',{name:users[1].name,exact:true})
  const privateProfile = finder.getByRole('heading',{name:users[2].name,exact:true})
  await field.fill('z')
  await visible.waitFor()
  assert.equal(await privateProfile.count(),0)
  await field.fill('@'+users[1].handle.slice(0,-2))
  await submit.click()
  await visible.waitFor()
  assert.equal(await privateProfile.count(),0)
  await field.fill('Cybersecurity')
  await field.press('Enter')
  await finder.getByRole('group',{name:'Matching categories'}).getByRole('button',{name:'Cybersecurity',exact:true}).click()
  await visible.waitFor()
  assert.equal(await privateProfile.count(),0)
  await finder.getByRole('combobox',{name:'Stage',exact:true}).selectOption('retired')
  await finder.getByRole('heading',{name:'No new people found',exact:true}).waitFor()
  await finder.getByRole('combobox',{name:'Stage',exact:true}).selectOption('professional')
  await visible.waitFor()
  const categoryToggle = finder.getByRole('button',{name:'Categories',exact:true})
  await categoryToggle.press('Enter')
  await finder.getByLabel('Find a category',{exact:true}).fill('Cybersecurity')
  await finder.getByRole('button',{name:'Cybersecurity',exact:true}).press('Enter')
  assert.equal(await categoryToggle.getAttribute('aria-expanded'),'false')
  assert.equal(await categoryToggle.evaluate(button=>button===document.activeElement),true)
  await categoryToggle.press('Enter')
  await finder.getByRole('button',{name:'Cybersecurity',exact:true}).press('Enter')
  await visible.waitFor()
  const onlineToggle = finder.getByRole('button',{name:'Online now',exact:true})
  await onlineToggle.click()
  const onlineCard = finder.getByRole('listitem').filter({has:visible})
  await onlineCard.getByText('Online',{exact:true}).waitFor()
  assert.equal(await privateProfile.count(),0)
  await onlinePeer.getByRole('button',{name:'Profile',exact:true}).click()
  await onlinePeer.getByRole('button',{name:'Availability',exact:true}).click()
  await onlinePeer.getByRole('combobox',{name:'Availability for approved contacts'}).selectOption('offline')
  await visible.waitFor({state:'hidden',timeout:22000})
  await onlineToggle.click()
  await visible.waitFor()
  if(process.env.SECTALK_DISCOVERY_TEST_SCREENSHOT)await finder.screenshot({path:process.env.SECTALK_DISCOVERY_TEST_SCREENSHOT})
  assert.equal(await finder.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true)
  await finder.setViewportSize({width:320,height:740})
  assert.equal(await finder.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true)
  await finder.setViewportSize({width:1280,height:860})
  if(process.env.SECTALK_DISCOVERY_TEST_DESKTOP_SCREENSHOT)await finder.screenshot({path:process.env.SECTALK_DISCOVERY_TEST_DESKTOP_SCREENSHOT})
  await finder.setViewportSize({width:390,height:844})
  await finder.getByRole('button',{name:'Send request to @'+users[1].handle,exact:true}).click()
  await finder.getByText('Contact request is pending.',{exact:true}).waitFor()
  await finder.getByRole('button',{name:'Back to inbox',exact:true}).click()
  await finder.getByRole('button',{name:'Find Friends',exact:true}).first().click()
  await finder.getByLabel('Search people',{exact:true}).fill('@'+users[1].handle)
  await finder.getByRole('heading',{name:'No new people found',exact:true}).waitFor()
  console.log('Passed three-account discovery, single letters, category-based online search, privacy, mobile fit and contact requests.')
} finally {
  await browser.close()
}
