import assert from 'node:assert/strict'
import {randomUUID} from 'node:crypto'
import {createClient} from '@supabase/supabase-js'

const app=new URL(process.env.SECTALK_STORAGE_TEST_APP).origin
const database=new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
for(const value of [app,database]) assert.equal(new URL(value).hostname,'127.0.0.1')
assert.ok(process.env.SECTALK_AXE_SCRIPT,'Supply a local axe-core browser bundle')
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER,
  args:['--use-fake-device-for-media-stream','--use-fake-ui-for-media-stream']})
const auth={persistSession:false,autoRefreshToken:false}
const admin=createClient(database,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,{auth})
const password=randomUUID()+'!Aa9'
const users=[]
const issues=[]

function data(result) {
  if(result.error) throw new Error(result.error.message)
  return result.data
}

async function account(label) {
  const handle='axa_'+randomUUID().slice(0,8)
  const email=handle+'@example.org'
  const {user}=data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  users.push(user.id)
  const client=createClient(database,process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY,{auth})
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:label}))
  return {client,email,handle}
}

async function scan(page,label) {
  const findings=await page.evaluate(async()=>{
    const results=await axe.run({runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa']}})
    return results.violations.map(({id,nodes})=>({id,targets:nodes.map(node=>node.target.join(' '))}))
  })
  if(findings.length) issues.push({label,findings})
}

async function signIn(page,person) {
  await page.goto(app+'/#account')
  await page.getByLabel('Email address',{exact:true}).fill(person.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.getByLabel('Password',{exact:true}).press('Enter')
  await page.getByRole('navigation',{name:'SecTalk features'}).waitFor()
}

try {
  const owner=await account('Accessibility owner')
  const contact=await account('Accessibility contact')
  const chat=data(await owner.client.rpc('st_request',{p_handle:contact.handle}))
  data(await contact.client.rpc('st_respond',{p_chat:chat,p_accept:true}))
  const page=await browser.newPage({viewport:{width:1366,height:900},locale:'en-US'})
  await page.addInitScript({path:process.env.SECTALK_AXE_SCRIPT})
  await page.goto(app+'/#account')
  await page.getByLabel('Email address',{exact:true}).waitFor()
  await scan(page,'Public sign-in')
  await page.getByRole('button',{name:'Forgot password?',exact:true}).focus()
  await page.keyboard.press('Enter')
  await page.getByRole('heading',{name:'Reset your password',exact:true}).waitFor()
  await scan(page,'Password recovery')
  await page.goto(app+'/pricing')
  await signIn(page,owner)
  const navigation=page.getByRole('navigation',{name:'SecTalk features'})
  await navigation.waitFor()
  const contactButton=page.getByRole('button',{name:/Accessibility contact/}).first()
  await contactButton.focus()
  await page.keyboard.press('Enter')
  const composer=page.getByRole('textbox',{name:'Write a message'})
  await composer.fill('Keyboard test message')
  await composer.press('Enter')
  await page.getByText('Keyboard test message',{exact:true}).waitFor()
  const chatAccessibility=await page.getByRole('main').ariaSnapshot()
  assert.match(chatAccessibility,/log "Messages"/)
  assert.match(chatAccessibility,/textbox "Write a message"/)
  assert.match(chatAccessibility,/button "Attach file"/)
  assert.match(chatAccessibility,/button "Send message"/)
  await page.getByLabel('Message actions',{exact:true}).focus()
  await page.keyboard.press('Enter')
  await page.getByRole('button',{name:'Reply',exact:true}).waitFor()
  await scan(page,'Open message actions')

  const receiver=await browser.newPage({viewport:{width:1100,height:900},locale:'en-US'})
  await receiver.addInitScript({path:process.env.SECTALK_AXE_SCRIPT})
  await signIn(receiver,contact)
  const start=page.getByRole('button',{name:'Start audio call',exact:true})
  await start.focus()
  await page.keyboard.press('Enter')
  const incoming=receiver.getByRole('region',{name:'Audio call',exact:true})
  await incoming.waitFor()
  const callAccessibility=await incoming.ariaSnapshot()
  assert.match(callAccessibility,/status: Audio · Incoming call/)
  assert.match(callAccessibility,/button "Answer"/)
  await scan(receiver,'Incoming audio call')
  await incoming.getByLabel('Call menu',{exact:true}).focus()
  await receiver.keyboard.press('Enter')
  await incoming.getByRole('button',{name:'Decline call',exact:true}).focus()
  await receiver.keyboard.press('Enter')
  await incoming.waitFor({state:'hidden'})
  await receiver.close()
  for(const section of ['Calls','Workspaces','Safety','Billing','Profile','Notifications']) {
    const button=navigation.getByRole('button',{name:section,exact:true})
    await button.focus()
    await page.keyboard.press('Enter')
    assert.equal(await button.getAttribute('aria-current'),'page')
    await page.locator('.content-page').waitFor()
    await scan(page,section)
  }
  await page.setViewportSize({width:390,height:844})
  await scan(page,'Notifications on mobile')
  await page.goto(app+'/status')
  await page.getByRole('main').waitFor()
  await scan(page,'Public status on mobile')
  for(const item of issues) console.log(JSON.stringify(item))
  assert.deepEqual(issues.map(item=>item.label),[],'WCAG rules reported violations in checked views')
  console.log('Passed desktop and mobile accessibility scans, keyboard-only message and call actions, and accessible form controls.')
} finally {
  await browser.close()
  for(const id of users) await admin.auth.admin.deleteUser(id)
}
