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

function observeCallAudio() {
  window.callAudioSamples=[]
  const start=AudioBufferSourceNode.prototype.start
  AudioBufferSourceNode.prototype.start=function(...args) {
    if(this.loop&&[3,5].includes(this.buffer?.duration)) {
      const record={seconds:this.buffer.duration,peak:0,ended:false}
      window.callAudioSamples.push(record)
      const analyser=this.context.createAnalyser()
      this.connect(analyser)
      const values=new Float32Array(analyser.fftSize)
      const timer=setInterval(()=>{
        analyser.getFloatTimeDomainData(values)
        for(const value of values)record.peak=Math.max(record.peak,Math.abs(value))
        if(record.peak>0.04)clearInterval(timer)
      },20)
      this.addEventListener('ended',()=>{
        record.ended=true
        clearInterval(timer)
      },{once:true})
    }
    return start.apply(this,args)
  }
}

function blockCallAudioUntilGesture() {
  const BrowserAudioContext=window.AudioContext
  let activated=false
  let release
  const userGesture=new Promise(resolve=>{release=resolve})
  const unlock=event=>{
    if(event.isTrusted) {
      activated=true
      release()
    }
  }
  window.addEventListener('keydown',unlock,true)
  window.addEventListener('click',unlock,true)
  window.AudioContext=class extends BrowserAudioContext {
    get state(){return activated?super.state:'suspended'}
    async resume(){
      await userGesture
      await super.resume()
      this.dispatchEvent(new Event('statechange'))
    }
  }
}

async function heard(page,seconds,count) {
  await page.waitForFunction(({seconds,count})=>window.callAudioSamples
    .filter(record=>record.seconds===seconds&&record.peak>0.04).length===count,{seconds,count})
}

async function stopped(page,seconds,count) {
  await page.waitForFunction(({seconds,count})=>window.callAudioSamples
    .filter(record=>record.seconds===seconds&&record.ended).length===count,{seconds,count})
}

try {
  const owner=await account('Accessibility owner')
  const contact=await account('Accessibility contact')
  const chat=data(await owner.client.rpc('st_request',{p_handle:contact.handle}))
  data(await contact.client.rpc('st_respond',{p_chat:chat,p_accept:true}))
  const page=await browser.newPage({viewport:{width:1366,height:900},locale:'en-US'})
  await page.addInitScript(observeCallAudio)
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
  await receiver.addInitScript(observeCallAudio)
  await receiver.addInitScript({path:process.env.SECTALK_AXE_SCRIPT})
  await signIn(receiver,contact)
  const callAnnouncement=receiver.locator('.call-announcement')
  assert.equal(await callAnnouncement.textContent(),'')
  const idleAnnouncement=await callAnnouncement.elementHandle()
  const start=page.getByRole('button',{name:'Start audio call',exact:true})
  await start.focus()
  await page.keyboard.press('Enter')
  const incoming=receiver.getByRole('region',{name:'Audio call',exact:true})
  await incoming.waitFor()
  const callAccessibility=await incoming.ariaSnapshot()
  assert.match(callAccessibility,/Audio · Incoming call/)
  assert.match(callAccessibility,/button "Answer"/)
  await Promise.all([heard(page,5,1),heard(receiver,3,1)])
  await receiver.getByRole('alert').filter({hasText:'Incoming audio call from Accessibility owner.'}).waitFor()
  assert.equal(await idleAnnouncement.evaluate(node=>node.textContent),'Incoming audio call from Accessibility owner.')
  await scan(receiver,'Incoming audio call')
  await incoming.getByLabel('Call menu',{exact:true}).focus()
  await receiver.keyboard.press('Enter')
  await incoming.getByRole('button',{name:'Decline call',exact:true}).focus()
  await receiver.keyboard.press('Enter')
  await incoming.waitFor({state:'hidden'})
  await Promise.all([stopped(page,5,1),stopped(receiver,3,1)])
  assert.equal(await idleAnnouncement.evaluate(node=>node.textContent),'')
  data(await contact.client.rpc('st_v6_set_quiet_mute',{p_chat:chat,p_muted:true}))
  await page.waitForFunction(()=>document.querySelector('button[aria-label="Start audio call"]')?.disabled===false)
  const mutedDecision=receiver.waitForResponse(response=>response.url().endsWith('/rpc/st_v6_direct_alert_quiet'))
  await start.press('Enter')
  assert.equal(await (await mutedDecision).json(),true)
  assert.equal(await idleAnnouncement.evaluate(node=>node.textContent),'')
  assert.equal(await incoming.count(),0)
  await heard(page,5,2)
  assert.equal(await receiver.evaluate(()=>window.callAudioSamples.length),1)
  const outgoing=page.getByRole('region',{name:'Audio call',exact:true})
  await outgoing.getByRole('button',{name:'Cancel call',exact:true}).press('Enter')
  await outgoing.waitFor({state:'hidden'})
  await stopped(page,5,2)
  data(await contact.client.rpc('st_v6_set_quiet_mute',{p_chat:chat,p_muted:false}))
  const priorSession=await receiver.context().storageState()
  await receiver.close()
  const freshReceiver=await browser.newPage({viewport:{width:1100,height:900},locale:'en-US',storageState:priorSession})
  await freshReceiver.addInitScript(observeCallAudio)
  await freshReceiver.addInitScript(blockCallAudioUntilGesture)
  await freshReceiver.goto(app+'/#account')
  await freshReceiver.getByRole('navigation',{name:'SecTalk features'}).waitFor()
  for(const side of [page,freshReceiver])await side.route('**/api/ice?*',request=>request.fulfill({
    json:{iceServers:[],iceTransportPolicy:'all',ttlSeconds:null},
  }))
  await page.getByRole('button',{name:'Start video call',exact:true}).press('Enter')
  const incomingVideo=freshReceiver.getByRole('region',{name:'Video call',exact:true})
  await incomingVideo.waitFor()
  assert.equal(await freshReceiver.evaluate(()=>window.callAudioSamples.length),0)
  await incomingVideo.getByRole('button',{name:'Enable call sounds',exact:true}).press('Enter')
  await Promise.all([heard(page,5,3),heard(freshReceiver,3,1)])
  await incomingVideo.getByRole('button',{name:'Answer',exact:true}).press('Enter')
  await Promise.all([stopped(page,5,3),stopped(freshReceiver,3,1)])
  await incomingVideo.getByRole('button',{name:'Hang up',exact:true}).press('Enter')
  await incomingVideo.waitFor({state:'hidden'})
  await freshReceiver.close()
  const headings={
    'Group chats':'Group chats', Friends:'Find Friends', Calls:'Calls', Workspaces:'Workspaces', Rooms:'Rooms',
    Tasks:'Direct chat tasks', Calendar:'Calendar', Meetings:'Meetings', Files:'Files', Search:'Search', Notifications:'Notifications',
    Safety:'Safety center', Billing:'Billing', Profile:'Profile',
  }
  for(const [section,heading] of Object.entries(headings)) {
    const button=navigation.getByRole('button',{name:section,exact:true})
    await button.focus()
    await page.keyboard.press('Enter')
    if(section==='Tasks') {
      await page.getByRole('group',{name:'Task sections'}).getByRole('button',{name:'Room and chat tasks',exact:true}).press('Enter')
      await page.getByRole('group',{name:'Task workspace scope'}).getByRole('button',{name:'Direct chat tasks',exact:true}).press('Enter')
    }
    await page.getByRole('heading',{name:heading,exact:true}).waitFor()
    assert.equal(await button.getAttribute('aria-current'),'page',section+' is the current keyboard destination')
    await scan(page,section)
  }
  await navigation.getByRole('button',{name:'Profile',exact:true}).press('Enter')
  await page.getByRole('button',{name:'Privacy and data',exact:true}).press('Enter')
  const privacy=page.getByRole('region',{name:'Account privacy and data',exact:true})
  const exportButton=privacy.getByRole('button',{name:'Export my data',exact:true})
  await exportButton.press('Enter')
  await privacy.getByLabel('Current password',{exact:true}).waitFor()
  await page.waitForFunction(()=>document.activeElement?.getAttribute('name')==='credential')
  await scan(page,'Personal data export verification')
  await privacy.getByRole('button',{name:'Back to data settings',exact:true}).press('Enter')
  await privacy.getByLabel('Current password',{exact:true}).waitFor({state:'hidden'})
  await page.waitForFunction(()=>document.activeElement?.textContent==='Export my data')
  const deleteButton=privacy.getByRole('button',{name:'Delete my account',exact:true})
  await deleteButton.press('Enter')
  await page.waitForFunction(()=>document.activeElement?.getAttribute('name')==='confirmation')
  await scan(page,'Account deletion confirmation')
  await privacy.getByRole('button',{name:'Back to data settings',exact:true}).press('Enter')
  await page.waitForFunction(()=>document.activeElement?.textContent==='Delete my account')
  await navigation.getByRole('button',{name:'Notifications',exact:true}).press('Enter')
  await page.setViewportSize({width:390,height:844})
  await scan(page,'Notifications on mobile')
  await page.goto(app+'/status')
  await page.getByRole('main').waitFor()
  await scan(page,'Public status on mobile')
  await page.goto(app+'/legal/privacy')
  await page.getByRole('heading',{name:'Privacy notice',exact:true}).waitFor()
  await scan(page,'Public privacy on mobile')
  for(const item of issues) console.log(JSON.stringify(item))
  assert.deepEqual(issues.map(item=>item.label),[],'WCAG rules reported violations in checked views')
  console.log('Passed desktop and mobile accessibility scans, keyboard actions, live call announcements, and audible voice and video ringing on both sides.')
} finally {
  await browser.close()
  for(const id of users) await admin.auth.admin.deleteUser(id)
}
