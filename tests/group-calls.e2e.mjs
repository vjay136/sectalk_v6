// Five local Edge sessions, synthetic microphones, local Supabase and LiveKit.
import assert from 'node:assert/strict'
import {randomUUID} from 'node:crypto'
import {createClient} from '@supabase/supabase-js'
import {RoomServiceClient} from 'livekit-server-sdk'

const video=process.env.SECTALK_GROUP_VIDEO==='1'
const mode=video?'video':'audio'
const app=new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase=new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.href,'http://127.0.0.1:3503/')
assert.equal(supabase.hostname,'127.0.0.1')
const {SECTALK_STORAGE_TEST_PUBLIC_KEY:key,SECTALK_STORAGE_TEST_SERVICE_KEY:serviceKey}=process.env
assert.ok(key && serviceKey)
const auth={persistSession:false,autoRefreshToken:false}
const admin=createClient(supabase.href,serviceKey,{auth})
const provider=new RoomServiceClient('http://127.0.0.1:7880','devkey','secret')
const password=randomUUID()+'!1Q'
const people=[]
let browser

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

async function account(name) {
  const handle=name.toLowerCase()+'_'+randomUUID().slice(0,8)
  const email=handle+'@example.org'
  const {user}=data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  const client=createClient(supabase.href,key,{auth})
  const person={client,id:user.id,handle,email,name}
  people.push(person)
  person.token=data(await client.auth.signInWithPassword({email,password})).session.access_token
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:name}))
  return person
}

try {
  const [host,...guests]=await Promise.all(['GroupOwner','GroupOne','GroupTwo','GroupThree','GroupFour'].map(account))
  const outsider=await account('GroupOutside')
  for (const person of guests) {
    const chat=data(await host.client.rpc('st_request',{p_handle:person.handle}))
    data(await person.client.rpc('st_respond',{p_chat:chat,p_accept:true}))
  }
  const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER,
    args:['--use-fake-device-for-media-stream','--use-fake-ui-for-media-stream']})
  async function open(person) {
    const page=await browser.newPage({locale:'en-US',permissions:['microphone','camera']})
    await page.addInitScript(cameraDenied=>{
      const Native=window.RTCPeerConnection
      window.groupTestPeers=[]
      window.RTCPeerConnection=class extends Native {
        constructor(config){super(config);window.groupTestPeers.push(this)}
      }
      if (cameraDenied) {
        const capture=navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices)
        navigator.mediaDevices.getUserMedia=constraints=>constraints.video
          ? Promise.reject(new DOMException('Fixture denied camera','NotAllowedError')) : capture(constraints)
      }
    },video && person===guests[3])
    await page.goto(app.href)
    await page.getByLabel('Email address',{exact:true}).fill(person.email)
    await page.getByLabel('Password',{exact:true}).fill(password)
    await page.locator('button.submit-auth').click()
    await page.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Calls',exact:true}).click()
    await page.getByRole('group',{name:'Call history'}).getByRole('button',{name:'Groups',exact:true}).click()
    return page
  }
  const pages=await Promise.all([host,...guests].map(open))
  const panel=page=>page.getByRole('region',{name:'Group calls',exact:true})
  const button=(page,name)=>panel(page).getByRole('button',{name,exact:true})
  for (const person of guests) await panel(pages[0]).getByRole('checkbox',{name:person.name,exact:true}).check()
  const created=pages[0].waitForResponse(response=>response.url().endsWith('/rpc/st_v6_group_call')&&
    response.request().postDataJSON()?.p_action==='create')
  await button(pages[0],'Start group '+mode).click()
  const creation=await created
  assert.equal(creation.status(),200)
  const call=(await creation.json()).id
  assert.ok(call)
  const denied=await fetch(new URL('/api/group-calls',app),{method:'POST',headers:{
    'Content-Type':'application/json',Authorization:'Bearer '+outsider.token,
  },body:JSON.stringify({call,device:randomUUID(),action:'ice'})})
  assert.equal(denied.status,403)
  for (const page of pages.slice(1,4)) await button(page,'Join group '+mode).click()

  async function hear(page,route,count,cameras=video?count:0) {
    await page.waitForFunction(async({route,count,cameras})=>{
      const audio=[...document.querySelectorAll('[data-group-route="'+route+'"] audio')]
      if (audio.length!==count || audio.some(element=>element.muted || !element.srcObject?.getAudioTracks().length)) return false
      const video=[...document.querySelectorAll('[data-group-route="'+route+'"] video:not([hidden])')]
      if (video.length!==cameras || video.some(element=>element.videoWidth<=0 || !element.srcObject?.getVideoTracks().length)) return false
      const trackIds=new Set(audio.map(element=>element.srcObject.getAudioTracks()[0].id))
      const cameraIds=new Set(video.map(element=>element.srcObject.getVideoTracks()[0].id))
      const reports=(await Promise.all(window.groupTestPeers.filter(peer=>peer.connectionState==='connected').map(peer=>peer.getStats())))
        .flatMap(report=>[...report.values()])
      return new Set(reports.filter(item=>item.type==='inbound-rtp'&&item.kind==='audio'&&item.totalAudioEnergy>0&&
        trackIds.has(item.trackIdentifier)).map(item=>item.trackIdentifier)).size===count &&
        new Set(reports.filter(item=>item.type==='inbound-rtp'&&item.kind==='video'&&item.framesDecoded>0&&
          cameraIds.has(item.trackIdentifier)).map(item=>item.trackIdentifier)).size===cameras
    },{route,count,cameras},{timeout:35000})
  }
  await Promise.all(pages.slice(0,4).map(page=>hear(page,'mesh',3)))
  await pages[0].waitForFunction(()=>window.groupTestPeers.filter(peer=>peer.connectionState==='connected').length===3)
  if (video) {
    await button(pages[0],'Turn group camera off').click()
    await button(pages[0],'Turn group camera on').click()
  }

  const fifth=pages[4]
  const block=route=>route.request().postDataJSON()?.action==='sfu'
    ? route.fulfill({status:503,contentType:'application/json',body:'{}'}) : route.continue()
  await fifth.route('**/api/group-calls',block)
  await button(fifth,'Join group '+mode).click()
  if (video) {
    await panel(fifth).getByText(/Camera unavailable/).waitFor()
    assert.equal(await button(fifth,'Turn group camera off').count(),0)
  }
  await panel(pages[0]).getByText('Connecting shared group media',{exact:true}).waitFor()
  await hear(pages[0],'mesh',3)
  await panel(pages[0]).getByText('Group '+mode+' on direct peers',{exact:true}).waitFor({timeout:26000})
  await button(fifth,'Join group '+mode).waitFor()
  await hear(pages[0],'mesh',3)
  await fifth.unroute('**/api/group-calls',block)

  await button(fifth,'Join group '+mode).click()
  await Promise.all(pages.map(page=>panel(page).getByText('Group '+mode+' on shared media',{exact:true}).waitFor({timeout:32000})))
  await Promise.all(pages.map(page=>hear(page,'sfu',4,video?(page===fifth?4:3):0)))
  assert.equal(await pages[0].locator('[data-group-route="mesh"]').count(),0)
  const live=await provider.listParticipants('sectalk-group-'+call+'-2')
  assert.equal(live.length,5)
  assert.ok(live.every(person=>person.tracks.length===(video && person.identity!==guests[3].id?2:1)))
  const blockReverse=route=>route.request().postDataJSON()?.action==='ice'
    ? route.fulfill({status:503,contentType:'application/json',body:'{}'}) : route.continue()
  await pages[3].route('**/api/group-calls',blockReverse)
  await button(fifth,'Leave group '+mode).click()
  await panel(pages[0]).getByText('Connecting direct group peers',{exact:true}).waitFor()
  await Promise.all(pages.slice(0,4).map(page=>hear(page,'sfu',3)))
  await panel(pages[0]).getByText('Group '+mode+' on shared media',{exact:true}).waitFor({timeout:26000})
  await pages[3].unroute('**/api/group-calls',blockReverse)
  await Promise.all(pages.slice(0,4).map(page=>panel(page).getByText('Group '+mode+' on direct peers',{exact:true}).waitFor({timeout:32000})))
  await Promise.all(pages.slice(0,4).map(page=>hear(page,'mesh',3)))
  assert.equal(await pages[0].locator('[data-group-route="sfu"]').count(),0)
  await button(pages[0],'End group '+mode).click()
  await Promise.all(pages.slice(1).map(page=>button(page,'Leave group '+mode).waitFor({state:'hidden'})))
  if (video) {
    await panel(pages[0]).getByRole('checkbox',{name:guests[3].name,exact:true}).check()
    await button(pages[0],'Start group video').click()
    await button(fifth,'Join group video').click()
    await panel(fifth).getByText(/Camera unavailable/).waitFor()
    await Promise.all([hear(pages[0],'mesh',1,0),hear(fifth,'mesh',1,1)])
    await button(pages[0],'End group video').click()
    await button(fifth,'Leave group video').waitFor({state:'hidden'})
  }
  console.log('Group '+mode+' passed native mesh, LiveKit handoff, rollback in both directions, and reverse mesh.')
} finally {
  await browser?.close()
  await Promise.allSettled(people.map(person=>admin.auth.admin.deleteUser(person.id)))
}
