// Run against the isolated loopback candidate with synthetic call networking.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { watchCallQos } from './helpers/call-qos.mjs'

const app=new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase=new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname,'127.0.0.1')
assert.equal(supabase.hostname,'127.0.0.1')
const {SECTALK_STORAGE_TEST_PUBLIC_KEY:key,SECTALK_STORAGE_TEST_SERVICE_KEY:serviceKey}=process.env
assert.ok(key&&serviceKey)
const options={auth:{persistSession:false,autoRefreshToken:false}}
const admin=createClient(supabase.href,serviceKey,options)
const suffix=randomUUID().slice(0,8)
const password=randomUUID()+'1!Q'
const sampleQuality = process.env.SECTALK_TEST_QOS === '1'
const testAnalytics = process.env.SECTALK_TEST_ANL_02 === '1'
const qualitySamples = new WeakMap()

function data(result){
  if(result.error)throw new Error(result.error.message)
  return result.data
}

async function account(name){
  const handle=name.toLowerCase()+'_'+suffix
  const email=handle+'@example.org'
  data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  const client=createClient(supabase.href,key,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:name}))
  return {client,email,handle}
}

const caller=await account('RingCaller')
const callee=await account('RingCallee')
const chat=data(await caller.client.rpc('st_request',{p_handle:callee.handle}))
data(await callee.client.rpc('st_respond',{p_chat:chat,p_accept:true}))
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const browser=await chromium.launch({
  executablePath:process.env.SECTALK_TEST_BROWSER,
  args:['--use-fake-device-for-media-stream','--use-fake-ui-for-media-stream'],
})

async function openChat(person,peerName){
  const page=await browser.newPage({locale:'en-US'})
  if (sampleQuality) qualitySamples.set(page, watchCallQos(page, 'direct'))
  await page.addInitScript(()=>{
    const Peer=window.RTCPeerConnection
    window.testCallPeers = []
    window.RTCPeerConnection=class extends Peer {
      constructor(config){
        super({...config,iceServers:[],iceTransportPolicy:'all'})
        window.testCallPeers.push(this)
      }
      setConfiguration(config){super.setConfiguration({...config,iceServers:[],iceTransportPolicy:'all'})}
    }
  })
  await page.goto(app.href)
  await page.getByLabel('Email address',{exact:true}).fill(person.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await page.locator('.chat-item').filter({hasText:peerName}).click()
  return page
}

async function lastCall(){
  return data(await caller.client.from('st_calls').select('id,status,end_reason').eq('chat_id',chat)
    .order('created_at',{ascending:false}).limit(1).single())
}

try{
  const [origin,first,second]=await Promise.all([
    openChat(caller,'RingCallee'),openChat(callee,'RingCaller'),openChat(callee,'RingCaller'),
  ])
  const callPanel=page=>page.getByRole('region',{name:'Audio call',exact:true})
  const callButton=(page,name)=>callPanel(page).getByRole('button',{name,exact:true})
  async function ring(){
    await origin.getByRole('button',{name:'Start audio call',exact:true}).click()
    await Promise.all([first,second].map(page=>callButton(page,'Answer').waitFor()))
  }
  async function noRings(){
    await Promise.all([origin,first,second].map(page=>callPanel(page).waitFor({state:'hidden'})))
  }

  await ring()
  let arrivals=0
  let release
  const barrier=new Promise(resolve=>{release=resolve})
  const decisions=[]
  for(const page of [first,second]){
    await page.route('**/rpc/st_v6_call_action',async route=>{
      if(route.request().postDataJSON().p_action==='accept'){
        arrivals+=1
        if(arrivals===2)release()
        await barrier
        const response=await route.fetch()
        decisions.push(await response.json())
        await route.fulfill({response})
      }else await route.continue()
    })
  }
  await Promise.all([first,second].map(page=>callButton(page,'Answer').click()))
  const loser=await Promise.race([first,second].map(async page=>{
    await page.getByText('Call answered on another device.',{exact:true}).waitFor()
    return page
  }))
  const winner=loser===first?second:first
  await callButton(winner,'Hang up').waitFor()
  await callPanel(loser).waitFor({state:'hidden'})
  assert.deepEqual(decisions.sort(),['accepted','answered_elsewhere'])
  const active=await lastCall()
  assert.equal(active.status,'active')
  if (sampleQuality) {
    for (const page of [origin, winner]) {
      assert.match(await qualitySamples.get(page)('setup'), /^(fast|moderate|slow)$/)
      assert.equal(await qualitySamples.get(page)('relay'), 'non_relayed')
      if (testAnalytics) {
        assert.equal(await qualitySamples.get(page)('join', 'started', false), 'started')
        assert.equal(await qualitySamples.get(page)('join', 'connected'), 'connected')
        assert.match(await qualitySamples.get(page)('mos'), /^(below_2|2_to_3|3_to_4|4_or_more)$/)
      }
    }
    if (testAnalytics) assert.equal(await qualitySamples.get(origin)('ice_restart', 'not_requested'), 'not_requested')
    await origin.evaluate(() => {
      const peer = window.testCallPeers.find(connection => connection.connectionState === 'connected')
      Object.defineProperty(peer, 'connectionState', { value: 'disconnected', configurable: true })
      peer.dispatchEvent(new Event('connectionstatechange'))
      window.resumeTestCall = () => {
        Reflect.deleteProperty(peer, 'connectionState')
        peer.dispatchEvent(new Event('connectionstatechange'))
      }
    })
    if (testAnalytics) assert.equal(await qualitySamples.get(origin)('ice_restart', 'requested'), 'requested')
    await origin.evaluate(() => window.resumeTestCall())
    assert.equal(await qualitySamples.get(origin)('recovery'), 'recovered')
  }
  data(await callee.client.rpc('st_call_status',{p_call:active.id,p_accept:false}))
  assert.equal((await lastCall()).status,'active')
  await callButton(winner,'Hang up').click()
  await noRings()
  assert.equal((await lastCall()).status,'ended')

  await ring()
  await callButton(first,'Busy').click()
  await Promise.all([
    origin.getByText('Your contact is busy.',{exact:true}).waitFor(),
    second.getByText('Call marked busy on another device.',{exact:true}).waitFor(),
  ])
  await noRings()
  assert.equal((await lastCall()).end_reason,'busy')

  await ring()
  await callButton(second,'Decline').click()
  await Promise.all([
    origin.getByText('Your contact declined the call.',{exact:true}).waitFor(),
    first.getByText('Call declined on another device.',{exact:true}).waitFor(),
  ])
  await noRings()
  assert.equal((await lastCall()).end_reason,'declined')

  await ring()
  await callButton(origin,'Cancel call').click()
  await Promise.all([first,second].map(page=>page.getByText('The caller cancelled.',{exact:true}).waitFor()))
  await noRings()
  assert.equal((await lastCall()).end_reason,'cancelled')
}finally{
  await browser.close()
}
console.log('Passed three browsers, competing answers, losing-device dismissal, endpoint ownership, busy, decline, and caller cancellation.')
if (sampleQuality) console.log('Passed direct call setup, selected ICE route, and recovery sample privacy and delivery.')
