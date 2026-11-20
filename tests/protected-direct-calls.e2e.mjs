// Local Edge, Supabase and Coturn with synthetic tracks only.
import assert from 'node:assert/strict'
import {randomUUID} from 'node:crypto'
import {createClient} from '@supabase/supabase-js'

const app=new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase=new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.href,'http://127.0.0.1:3501/')
assert.equal(supabase.hostname,'127.0.0.1')
const {SECTALK_STORAGE_TEST_PUBLIC_KEY:key,SECTALK_STORAGE_TEST_SERVICE_KEY:serviceKey}=process.env
assert.ok(key && serviceKey)
const auth={persistSession:false,autoRefreshToken:false}
const admin=createClient(supabase.href,serviceKey,{auth})
const password=randomUUID()+'!1Q'
const accounts=[]
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
  accounts.push(person)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:name}))
  return person
}

try {
  const [one,two,outsider]=await Promise.all([account('ProtectedCaller'),account('ProtectedCallee'),account('ProtectedOther')])
  const chat=data(await one.client.rpc('st_request',{p_handle:two.handle}))
  data(await two.client.rpc('st_respond',{p_chat:chat,p_accept:true}))
  const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER,
    args:['--use-fake-device-for-media-stream','--use-fake-ui-for-media-stream']})
  async function open(person,target,unsupported=false) {
    const page=await browser.newPage({locale:'en-US',permissions:['microphone','camera']})
    await page.addInitScript(disable=>{
      const Peer=window.RTCPeerConnection
      const Delegate=window.RTCRtpScriptTransform
      const BrowserWorker=window.Worker
      window.callTest={peers:[],decoded:[],transforms:[],states:[],workerErrors:[],wrongKey:null}
      window.RTCPeerConnection=class extends Peer {
        constructor(config) {
          super(config)
          window.callTest.peers.push(this)
          this.addEventListener('connectionstatechange',()=>window.callTest.states.push(this.connectionState))
        }
      }
      window.Worker=class extends BrowserWorker {
        constructor(url,options) {
          super(url,options)
          if (url==='/protected-call-frames.js') this.addEventListener('message',event=>{
            if (event.data?.type==='decoded') window.callTest.decoded.push(event.data.kind)
            if (event.data?.type==='error') window.callTest.workerErrors.push('Worker reported a stream failure')
          })
          if (url==='/protected-call-frames.js') this.addEventListener('error',event=>window.callTest.workerErrors.push(event.message))
        }
      }
      if (disable) Object.defineProperty(window,'RTCRtpScriptTransform',{configurable:true,value:undefined})
      else if (Delegate) window.RTCRtpScriptTransform=class extends Delegate {
        constructor(worker,options) {
          const wrong=options?.op==='decrypt' && window.callTest.wrongKey
          super(worker,wrong?{...options,key:wrong}:options)
          window.callTest.transforms.push([options.op,options.kind,options.key.extractable])
        }
      }
    },unsupported)
    await page.goto(app.href)
    await page.getByLabel('Email address',{exact:true}).fill(person.email)
    await page.getByLabel('Password',{exact:true}).fill(password)
    await page.locator('button.submit-auth').click()
    await page.locator('.chat-item').filter({hasText:target.name}).click()
    return page
  }
  const [a,b,c]=await Promise.all([open(one,two),open(two,one),open(two,one,true)])
  assert.equal(await a.evaluate(()=>typeof RTCRtpScriptTransform),'function')
  const panel=(page,mode)=>page.getByRole('region',{name:'Protected '+mode+' call',exact:true})
  const button=(page,mode,name)=>panel(page,mode).getByRole('button',{name,exact:true})
  const verification=(page,mode)=>panel(page,mode).getByLabel('Call verification code')
  const rows=()=>one.client.from('st_calls').select('id,video,status,media_protection').eq('chat_id',chat)
  async function start(page,mode) {
    const option=page.getByRole('button',{name:'Start protected '+mode+' call',exact:true})
    if (!await option.isVisible()) await page.locator('summary[aria-label="Protected call options"]').click()
    await option.click()
  }
  async function ring(mode) {
    const started=a.waitForResponse(response=>response.url().endsWith('/rpc/st_v6_start_protected_call'))
    await start(a,mode)
    const response=await started
    assert.ok(response.ok())
    const id=await response.json()
    await button(b,mode,'Answer').waitFor()
    return data(await rows().eq('id',id).single())
  }
  async function code(mode) {
    await Promise.all([a,b].map(page=>verification(page,mode).waitFor()))
    const [left,right]=await Promise.all([a,b].map(page=>verification(page,mode).textContent()))
    assert.match(left,/^[0-9A-F]{4}( [0-9A-F]{4}){2}$/)
    assert.equal(left,right)
    return left
  }

  const rejected=await ring('audio')
  assert.equal(rejected.media_protection,1)
  assert.equal(data(await two.client.rpc('st_v6_call_action',{p_call:rejected.id,p_action:'accept',p_device:randomUUID()})),'unavailable')
  await button(c,'audio','Answer').click()
  await c.getByText('This browser cannot answer the protected call.',{exact:true}).waitFor()
  assert.equal(data(await rows().eq('id',rejected.id).single()).status,'ringing')
  assert.equal(await c.evaluate(()=>window.callTest.peers.length),0)
  await button(a,'audio','Cancel call').click()
  await panel(b,'audio').waitFor({state:'hidden'})
  await c.close()

  const codes=new Set()
  for (const mode of ['audio','video']) {
    const call=await ring(mode)
    assert.equal(call.media_protection,1)
    await button(b,mode,'Answer').click()
    const agreed=await code(mode)
    assert.ok(!codes.has(agreed))
    codes.add(agreed)
    const fakePublic='A'.repeat(87)
    for (const person of [one,two,outsider]) {
      const blocked=await person.client.rpc('st_v6_protected_call_key',{p_call:call.id,p_device:randomUUID(),p_key:fakePublic})
      assert.equal(blocked.error?.code,'42501')
    }
    for (const page of [a,b]) {
      assert.equal(await panel(page,mode).locator('video[aria-label="Remote participant"]').count(),0)
      assert.equal(await page.evaluate(()=>window.callTest.peers.filter(peer=>peer.signalingState!=='closed').length),0)
      await page.evaluate(()=>{window.callTest.decoded.length=0;window.callTest.transforms.length=0})
    }
    await Promise.all([a,b].map(page=>button(page,mode,'Codes match').click()))
    try {
      await Promise.all([a,b].map(page=>panel(page,mode).getByText(/Protected media connected/).waitFor({timeout:12000})))
    } catch(error) {
      for (const page of [a,b]) console.error(await page.evaluate(async()=>{
        const {peers,decoded,transforms,states,workerErrors}=window.callTest
        const peer=peers.at(-1)
        const stats=peer ? [...(await peer.getStats().catch(()=>new Map())).values()] : []
        return {decoded,transforms,states,workerErrors,candidates:stats.filter(item=>item.type==='candidate-pair').map(item=>item.state),
          media:stats.filter(item=>item.type==='inbound-rtp'||item.type==='outbound-rtp')
            .map(item=>({type:item.type,kind:item.kind,received:item.bytesReceived,sent:item.bytesSent}))}
      }))
      throw error
    }
    for (const page of [a,b]) {
      const kinds=mode==='video'?['audio','video']:['audio']
      await page.waitForFunction(async kinds=>{
        const peer=window.callTest.peers.findLast(item=>item.connectionState==='connected')
        if (!peer) return false
        const reports=[...(await peer.getStats()).values()]
        return kinds.every(kind=>reports.some(stat=>stat.type==='inbound-rtp' && stat.kind===kind &&
          (kind==='audio'?stat.totalSamplesReceived>0 && stat.totalAudioEnergy>0:stat.framesDecoded>0)))
      },kinds)
      const trace=await page.evaluate(()=>({decoded:window.callTest.decoded,transforms:window.callTest.transforms}))
      assert.deepEqual(trace.decoded.sort(),kinds)
      assert.deepEqual(trace.transforms.map(([op,kind,extractable])=>[op,kind,extractable]),
        kinds.flatMap(kind=>[['encrypt',kind,false],['decrypt',kind,false]]))
      assert.equal(await panel(page,mode).getByRole('button',{name:'Share screen'}).count(),0)
    }
    await button(a,mode,'Hang up').click()
    await panel(b,mode).waitFor({state:'hidden'})
    console.log('Protected '+mode+' passed with native encrypted and authenticated media in both browsers.')
  }

  await b.evaluate(async()=>{window.callTest.wrongKey=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['decrypt'])})
  await ring('audio')
  await button(b,'audio','Answer').click()
  await code('audio')
  await Promise.all([a,b].map(page=>button(page,'audio','Codes match').click()))
  await b.getByText('Protected media could not be authenticated.',{exact:true}).waitFor({timeout:25000})
  await panel(b,'audio').waitFor({state:'hidden'})
  assert.equal(await b.locator('video[aria-label="Remote participant"]').count(),0)
  console.log('Unsupported browser, legacy acceptance, wrong endpoints and invalid media authentication failed closed.')
} finally {
  await browser?.close()
  await Promise.allSettled(accounts.map(person=>admin.auth.admin.deleteUser(person.id)))
}
