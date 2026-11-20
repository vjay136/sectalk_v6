// Verify protected SFU media with real local LiveKit and three native Edge sessions using synthetic tracks.
import assert from 'node:assert/strict'
import {randomUUID} from 'node:crypto'
import {createClient} from '@supabase/supabase-js'
import {RoomServiceClient,TokenVerifier,TrackSource} from 'livekit-server-sdk'

const app=new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase=new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.href,'http://127.0.0.1:3502/')
assert.equal(supabase.hostname,'127.0.0.1')
const {SECTALK_STORAGE_TEST_PUBLIC_KEY:key,SECTALK_STORAGE_TEST_SERVICE_KEY:serviceKey}=process.env
assert.ok(key && serviceKey)
const auth={persistSession:false,autoRefreshToken:false}
const admin=createClient(supabase.href,serviceKey,{auth})
const provider=new RoomServiceClient('http://127.0.0.1:7880','devkey','secret')
const verifier=new TokenVerifier('devkey','secret')
const password=randomUUID()+'!1Q'
const people=[]
let browser

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

async function account(name) {
  const handle=name.toLowerCase().slice(0,14)+'_'+randomUUID().slice(0,8)
  const email=handle+'@example.org'
  const {user}=data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  const client=createClient(supabase.href,key,{auth})
  const person={client,id:user.id,handle,email,name}
  people.push(person)
  person.token=data(await client.auth.signInWithPassword({email,password})).session.access_token
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:name}))
  return person
}

async function api(path,person,values) {
  return fetch(new URL('/api/meetings/'+path,app),{method:'POST',
    headers:{'Content-Type':'application/json',Authorization:'Bearer '+person.token},body:JSON.stringify(values)})
}

try {
  const [host,second,third,outsider]=await Promise.all([
    account('ProtectedHost'),account('ProtectedSecond'),account('ProtectedThird'),account('ProtectedOutside'),
  ])
  const workspace=data(await host.client.rpc('st_v2_create_workspace',{p_name:'Protected meeting fixture'}))
  for (const person of [second,third,outsider]) {
    data(await host.client.rpc('st_v2_invite',{p_workspace:workspace,p_handle:person.handle}))
    const invite=data(await person.client.from('st_v2_invites').select('id').eq('workspace_id',workspace).single())
    data(await person.client.rpc('st_v2_reply_invite',{p_invite:invite.id,p_accept:true}))
  }
  const title='Protected meeting '+randomUUID().slice(0,8)
  const meeting=data(await host.client.rpc('st_v6_start_instant_meeting',{
    p_id:randomUUID(),p_workspace:workspace,p_title:title,p_minutes:15,
  }))
  for (const person of [second,third]) {
    data(await person.client.rpc('st_v3_request_admission',{p_meeting:meeting}))
    data(await host.client.rpc('st_v3_admit',{p_meeting:meeting,p_user:person.id,p_allow:true}))
  }
  assert.equal((await api('protected',second,{action:'start',meeting})).status,403)
  assert.equal((await api('guests',host,{action:'policy',enabled:true,meeting})).status,200)
  assert.equal((await api('guests',host,{action:'create',meeting})).status,200)
  const managed=await api('token',host,{meetingId:meeting})
  assert.equal(managed.status,200)
  assert.equal((await verifier.verify((await managed.json()).token)).video.room,'sectalk-v3-'+meeting)

  const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER,
    args:['--use-fake-device-for-media-stream','--use-fake-ui-for-media-stream']})
  async function open(person) {
    const page=await browser.newPage({locale:'en-US',permissions:['microphone','camera']})
    await page.addInitScript(()=>{
      const Peer=window.RTCPeerConnection
      window.protectedTestPeers=[]
      window.protectedTestTransforms={script:0,streams:0}
      window.RTCPeerConnection=class extends Peer {
        constructor(config) { super(config);window.protectedTestPeers.push(this) }
      }
      const Native=window.RTCRtpScriptTransform
      if (Native) window.RTCRtpScriptTransform=class extends Native {
        constructor(...args) { super(...args);window.protectedTestTransforms.script++ }
      }
      for (const target of [RTCRtpSender.prototype,RTCRtpReceiver.prototype]) {
        const streams=target.createEncodedStreams
        if (typeof streams==='function') target.createEncodedStreams=function() {
          window.protectedTestTransforms.streams++
          return streams.call(this)
        }
      }
    })
    const url=new URL(app)
    url.searchParams.set('meeting',meeting)
    await page.goto(url.href)
    await page.getByLabel('Email address',{exact:true}).fill(person.email)
    await page.getByLabel('Password',{exact:true}).fill(password)
    await page.locator('button.submit-auth').click()
    await page.getByRole('heading',{name:title,exact:true}).waitFor()
    return page
  }

  const pages=await Promise.all([host,second,third].map(open))
  const [owner]=pages
  assert.equal(await owner.evaluate(()=>typeof RTCRtpScriptTransform),'function')
  await owner.getByRole('button',{name:'Protect meeting media',exact:true}).click()
  const panel=page=>page.getByRole('region',{name:'Protected meeting',exact:true})
  const buttons=(page,name)=>panel(page).getByRole('button',{name,exact:true})
  for (const page of pages) await panel(page).waitFor()
  assert.equal((await api('token',host,{meetingId:meeting})).status,403)
  assert.equal((await api('guests',host,{action:'create',meeting})).status,403)
  assert.notEqual((await api('guests',host,{action:'policy',enabled:true,meeting})).status,200)
  assert.equal((await api('protected',outsider,{action:'token',device:randomUUID(),meeting})).status,403)
  assert.equal(await owner.getByRole('region',{name:'Meeting recording',exact:true}).count(),0)
  assert.equal(await owner.getByRole('region',{name:'Guest access',exact:true}).count(),0)
  assert.equal(await owner.getByRole('button',{name:'Join audio and video',exact:true}).count(),0)

  const hostPayloads=[]
  owner.on('request',request=>{
    if (request.url().endsWith('/rpc/st_v6_protected_meeting_exchange')) {
      const body=request.postDataJSON()
      if (body?.p_action==='wrap') hostPayloads.push(body.p_envelopes)
    }
  })
  const enrollments=pages.map(page=>page.waitForResponse(response=>response.url().endsWith('/rpc/st_v6_protected_meeting_exchange') &&
    response.request().postDataJSON()?.p_action==='key'))
  await Promise.all(pages.map(page=>buttons(page,'Prepare encrypted media').click()))
  for (const response of await Promise.all(enrollments)) {
    const result=await response.json()
    assert.ok(response.ok() && result?.roster?.length===3,result?.message || 'Protected endpoint enrollment failed')
  }
  const code=page=>panel(page).getByLabel('Group verification code')
  await Promise.all(pages.map(page=>code(page).waitFor()))
  const codes=await Promise.all(pages.map(page=>code(page).textContent()))
  assert.match(codes[0],/^[A-F0-9]{4}( [A-F0-9]{4}){2}$/)
  assert.equal(new Set(codes).size,1)
  assert.equal(hostPayloads.length,1)
  assert.deepEqual(Object.keys(hostPayloads[0]).sort(),[second.id,third.id].sort())
  for (const envelope of Object.values(hostPayloads[0])) assert.match(envelope,/^[\w-]{80}$/)
  assert.equal(data(await second.client.rpc('st_v6_protected_meeting_exchange',{
    p_meeting:meeting,p_device:randomUUID(),p_action:'view',
  })),null)
  await Promise.all(pages.slice(0,2).map(page=>buttons(page,'Group codes match').click()))
  await panel(owner).getByText('Waiting for everyone to confirm the group code.',{exact:true}).waitFor()
  assert.equal(await buttons(owner,'Join protected meeting media').count(),0)
  await buttons(pages[2],'Group codes match').click()
  const credentials=pages.map(page=>page.waitForResponse(response=>response.url().endsWith('/api/meetings/protected')&&
    response.request().method()==='POST'&&response.request().postDataJSON()?.action==='token'))
  await Promise.all(pages.map(page=>buttons(page,'Join protected meeting media').click()))
  const room='sectalk-protected-'+meeting
  for (const response of await Promise.all(credentials)) {
    assert.equal(response.status(),200)
    const claim=await verifier.verify((await response.json()).token)
    assert.equal(claim.video.room,room)
    assert.equal(claim.video.canPublishData,false)
  }
  await Promise.all(pages.map(page=>panel(page).getByText('Protected meeting media connected',{exact:true}).waitFor()))
  for (const page of pages) {
    for (const source of ['microphone','camera']) {
      await page.locator('.meeting-media button[data-lk-source="'+source+'"]').click()
      await page.waitForSelector('.meeting-media button[data-lk-source="'+source+'"][aria-pressed="true"]')
    }
  }
  for (const page of pages) {
    await page.waitForFunction(async()=>{
      for (const peer of window.protectedTestPeers) {
        if (peer.connectionState!=='connected') continue
        const stats=[...(await peer.getStats()).values()]
        if (stats.filter(item=>item.type==='inbound-rtp' && item.kind==='audio' && item.totalAudioEnergy>0).length>=2 &&
            stats.filter(item=>item.type==='inbound-rtp' && item.kind==='video' && item.framesDecoded>0).length>=2) return true
      }
      return false
    },undefined,{timeout:30000})
    const native=await page.evaluate(()=>window.protectedTestTransforms)
    assert.ok(native.script + native.streams >= 4)
    console.log('Native LiveKit encoded transforms',native)
  }
  const participants=await provider.listParticipants(room)
  assert.deepEqual(participants.map(person=>person.identity).sort(),[host.id,second.id,third.id].sort())
  for (const person of participants) {
    assert.deepEqual(person.tracks.map(track=>track.source).sort(),[TrackSource.CAMERA,TrackSource.MICROPHONE].sort())
    assert.ok(person.tracks.every(track=>track.encryption===1))
  }
  data(await third.client.rpc('st_v3_leave',{p_meeting:meeting}))
  await Promise.all(pages.slice(0,2).map(page=>panel(page).getByText(/The protected roster is closed/).waitFor()))
  assert.equal(await owner.locator('.meeting-media').count(),0)
  assert.equal((await api('token',host,{meetingId:meeting})).status,403)
  console.log('Three native clients decoded encrypted LiveKit audio and video, rejected early/unowned access, and disconnected after roster departure.')
} finally {
  await browser?.close()
  await Promise.allSettled(people.map(person=>admin.auth.admin.deleteUser(person.id)))
}
