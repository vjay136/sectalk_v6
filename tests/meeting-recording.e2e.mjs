// Use disposable loopback Supabase/LiveKit and private Storage.
// Set SECTALK_RECORDING_REAL=1 for actual Egress and SECTALK_RECORDING_VIDEO=1 for MP4.
import assert from 'node:assert/strict'
import { createHash, randomUUID } from 'node:crypto'
import { createServer } from 'node:http'
import { createClient } from '@supabase/supabase-js'
import { AccessToken, EgressClient, EgressStatus, RoomServiceClient, TokenVerifier, TrackSource } from 'livekit-server-sdk'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname,'127.0.0.1')
assert.equal(supabase.hostname,'127.0.0.1')
const { SECTALK_STORAGE_TEST_PUBLIC_KEY: publicKey, SECTALK_STORAGE_TEST_SERVICE_KEY: serviceKey } = process.env
assert.ok(publicKey && serviceKey)
const opts = { auth:{ persistSession:false, autoRefreshToken:false } }
const real = process.env.SECTALK_RECORDING_REAL === '1'
const video = process.env.SECTALK_RECORDING_VIDEO === '1'
assert.ok(!video || real,'Video verification requires the actual Egress worker')
const recordingLabel = video ? 'single-camera recording' : 'audio recording'
const recordingTitle = video ? 'Single-camera recording' : 'Audio recording'
const requestLabel = video ? 'Request recording with my camera' : 'Request audio recording'
const filename = video ? 'meeting.mp4' : 'meeting.ogg'
const admin = createClient(supabase.href,serviceKey,opts)
const password = randomUUID()+'!1Q'

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

async function account(name) {
  const handle = name.toLowerCase()+'_'+randomUUID().slice(0,8)
  const email = handle+'@example.org'
  const { user } = data(await admin.auth.admin.createUser({ email,password,email_confirm:true }))
  const client = createClient(supabase.href,publicKey,opts)
  const { session } = data(await client.auth.signInWithPassword({ email,password }))
  data(await client.rpc('st_save_profile',{ p_handle:handle,p_name:name }))
  return { id:user.id, client, email, handle, token:session.access_token }
}

const [host,guest,other] = await Promise.all([account('RecorderHost'),account('RecorderGuest'),account('RecorderOther')])
const workspace = data(await host.client.rpc('st_v2_create_workspace',{ p_name:'Recording checks' }))
for (const user of [guest,other]) {
  data(await host.client.rpc('st_v2_invite',{ p_workspace:workspace,p_handle:user.handle }))
  const invite = data(await user.client.from('st_v2_invites').select('id').eq('workspace_id',workspace).single())
  data(await user.client.rpc('st_v2_reply_invite',{ p_invite:invite.id,p_accept:true }))
}
const title = 'Recording fixture '+randomUUID().slice(0,8)
const meeting = data(await host.client.rpc('st_v6_start_instant_meeting',{
  p_id:randomUUID(),p_workspace:workspace,p_title:title,p_minutes:15,
}))
data(await guest.client.rpc('st_v3_request_admission',{ p_meeting:meeting }))
data(await host.client.rpc('st_v3_admit',{ p_meeting:meeting,p_user:guest.id,p_allow:true }))

const audioBytes = Buffer.from('OggS disposable byte authorization fixture')
const jobs = new Map()
const fixtureErrors = []
const verifier = new TokenVerifier('devkey','secret')
const provider = real ? 'http://127.0.0.1:7890' : 'http://127.0.0.1:7880'
const meetings = new RoomServiceClient(provider,'devkey','secret')
const liveEgress = new EgressClient(provider,'devkey','secret')
const recordingPaths = new Set()
let starts = 0
const fixture = createServer(async (request,response) => {
  try {
    const parts = []
    for await (const chunk of request) parts.push(chunk)
    const body = JSON.parse(Buffer.concat(parts).toString('utf8'))
    const headers = String(request.headers.authorization)
    const grant = await verifier.verify(headers.replace(/^Bearer\s+/i,''))
    assert.ok(grant.video?.roomRecord)
    let result
    if (request.url.endsWith('/StartEgress')) {
      starts++
      assert.equal(body.roomName,'sectalk-v3-'+meeting)
      assert.equal(body.outputs.length,1)
      const key = body.outputs[0].file.filepath
      assert.match(key,new RegExp('^'+meeting+'/[a-f0-9-]+/meeting\\.ogg$'))
      assert.equal(body.storage.s3.bucket,'recordings')
      const audio = body.media.audio
      assert.equal(Boolean(audio.captureAll),false)
      assert.ok(audio.routes.length > 0)
      assert.ok(audio.routes.every(route=>route.trackId.startsWith('TR_') && Object.hasOwn(route,'trackId')))
      assert.equal(new Set(audio.routes.map(route=>route.trackId)).size,audio.routes.length)
      const active = await meetings.listParticipants(body.roomName)
      assert.deepEqual(active.map(person=>person.identity).sort(),[host.id,guest.id].sort())
      assert.deepEqual(audio.routes.map(route=>route.trackId).sort(),active.flatMap(person=>person.tracks
        .filter(track=>track.source===TrackSource.MICROPHONE).map(track=>track.sid)).sort())
      data(await admin.storage.from('recordings').upload(key,audioBytes,{ contentType:'audio/ogg' }))
      const id = 'EG_local_fixture_'+starts
      result = { egressId:id,roomName:body.roomName,status:starts===1?'EGRESS_FAILED':'EGRESS_ACTIVE',egress:body,
        fileResults:[{ filename:key,size:String(audioBytes.length),duration:"6500000000" }] }
      jobs.set(id,result)
    } else if (request.url.endsWith('/ListEgress')) {
      result = { items:[...jobs.values()].filter(job=>(!body.egressId || job.egressId===body.egressId)
        && (!body.roomName || job.roomName===body.roomName)) }
    } else if (request.url.endsWith('/StopEgress')) {
      result = jobs.get(body.egressId)
      assert.ok(result)
      result.status = 'EGRESS_COMPLETE'
    } else throw new Error('Unexpected mock provider route')
    response.writeHead(200,{ 'Content-Type':'application/json' }).end(JSON.stringify(result))
  } catch (error) {
    fixtureErrors.push(error)
    response.writeHead(500,{ 'Content-Type':'application/json' }).end(JSON.stringify({ code:'internal',msg:'fixture failed' }))
  }
})
if (!real) await new Promise((resolve,reject)=>fixture.listen(3490,'127.0.0.1',resolve).once('error',reject))

const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
let browser
let pauseRecordingViews = false
const diagnostics = []
const endpoint = new URL('/api/meetings/recordings',app)
function call(user,action,id) {
  return fetch(endpoint,{ method:'POST',headers:{ Authorization:'Bearer '+user.token,'Content-Type':'application/json' },
    body:JSON.stringify({ meeting, action, id }) })
}
function bytes(user,id) {
  const url = new URL(endpoint)
  url.searchParams.set('meeting',meeting)
  url.searchParams.set('recording',id)
  return fetch(url,{ headers:user?{ Authorization:'Bearer '+user.token }:{} })
}
const region = page => page.getByRole('region',{ name:'Meeting recording' })
const button = (page,name) => region(page).getByRole('button',{ name,exact:true })

try {
  browser = await chromium.launch({ executablePath:process.env.SECTALK_TEST_BROWSER,
    args:['--use-fake-device-for-media-stream','--use-fake-ui-for-media-stream'] })
  async function open(user) {
    const page = await browser.newPage({ locale:'en-US',permissions:['microphone','camera'] })
    if (real) await page.route(endpoint.href,route => {
      const request=route.request()
      if (pauseRecordingViews && request.method()==='POST' && request.postDataJSON()?.action==='view') {
        return route.fulfill({ status:503, json:{ error:'Polling temporarily disabled by the fixture.' } })
      }
      return route.continue()
    })
    page.on('console',event=>{ if (event.type()==='error') diagnostics.push(event.text()) })
    const url = new URL(app)
    url.searchParams.set('meeting',meeting)
    await page.goto(url.href)
    await page.getByLabel('Email address',{ exact:true }).fill(user.email)
    await page.getByLabel('Password',{ exact:true }).fill(password)
    await page.locator('button.submit-auth').click()
    await page.getByRole('heading',{ name:title,exact:true }).waitFor()
    await page.getByRole('button',{ name:'Join audio and video',exact:true }).click()
    const mic = page.locator('.meeting-media button[data-lk-source="microphone"]')
    await mic.click()
    await page.waitForSelector('.meeting-media button[data-lk-source="microphone"][aria-pressed="true"]')
    if (video) {
      await page.locator('.meeting-media button[data-lk-source="camera"]').click()
      await page.waitForSelector('.meeting-media button[data-lk-source="camera"][aria-pressed="true"]')
    }
    return page
  }

  assert.equal((await fetch(endpoint)).status,200)
  assert.equal((await fetch(new URL('/api/meetings/recordings/webhook',app),{ method:'POST',body:'{}' })).status,401)
  assert.equal((await call(host,'request')).status,403)
  assert.ok((await other.client.rpc('st_v6_recording_command',{p_meeting:meeting,p_actor:other.id,p_action:'internal'})).error)
  const [hostPage,guestPage] = await Promise.all([open(host),open(guest)])
  await button(hostPage,'Allow workspace recording').click()
  await button(hostPage,requestLabel).waitFor()
  assert.equal((await call(guest,'request')).status,403)

  async function consent() {
    await button(hostPage,requestLabel).click()
    if (video) await region(guestPage).getByText(/Other cameras and shared screens are excluded/).waitFor()
    await button(hostPage,'Agree to '+recordingLabel).click()
    await region(hostPage).getByText(/1 of 2 have agreed/).waitFor()
    const state = await (await call(host,'view')).json()
    await region(guestPage).getByText(/All connected participants must agree/).waitFor()
    assert.equal(state.recording.count,2)
    assert.equal(state.recording.approved,1)
    assert.equal(state.recording.mode,video?'single-camera':'audio')
    assert.equal(await button(hostPage,'Start '+recordingLabel).isEnabled(),false)
    assert.equal((await call(host,'start',state.recording.id)).status,409)
    if (real) {
      const submitted = await liveEgress.listEgress({ roomName:'sectalk-v3-'+meeting })
      assert.ok(!submitted.some(job=>job.request.case==='egress' && job.request.value.outputs.some(output=>
        output.config.case==='file' && output.config.value.filepath.includes('/'+state.recording.id+'/'))))
    }
    assert.equal((await call(other,'accept',state.recording.id)).status,403)
    await button(guestPage,'Agree to '+recordingLabel).click()
    await button(hostPage,'Start '+recordingLabel).click()
    recordingPaths.add(meeting+'/'+state.recording.id+'/'+filename)
    return state.recording.id
  }

  async function waitForRealWorker(id) {
    if (!real) return
    const deadline=Date.now()+35_000
    const filepath=meeting+'/'+id+'/'+filename
    let found
    while (Date.now()<deadline) {
      const jobs=await liveEgress.listEgress({ roomName:'sectalk-v3-'+meeting })
      found=jobs.find(job=>job.request.case==='egress' && job.request.value.outputs.some(output=>
        output.config.case==='file' && output.config.value.filepath===filepath))
      if (found?.status===EgressStatus.EGRESS_ACTIVE) break
      if (found && found.status>=EgressStatus.EGRESS_COMPLETE) break
      await new Promise(resolve=>setTimeout(resolve,300))
    }
    assert.equal(found?.status,EgressStatus.EGRESS_ACTIVE,found?.error || 'The real worker did not become active')
    const input=found.request.value.source
    assert.equal(input.case,'media')
    assert.equal(input.value.audio.captureAll,false)
    const roster=(await meetings.listParticipants('sectalk-v3-'+meeting)).filter(person=>person.kind!==2)
    assert.deepEqual(roster.map(person=>person.identity).sort(),[host.id,guest.id].sort())
    assert.deepEqual(input.value.audio.routes.map(route=>route.match.value).sort(),roster.flatMap(person=>person.tracks
      .filter(track=>track.source===TrackSource.MICROPHONE).map(track=>track.sid)).sort())
    if (video) {
      const cameras=roster.flatMap(person=>person.tracks.filter(track=>track.source===TrackSource.CAMERA))
      assert.equal(cameras.length,2)
      const hostCamera=roster.find(person=>person.identity===host.id).tracks.find(track=>track.source===TrackSource.CAMERA)
      assert.deepEqual(input.value.video,{ case:'videoTrackId', value:hostCamera.sid })
    } else assert.equal(input.value.video.case,undefined)
    await new Promise(resolve=>setTimeout(resolve,2200))
  }

  if (!real) {
    const failed = await consent()
    await region(hostPage).getByText('The recording was discarded.',{ exact:true }).waitFor()
    assert.equal(starts,1)
    assert.equal((await bytes(host,failed)).status,404)
    assert.ok((await admin.storage.from('recordings').download(meeting+'/'+failed+'/meeting.ogg')).error)
  }

  const revoked = await consent()
  await waitForRealWorker(revoked)
  await region(guestPage).getByText(recordingTitle+' is in progress.',{ exact:true }).waitFor()
  assert.equal((await bytes(guest,revoked)).status,404)
  await button(guestPage,'Withdraw recording consent').click()
  await region(hostPage).getByText('The recording was discarded.',{ exact:true }).waitFor()
  assert.equal((await bytes(host,revoked)).status,404)
  assert.ok((await admin.storage.from('recordings').download(meeting+'/'+revoked+'/'+filename)).error)

  if (video) {
    const cameraLost = await consent()
    await waitForRealWorker(cameraLost)
    const camera = hostPage.locator('.meeting-media button[data-lk-source="camera"]')
    await camera.click()
    await hostPage.waitForSelector('.meeting-media button[data-lk-source="camera"][aria-pressed="false"]')
    await region(hostPage).getByText('The recording was discarded.',{ exact:true }).waitFor()
    assert.equal((await bytes(host,cameraLost)).status,404)
    assert.ok((await admin.storage.from('recordings').download(meeting+'/'+cameraLost+'/'+filename)).error)
    await camera.click()
    await hostPage.waitForSelector('.meeting-media button[data-lk-source="camera"][aria-pressed="true"]')
  }

  const changed = await consent()
  await waitForRealWorker(changed)
  await region(hostPage).getByText(recordingTitle+' is in progress.',{ exact:true }).waitFor()
  data(await other.client.rpc('st_v3_request_admission',{ p_meeting:meeting }))
  data(await host.client.rpc('st_v3_admit',{ p_meeting:meeting,p_user:other.id,p_allow:true }))
  pauseRecordingViews = real
  const latePage = await open(other)
  if (real) {
    const deadline=Date.now()+15_000
    let status
    do {
      const state=data(await admin.rpc('st_v6_recording_command',{ p_meeting:meeting,p_actor:null,p_action:'internal' }))
      status=state?.recording?.status
      if (status==='failed') break
      await new Promise(resolve=>setTimeout(resolve,200))
    } while (Date.now()<deadline)
    assert.equal(status,'failed','The actual LiveKit webhook must discard the late-join recording without browser polling')
    pauseRecordingViews = false
  } else {
    const webhook = JSON.stringify({ event:'participant_joined',room:{name:'sectalk-v3-'+meeting},participant:{identity:other.id} })
    const proof = new AccessToken('devkey','secret',{ ttl:30 })
    proof.sha256 = createHash('sha256').update(webhook).digest('base64')
    const event = await fetch(new URL('/api/meetings/recordings/webhook',app),{ method:'POST',body:webhook,
      headers:{ Authorization:await proof.toJwt(),'Content-Type':'application/webhook+json' } })
    assert.equal(event.status,204)
  }
  await region(hostPage).getByText('The recording was discarded.',{ exact:true }).waitFor()
  assert.equal((await bytes(host,changed)).status,404)
  assert.ok((await admin.storage.from('recordings').download(meeting+'/'+changed+'/'+filename)).error)
  data(await other.client.rpc('st_v3_leave',{ p_meeting:meeting }))
  await latePage.locator('.meeting-media').waitFor({ state:'detached' })
  const leaveDeadline = Date.now()+5000
  while ((await meetings.listParticipants('sectalk-v3-'+meeting)).some(person=>person.identity===other.id) && Date.now()<leaveDeadline) {
    await new Promise(resolve=>setTimeout(resolve,100))
  }

  const done = await consent()
  await waitForRealWorker(done)
  await button(hostPage,'Stop '+recordingLabel).click()
  await button(hostPage,'Download '+recordingLabel).waitFor()
  const recorded = data(await host.client.rpc('st_v7_workspace_usage', {p_workspace:workspace}))
  assert.ok(recorded.recording_ms > 0)
  if (!real) assert.equal(recorded.recording_ms, 6500)
  assert.equal((await guest.client.rpc('st_v7_workspace_usage', {p_workspace:workspace})).error?.code, '42501')
  if (!real) assert.equal(starts,4)
  assert.equal((await bytes(null,done)).status,401)
  assert.equal((await bytes(other,done)).status,404)
  assert.ok((await guest.client.storage.from('recordings').download(meeting+'/'+done+'/'+filename)).error)
  let hostAudio
  for (const user of [host,guest]) {
    const response = await bytes(user,done)
    if (real && response.status !== 200) {
      const path=meeting+'/'+done+'/'+filename
      const listed=await admin.storage.from('recordings').list(meeting+'/'+done)
      const stored=await admin.storage.from('recordings').download(path)
      assert.equal(response.status,200,JSON.stringify({ role:user===host?'host':'guest',
        folderHasRecording:listed.data?.some(object=>object.name===filename), storageStatus:stored.error?.status ?? null }))
    }
    assert.equal(response.status,200)
    assert.match(response.headers.get('Cache-Control'),/private, no-store/)
    assert.equal(response.headers.get('Content-Type'),video?'video/mp4':'audio/ogg')
    const received=Buffer.from(await response.arrayBuffer())
    if (real) {
      if (hostAudio) assert.deepEqual(received,hostAudio)
      else hostAudio=received
    } else assert.deepEqual(received,audioBytes)
  }
  if (video) {
    assert.equal(hostAudio.subarray(4,8).toString(),'ftyp')
    const playback=await browser.newPage()
    const decoded=await playback.evaluate(async bytes => {
      const url=URL.createObjectURL(new Blob([Uint8Array.from(bytes)],{type:'video/mp4'}))
      const video=document.createElement('video')
      video.muted=true
      video.src=url
      try {
        await new Promise((resolve,reject) => {
          video.onloadeddata=resolve
          video.onerror=()=>reject(new Error(video.error?.message))
        })
        await video.play()
        const frame=await new Promise(resolve=>video.requestVideoFrameCallback((_,metadata)=>resolve(metadata)))
        const audioContext=new AudioContext()
        try {
          const audio=await audioContext.decodeAudioData(Uint8Array.from(bytes).buffer)
          const samples=audio.getChannelData(0)
          return { width:video.videoWidth,height:video.videoHeight,duration:video.duration,
            frames:frame.presentedFrames,audioChannels:audio.numberOfChannels,
            audible:samples.some(value=>Math.abs(value)>0.001) }
        } finally { await audioContext.close() }
      } finally {
        video.pause()
        URL.revokeObjectURL(url)
      }
    },[...hostAudio])
    assert.ok(decoded.width>0 && decoded.height>0 && decoded.duration>1 && decoded.frames>0 && decoded.audible)
    console.log('Decoded actual single-camera Egress output',decoded)
  } else if (real) {
    assert.equal(hostAudio.subarray(0,4).toString(),'OggS')
    const decoded=await hostPage.evaluate(async bytes => {
      const context=new AudioContext()
      try {
        const audio=await context.decodeAudioData(Uint8Array.from(bytes).buffer)
        let peak=0
        for (const value of audio.getChannelData(0)) peak=Math.max(peak,Math.abs(value))
        return { duration:audio.duration,peak,channels:audio.numberOfChannels }
      } finally { await context.close() }
    },[...hostAudio])
    assert.ok(decoded.duration>1 && decoded.channels>=1 && decoded.peak>0.001)
    console.log('Decoded actual Egress output', { duration:Math.round(decoded.duration*100)/100,channels:decoded.channels })
  }
  assert.deepEqual(fixtureErrors,[])
} catch (error) {
  if (fixtureErrors.length) console.error(fixtureErrors.map(error=>error.message))
  if (diagnostics.length) console.error(diagnostics.slice(-8))
  throw error
} finally {
  await browser?.close()
  if (!real) {
    fixture.closeAllConnections()
    await new Promise(resolve=>fixture.close(resolve))
  }
  const fixtureObjects = [...recordingPaths]
  if (fixtureObjects.length) await admin.storage.from('recordings').remove(fixtureObjects)
}
console.log('Passed LiveKit room consent, scoped '+(real?'real':'mock')+' egress, safe discard, withdrawal, late-join invalidation, and private recording byte access.')
