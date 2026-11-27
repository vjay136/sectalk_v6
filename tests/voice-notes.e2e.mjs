// Isolated Edge microphone/playback test. Use the existing synthetic English WAV, not a real microphone.
import assert from 'node:assert/strict'
import {execFileSync} from 'node:child_process'
import {randomUUID} from 'node:crypto'
import {createClient} from '@supabase/supabase-js'

const app=new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase=new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.href,'http://127.0.0.1:3504/')
assert.equal(supabase.hostname,'127.0.0.1')
const {SECTALK_STORAGE_TEST_PUBLIC_KEY:key,SECTALK_STORAGE_TEST_SERVICE_KEY:serviceKey,SECTALK_VOICE_WAV:wav}=process.env
assert.ok(key && serviceKey && wav)
const speechEnabled=process.env.SECTALK_VOICE_EXPECT_SPEECH!=='0'
const database=process.env.SECTALK_VOICE_TEST_DB || 'supabase_db_v4-auth-qa'
assert.match(database,/^supabase_db_(?:v4-auth-qa|(?:sectalk-)?v6-[a-z0-9-]+-qa)$/)
const auth={persistSession:false,autoRefreshToken:false}
const admin=createClient(supabase.href,serviceKey,{auth})
const endpoint=new URL('/api/voice-notes',app)
const password=randomUUID()+'!1Q'
const users=[]
let browser
let android

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
  users.push(person)
  person.token=data(await client.auth.signInWithPassword({email,password})).session.access_token
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:name}))
  return person
}

try {
  assert.deepEqual(await (await fetch(endpoint)).json(),{configured:true,speech:speechEnabled})
  const [sender,peer,outsider]=await Promise.all([account('VoiceSender'),account('VoicePeer'),account('VoiceOutside')])
  const chat=data(await sender.client.rpc('st_request',{p_handle:peer.handle}))
  data(await peer.client.rpc('st_respond',{p_chat:chat,p_accept:true}))
  const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER,args:[
    '--use-fake-device-for-media-stream','--use-fake-ui-for-media-stream','--use-file-for-fake-audio-capture='+wav,
  ]})
  const androidEndpoint=process.env.SECTALK_ANDROID_CDP
  if (androidEndpoint) {
    assert.equal(new URL(androidEndpoint).origin,'http://127.0.0.1:9248')
    android=await chromium.connectOverCDP(androidEndpoint)
  }
  async function open(person,target,receiveOnAndroid=false) {
    const androidContext=receiveOnAndroid ? android.contexts()[0] : null
    const activeTab=androidContext?.pages().find(candidate=>candidate.url()===app.href)
    const page=androidContext ? activeTab ?? await androidContext.newPage() :
      await browser.newPage({locale:'en-US',permissions:['microphone']})
    const network=new Map()
    if (receiveOnAndroid) {
      page.on('response',response=>{
        const url=new URL(response.url())
        if (url.origin===supabase.origin) network.set(url.pathname,String(response.status()))
      })
      page.on('requestfailed',request=>{
        const url=new URL(request.url())
        if (url.origin===supabase.origin) network.set(url.pathname,request.failure()?.errorText)
      })
    }
    await page.addInitScript(()=>{
      window.voicePlayback=[]
      window.voiceCaptures=[]
      const decode=AudioContext.prototype.decodeAudioData
      const start=AudioBufferSourceNode.prototype.start
      if (navigator.mediaDevices) {
        const microphone=navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices)
        navigator.mediaDevices.getUserMedia=async constraints=>{
          const stream=await microphone(constraints)
          window.voiceCaptures.push(...stream.getAudioTracks())
          return stream
        }
      }
      AudioContext.prototype.decodeAudioData=async function(...args) {
        const result=await decode.apply(this,args)
        const samples=result.getChannelData(0)
        window.voicePlayback.push({duration:result.duration,audible:samples.some(value=>Math.abs(value)>0.005),started:false})
        return result
      }
      AudioBufferSourceNode.prototype.start=function(...args) {
        if (window.voicePlayback.length) window.voicePlayback.at(-1).started=true
        return start.apply(this,args)
      }
    })
    await page.goto(app.href,{waitUntil:'domcontentloaded',timeout:60000})
    if (receiveOnAndroid) {
      await page.bringToFront()
      await page.evaluate(()=>localStorage.clear())
      await page.reload()
    }
    await page.getByLabel('Email address',{exact:true}).fill(person.email)
    await page.getByLabel('Password',{exact:true}).fill(password)
    await page.locator('button.submit-auth').click()
    const navigation=page.getByRole('navigation',{name:'SecTalk features'})
    const accept=page.getByRole('button',{name:'Accept and continue',exact:true})
    try {
      await navigation.or(accept).first().waitFor({timeout:60000})
    } catch (error) {
      if (receiveOnAndroid) {
        const state=await page.evaluate(()=>({visibility:document.visibilityState,focused:document.hasFocus()}))
        console.error('Android workspace bootstrap',state,Object.fromEntries(network))
      }
      throw error
    }
    if (await accept.isVisible()) {
      await page.getByRole('checkbox',{name:'I accept the SecTalk Community Rules.'}).check()
      await accept.click()
    }
    await navigation.waitFor()
    await page.locator('.chat-item').filter({hasText:target.name}).click()
    return page
  }
  const a=await open(sender,peer)
  const b=await open(peer,sender,Boolean(android))
  function request(person,message,mode,method='GET',scope=chat) {
    const url=new URL(endpoint)
    url.search=new URLSearchParams({chat:scope,message,...(mode?{mode}:{})})
    return fetch(url,{method,headers:person?{Authorization:'Bearer '+person.token}:{}})
  }
  async function record(consent) {
    await a.getByRole('button',{name:'Record voice note',exact:true}).click()
    await a.getByRole('button',{name:'Stop recording',exact:true}).waitFor()
    await new Promise(resolve=>setTimeout(resolve,5300))
    await a.getByRole('button',{name:'Stop recording',exact:true}).click()
    await a.getByRole('button',{name:'Play recording preview',exact:true}).waitFor()
    assert.ok(await a.evaluate(()=>window.voiceCaptures.every(track=>track.readyState==='ended')))
    const checkbox=a.getByRole('checkbox',{name:'Allow an English transcript for this note',exact:true})
    if (speechEnabled) assert.equal(await checkbox.isChecked(),false)
    else assert.equal(await checkbox.count(),0)
    if (consent) {
      await a.getByRole('button',{name:'Play recording preview',exact:true}).click()
      await a.waitForFunction(()=>window.voicePlayback.some(sample=>sample.audible&&sample.started))
      if (speechEnabled) await checkbox.check()
    }
    const response=a.waitForResponse(response=>response.url().startsWith(endpoint.href+'?')&&
      response.request().method()==='POST'&&!response.url().includes('mode='))
    await a.getByRole('button',{name:'Send voice note',exact:true}).click()
    const posted=await response
    assert.equal(posted.status(),201)
    return new URL(posted.url()).searchParams.get('message')
  }
  const unconsented=await record(false)
  const unconsentedView=await (await request(peer,unconsented)).json()
  assert.ok(unconsentedView.waveform.some(level=>level>0))
  assert.equal(unconsentedView.canTranscribe,false)
  assert.equal((await request(sender,unconsented,'transcribe','POST')).status,speechEnabled?403:503)
  const voice=await record(true)
  await b.getByRole('img',{name:'Voice note waveform'}).nth(1).waitFor()
  await b.getByRole('button',{name:'Play voice note',exact:true}).last().click()
  await b.waitForFunction(()=>window.voicePlayback.some(sample=>sample.audible&&sample.started&&sample.duration>3))
  assert.equal((await request(null,voice,'audio')).status,401)
  assert.equal((await request(outsider,voice,'audio')).status,404)
  assert.equal((await request(peer,voice,'audio','GET',randomUUID())).status,404)
  assert.equal((await request(peer,voice,'transcribe','POST')).status,speechEnabled?403:503)
  assert.ok((await peer.client.rpc('st_v6_voice_note_command',{p_action:'read',p_actor:peer.id,p_chat:chat,p_message:voice})).error)
  const clip=await request(peer,voice,'audio')
  assert.equal(clip.headers.get('content-type'),'audio/wav')
  assert.match(clip.headers.get('cache-control'),/private, no-store/)
  const buffer=Buffer.from(await clip.arrayBuffer())
  assert.equal(buffer.subarray(0,4).toString(),'RIFF')
  assert.equal(buffer.subarray(8,12).toString(),'WAVE')
  if (speechEnabled) {
    await a.getByRole('button',{name:'Generate English transcript',exact:true}).click()
    await a.getByText(/Transcript · .*welcome everyone/i).waitFor({timeout:40000})
    await b.getByText(/Transcript · .*welcome everyone/i).waitFor({timeout:30000})
  }
  const dbRead=(id,columns)=> {
    assert.match(id,/^[\da-f-]{36}$/i)
    return execFileSync('docker',['exec',database,'psql','-U','postgres','-d','postgres','-Atqc',
      `select ${columns} from sectalk_private.st_v6_voice_note where message='${id}'`],{encoding:'utf8'}).trim()
  }
  const [sealed,speech]=dbRead(voice,"encode(sealed,'hex'),encode(transcript,'hex')").split('|').map(part=>Buffer.from(part,'hex'))
  assert.equal(sealed.length,buffer.length-44+28)
  assert.notDeepEqual(sealed.subarray(12,-16),buffer.subarray(44))
  if (speechEnabled) assert.ok(speech.length>28 && !speech.includes(Buffer.from('Welcome everyone')))
  else assert.equal(speech.length,0)
  assert.ok((await request(peer,voice)).ok)
  data(await sender.client.rpc('st_v5_message_action',{p_message:voice,p_action:'revoke'}))
  assert.equal((await request(peer,voice,'audio')).status,404)
  assert.equal(dbRead(voice,'message'),'')
  if (speechEnabled) await b.getByText(/Transcript · .*welcome everyone/i).waitFor({state:'hidden'})
  await a.getByRole('button',{name:'Record voice note',exact:true}).click()
  await a.getByRole('button',{name:'Stop recording',exact:true}).waitFor()
  await a.getByRole('button',{name:'Block contact',exact:true}).click()
  await a.getByRole('button',{name:'Block',exact:true}).click()
  await a.waitForFunction(()=>window.voiceCaptures.every(track=>track.readyState==='ended'))
  assert.equal((await request(peer,unconsented,'audio')).status,404)
  console.log('Microphone capture, peer playback, waveform, managed ciphertext and revocation passed.'+
    (speechEnabled ? ' Offline speech and consent also passed.' : ' Core playback passed with optional speech disabled.')+
    (android ? ' The recipient used Chrome on the Android emulator.' : ''))
} finally {
  await android?.close()
  await browser?.close()
  await Promise.allSettled(users.map(person=>admin.auth.admin.deleteUser(person.id)))
}
