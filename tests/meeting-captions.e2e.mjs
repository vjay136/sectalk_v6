// Run against the disposable local speech worker with synthetic host and guest 16 kHz WAV paths.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { createClient } from '@supabase/supabase-js'
import { RoomServiceClient, TrackSource } from 'livekit-server-sdk'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname,'127.0.0.1')
assert.equal(supabase.hostname,'127.0.0.1')
const { SECTALK_STORAGE_TEST_PUBLIC_KEY: key, SECTALK_STORAGE_TEST_SERVICE_KEY: serviceKey,
  SECTALK_CAPTION_HOST_WAV: hostWav, SECTALK_CAPTION_GUEST_WAV: guestWav } = process.env
assert.ok(key && serviceKey && hostWav && guestWav)
const auth={persistSession:false,autoRefreshToken:false}
const admin=createClient(supabase.href,serviceKey,{auth})
const media=new RoomServiceClient('http://127.0.0.1:7880','devkey','secret')
const { chromium }=await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const password=randomUUID()+'!1Q'
const endpoint=new URL('/api/meetings/captions',app)
const accounts=[]
const browsers=[]

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
  person.token=data(await client.auth.signInWithPassword({email,password})).session.access_token
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:name}))
  return person
}

try {
  assert.equal((await (await fetch(endpoint)).json()).configured,true)
  const [host,guest,outsider]=await Promise.all([account('CaptionHost'),account('CaptionGuest'),account('CaptionOther')])
  const workspace=data(await host.client.rpc('st_v2_create_workspace',{p_name:'Caption fixture'}))
  for (const person of [guest,outsider]) {
    data(await host.client.rpc('st_v2_invite',{p_workspace:workspace,p_handle:person.handle}))
    const invite=data(await person.client.from('st_v2_invites').select('id').eq('workspace_id',workspace).single())
    data(await person.client.rpc('st_v2_reply_invite',{p_invite:invite.id,p_accept:true}))
  }
  const title='Caption fixture '+randomUUID().slice(0,8)
  const meeting=data(await host.client.rpc('st_v6_start_instant_meeting',{
    p_id:randomUUID(),p_workspace:workspace,p_title:title,p_minutes:15,
  }))
  data(await guest.client.rpc('st_v3_request_admission',{p_meeting:meeting}))
  data(await host.client.rpc('st_v3_admit',{p_meeting:meeting,p_user:guest.id,p_allow:true}))

  function request(person,action,language) {
    return fetch(endpoint,{method:'POST',headers:{Authorization:'Bearer '+person.token,'Content-Type':'application/json'},
      body:JSON.stringify({meeting,action,language})})
  }
  async function open(person,wav) {
    const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER,args:[
      '--use-fake-device-for-media-stream','--use-fake-ui-for-media-stream','--use-file-for-fake-audio-capture='+wav,
    ]})
    browsers.push(browser)
    const page=await browser.newPage({locale:'en-US',permissions:['microphone','camera']})
    const uploads=[]
    page.on('response',response=>{
      if (response.request().method()==='PUT' && response.url().startsWith(endpoint.href+'?')) uploads.push(response.status())
    })
    const url=new URL(app)
    url.searchParams.set('meeting',meeting)
    await page.goto(url.href)
    await page.getByLabel('Email address',{exact:true}).fill(person.email)
    await page.getByLabel('Password',{exact:true}).fill(password)
    await page.locator('button.submit-auth').click()
    await page.getByRole('heading',{name:title,exact:true}).waitFor()
    await page.getByRole('button',{name:'Join audio and video',exact:true}).click()
    await page.locator('.meeting-media button[data-lk-source="microphone"]').click()
    await page.waitForSelector('.meeting-media button[data-lk-source="microphone"][aria-pressed="true"]')
    return {page,uploads}
  }

  const [a,b]=await Promise.all([open(host,hostWav),open(guest,guestWav)])
  const hostMember=await media.getParticipant('sectalk-v3-'+meeting,host.id)
  const databaseView=data(await admin.rpc('st_v6_meeting_caption_command',{
    p_meeting:meeting,p_actor:host.id,p_action:'view',p_sid:hostMember.sid,
  }))
  assert.ok(databaseView?.host && databaseView.admitted)
  const initial=await request(host,'view')
  assert.equal(initial.status,200,await initial.text())
  const begin=a.page.getByRole('button',{name:'Open captions',exact:true})
  const language=a.page.getByLabel('Spoken language',{exact:true})
  await begin.waitFor()
  await language.selectOption('es')
  assert.equal(await language.inputValue(),'es')
  await language.selectOption('en')
  assert.equal((await request(guest,'start','en')).status,403)
  assert.equal((await request(outsider,'join')).status,403)
  assert.ok((await guest.client.rpc('st_v6_meeting_caption_command',{p_meeting:meeting,p_actor:host.id,p_action:'view'})).error)
  await begin.click()
  const agree='Agree to captions and transcript'
  await b.page.getByRole('button',{name:agree,exact:true}).waitFor()
  assert.equal((await request(host,'start','hi')).status,403)
  const guestMember=await media.getParticipant('sectalk-v3-'+meeting,guest.id)
  const guestMic=guestMember.tracks.find(track=>track.source===TrackSource.MICROPHONE)
  const unauthorizedUrl=new URL(endpoint)
  unauthorizedUrl.searchParams.set('meeting',meeting)
  const sample=await readFile(guestWav)
  assert.equal((await fetch(unauthorizedUrl,{method:'PUT',headers:{Authorization:'Bearer '+guest.token,
    'Content-Type':'application/octet-stream','X-Microphone-Track':guestMic.sid},body:sample.subarray(44)})).status,403)
  assert.deepEqual(a.uploads,[])
  assert.deepEqual(b.uploads,[])

  await a.page.getByRole('button',{name:agree,exact:true}).click()
  const live='Recent captions'
  const hostLine=/CaptionHost.*welcome everyone/i
  const guestLine=/CaptionGuest.*prepare the report/i
  function captions(page,name,pattern) {
    return page.getByRole('list',{name,exact:true}).getByRole('listitem').filter({hasText:pattern}).first()
  }
  try {
    await captions(a.page,live,hostLine).waitFor({timeout:45000})
  } catch (error) {
    console.error('Synthetic host caption request statuses',a.uploads)
    throw error
  }
  assert.equal((await (await request(guest,'view')).json()).lines.length,0)
  assert.deepEqual(b.uploads,[])
  await b.page.getByRole('button',{name:agree,exact:true}).click()
  await captions(b.page,live,hostLine).waitFor({timeout:45000})
  await captions(a.page,live,guestLine).waitFor({timeout:45000})
  assert.ok(a.uploads.includes(204) && b.uploads.includes(204))
  assert.equal((await request(outsider,'view')).status,403)
  assert.equal((await fetch(unauthorizedUrl,{method:'PUT',headers:{Authorization:'Bearer '+host.token,
    'Content-Type':'application/octet-stream','X-Microphone-Track':guestMic.sid},body:sample.subarray(44)})).status,403)

  await media.removeParticipant('sectalk-v3-'+meeting,guest.id)
  await b.page.locator('.meeting-media').waitFor({state:'detached'})
  await b.page.getByRole('button',{name:'Join audio and video',exact:true}).click()
  await b.page.getByRole('button',{name:agree,exact:true}).waitFor()
  const rejoined=await media.getParticipant('sectalk-v3-'+meeting,guest.id)
  assert.notEqual(rejoined.sid,guestMember.sid)
  const awaitingConsent=await (await request(guest,'view')).json()
  assert.equal(awaitingConsent.sending,false)
  assert.deepEqual(awaitingConsent.lines,[])
  await b.page.getByRole('button',{name:agree,exact:true}).click()
  await captions(b.page,live,hostLine).waitFor()

  a.page.on('dialog', dialog=>void dialog.accept())
  await a.page.getByRole('button',{name:'End meeting',exact:true}).click()
  await captions(a.page,'Transcript lines',hostLine).waitFor()
  await captions(b.page,'Transcript lines',guestLine).waitFor()
  const transcript=await (await request(host,'view')).json()
  assert.equal(transcript.active,false)
  assert.equal(transcript.language,'en')
  assert.ok(transcript.lines.some(line=>line.speaker===guest.name && /prepare the report/i.test(line.line)))
  await b.page.getByRole('button',{name:'Withdraw caption consent',exact:true}).click()
  await captions(a.page,'Transcript lines',guestLine).waitFor({state:'hidden'})
  assert.equal((await (await request(host,'view')).json()).lines.some(line=>line.speaker===guest.name),false)
  console.log('Passed real offline captions and post-call transcript using distinct synthetic microphone audio, authenticated speaker labels, and consent withdrawal.')
} finally {
  await Promise.allSettled(browsers.map(browser=>browser.close()))
  await Promise.allSettled(accounts.map(person=>admin.auth.admin.deleteUser(person.id)))
}
