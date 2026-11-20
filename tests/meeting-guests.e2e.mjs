// Run against the disposable Supabase/LiveKit test stack and app on 3498.
// The app's local Siteverify fixture URL must point to port 3499.
import assert from 'node:assert/strict'
import {execFileSync} from 'node:child_process'
import {randomBytes,randomUUID} from 'node:crypto'
import {createServer} from 'node:http'
import {createClient} from '@supabase/supabase-js'
import {RoomServiceClient,TokenVerifier} from 'livekit-server-sdk'

const app=new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase=new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.href,'http://127.0.0.1:3498/')
assert.equal(supabase.hostname,'127.0.0.1')
const {SECTALK_STORAGE_TEST_PUBLIC_KEY:key,SECTALK_STORAGE_TEST_SERVICE_KEY:serviceKey}=process.env
assert.ok(key && serviceKey)
const auth={persistSession:false,autoRefreshToken:false}
const admin=createClient(supabase.href,serviceKey,{auth})
const provider=new RoomServiceClient('http://127.0.0.1:7880','devkey','secret')
const verifier=new TokenVerifier('devkey','secret')
const endpoint=new URL('/api/meetings/guests',app)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const accounts=[]
const challenges=[]
const password=randomUUID()+'!1Q'
const browserChallenge='valid-browser-'+randomUUID()
let browser

const fixture=createServer(async(request,response)=>{
  if (request.url!=='/siteverify' || request.method!=='POST') { response.writeHead(404).end(); return }
  const parts=[]
  for await (const part of request) parts.push(part)
  const form=new URLSearchParams(Buffer.concat(parts).toString())
  const proof=form.get('response')
  challenges.push(proof)
  if (form.get('secret')!=='guest-fixture-captcha-secret') { response.writeHead(401).end(); return }
  response.writeHead(200,{'Content-Type':'application/json'}).end(JSON.stringify({
    success:proof!=='bad',hostname:proof==='wrong-host'?'wrong.test':'127.0.0.1',
    action:proof==='wrong-action'?'sign_up':'meeting_guest',
    challenge_ts:new Date(Date.now()-(proof==='old-challenge'?301000:0)).toISOString(),
  }))
})
await new Promise((resolve,reject)=>fixture.listen(3499,'127.0.0.1',resolve).once('error',reject))

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
  const [host,cohost]=await Promise.all([account('GuestOwner'),account('GuestCohost')])
  const workspace=data(await host.client.rpc('st_v2_create_workspace',{p_name:'Guest fixture'}))
  data(await host.client.rpc('st_v2_invite',{p_workspace:workspace,p_handle:cohost.handle}))
  const invite=data(await cohost.client.from('st_v2_invites').select('id').eq('workspace_id',workspace).single())
  data(await cohost.client.rpc('st_v2_reply_invite',{p_invite:invite.id,p_accept:true}))
  const title='Guest fixture '+randomUUID().slice(0,8)
  const meeting=data(await host.client.rpc('st_v6_start_instant_meeting',{
    p_id:randomUUID(),p_workspace:workspace,p_title:title,p_minutes:15,
  }))
  data(await cohost.client.rpc('st_v3_request_admission',{p_meeting:meeting}))
  data(await host.client.rpc('st_v3_admit',{p_meeting:meeting,p_user:cohost.id,p_allow:true}))
  data(await host.client.rpc('st_v6_moderate_meeting',{p_meeting:meeting,p_action:'cohost',p_target:cohost.id,p_enabled:true}))

  function request(action,values={},authorization) {
    return fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json',
      ...(authorization?{Authorization:authorization}:{})},body:JSON.stringify({action,...values})})
  }
  const owner=(action,values={})=>request(action,{meeting,...values},'Bearer '+host.token)
  const moderator=(action,values={})=>request(action,{meeting,...values},'Bearer '+cohost.token)
  const visit=(action,access,values={})=>request(action,values,'Guest '+access)
  const submit=(ticket,captcha,name='Browser Visitor')=>request('request',{ticket,captcha,name})
  assert.equal((await owner('create')).status,403)
  assert.equal((await moderator('policy',{enabled:true})).status,403)
  assert.ok((await cohost.client.rpc('st_v6_meeting_guest_command',{p_action:'view',p_meeting:meeting,p_actor:host.id})).error)
  const emptyProbe=await submit(randomBytes(32).toString('base64url'),'unseen')
  assert.equal(emptyProbe.status,403)
  assert.deepEqual(challenges,[])
  const home=await fetch(app)
  const guestPageHeaders=await fetch(new URL('/meeting-guest',app))
  assert.doesNotMatch(home.headers.get('content-security-policy'),/challenges\.cloudflare\.com/)
  assert.match(guestPageHeaders.headers.get('content-security-policy'),/frame-src https:\/\/challenges\.cloudflare\.com/)
  assert.match(guestPageHeaders.headers.get('referrer-policy'),/no-referrer/)

  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER,
    args:['--use-fake-device-for-media-stream','--use-fake-ui-for-media-stream']})
  const hostPage=await browser.newPage({locale:'en-US',permissions:['camera','microphone']})
  const hostUrl=new URL(app)
  hostUrl.searchParams.set('meeting',meeting)
  await hostPage.goto(hostUrl.href)
  await hostPage.getByLabel('Email address',{exact:true}).fill(host.email)
  await hostPage.getByLabel('Password',{exact:true}).fill(password)
  await hostPage.locator('button.submit-auth').click()
  await hostPage.getByRole('heading',{name:title,exact:true}).waitFor()
  const panel=hostPage.getByRole('region',{name:'Guest access',exact:true})
  const control=name=>panel.getByRole('button',{name,exact:true})
  await control('Allow guest access').click()
  await control('Create guest link').click()
  const field=panel.getByLabel('Guest link',{exact:true})
  await field.waitFor()
  const guestUrl=new URL(await field.inputValue())
  const ticket=guestUrl.hash.slice(1)
  assert.equal(guestUrl.pathname,'/meeting-guest')
  assert.equal(guestUrl.search,'')
  assert.match(ticket,/^[\w-]{43}$/)
  const links=(await (await owner('view')).json()).links
  const link=links[0]
  const expires=Date.parse(link.expires_at)-Date.now()
  assert.ok(expires>0 && expires<=600000)
  assert.equal((await moderator('revoke',{link:link.id})).status,403)
  const rejected=['bad','wrong-host','wrong-action','old-challenge']
  for (const invalid of rejected) assert.equal((await submit(ticket,invalid)).status,403)
  assert.deepEqual(challenges,rejected)

  const guest=await browser.newPage({locale:'en-US',permissions:['microphone','camera']})
  await guest.route('https://challenges.cloudflare.com/turnstile/v0/api.js*',route=>route.fulfill({
    contentType:'application/javascript',body:`window.turnstile={
      render(node,options) {
        const button=document.createElement('button');
        button.type='button'; button.textContent='Verify synthetic guest';
        button.addEventListener('click',()=>options.callback(${JSON.stringify(browserChallenge)}));
        node.append(button); return 'fixture';
      },remove(){},reset(){}
    }`,
  }))
  let access
  let mediaToken
  guest.on('response',async response=>{
    if (response.url()!==endpoint.href || response.request().method()!=='POST' || !response.ok()) return
    const action=response.request().postDataJSON()?.action
    if (action==='request') access=(await response.json()).access
    if (action==='token') mediaToken=(await response.json()).token
  })
  await guest.goto(guestUrl.href)
  await guest.getByLabel('Display name',{exact:true}).fill('Browser Visitor')
  await guest.getByRole('button',{name:'Verify synthetic guest'}).click()
  await guest.getByRole('button',{name:'Request admission',exact:true}).click()
  await guest.getByText('Waiting for the host to admit you.',{exact:true}).waitFor()
  assert.equal(new URL(guest.url()).hash,'')
  assert.match(access,/^[\w-]{43}$/)
  assert.equal((await visit('token',access)).status,403)
  assert.equal((await submit(ticket,browserChallenge)).status,403)
  const lobby=(await (await owner('view')).json()).visitors
  assert.equal(lobby.length,1)
  assert.equal(lobby[0].state,'waiting')
  assert.equal((await moderator('approve',{visitor:lobby[0].id})).status,403)
  assert.equal((await moderator('view')).status,403)
  assert.equal((await visit('view',access,{meeting})).status,401)

  await hostPage.getByRole('button',{name:'Join audio and video',exact:true}).click()
  await hostPage.locator('.meeting-media button[data-lk-source="microphone"]').waitFor()
  await control('Admit guest').click()
  await guest.getByRole('button',{name:'Join meeting media',exact:true}).click()
  await guest.locator('.meeting-media button[data-lk-source="microphone"]').click()
  await guest.waitForSelector('.meeting-media button[data-lk-source="microphone"][aria-pressed="true"]')
  await hostPage.locator('.meeting-media').getByText('Guest · Browser Visitor',{exact:true}).waitFor()
  assert.ok(mediaToken)
  const claims=await verifier.verify(mediaToken)
  assert.equal(claims.sub,lobby[0].id)
  assert.equal(claims.video.room,'sectalk-v3-'+meeting)
  assert.equal(claims.video.roomJoin,true)
  assert.equal(claims.video.canPublishData,false)
  assert.equal(claims.video.roomAdmin,undefined)
  assert.ok(claims.exp-Math.floor(Date.now()/1000)<=30)
  assert.ok((await provider.listParticipants('sectalk-v3-'+meeting)).some(person=>person.identity===lobby[0].id))
  assert.equal((await guest.evaluate(()=>Object.keys(localStorage).some(key=>/^sb-.*auth-token$/.test(key)))),false)
  assert.ok((await createClient(supabase.href,key,{auth}).auth.getUser(mediaToken)).error)

  await control('Revoke guest link').click()
  await panel.getByText('Guest link revoked.',{exact:true}).waitFor()
  await guest.getByText('This guest session is closed.',{exact:false}).waitFor()
  await guest.locator('.meeting-media').waitFor({state:'detached'})
  assert.ok(!(await provider.listParticipants('sectalk-v3-'+meeting)).some(person=>person.identity===lobby[0].id))
  assert.equal((await visit('token',access)).status,403)
  assert.equal((await submit(ticket,'after-revocation')).status,403)
  assert.ok(!challenges.includes('after-revocation'))

  const expired=await (await owner('create')).json()
  const expiryId=expired.links.find(item=>item.id!==link.id).id
  assert.match(expiryId,/^[\da-f-]{36}$/)
  execFileSync('docker',['exec','supabase_db_v4-auth-qa','psql','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-c',
    `update sectalk_private.st_v6_guest_link set expires_at=now()-interval '1 second' where id='${expiryId}'`],{stdio:'ignore'})
  assert.equal((await submit(expired.ticket,'expired-link')).status,403)
  assert.ok(!challenges.includes('expired-link'))
  console.log('Passed guest link policy, CAPTCHA verification, host-only lobby, isolated media token, expiry, revocation and live disconnect.')
} finally {
  await browser?.close()
  await new Promise(resolve=>fixture.close(resolve))
  await Promise.allSettled(accounts.map(person=>admin.auth.admin.deleteUser(person.id)))
}
