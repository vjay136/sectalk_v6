// Run against the disposable Supabase stack and the isolated app on 3500 with ROOM_GUEST_SERVICE_KEY configured.
import assert from 'node:assert/strict'
import {execFileSync} from 'node:child_process'
import {randomUUID} from 'node:crypto'
import {createClient} from '@supabase/supabase-js'

const app=new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase=new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.href,'http://127.0.0.1:3500/')
assert.equal(supabase.hostname,'127.0.0.1')
const {SECTALK_STORAGE_TEST_PUBLIC_KEY:key,SECTALK_STORAGE_TEST_SERVICE_KEY:serviceKey}=process.env
assert.ok(key && serviceKey)
const auth={persistSession:false,autoRefreshToken:false}
const admin=createClient(supabase.href,serviceKey,{auth})
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const endpoint=new URL('/api/rooms/guests',app)
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
  const person={client,id:user.id,handle,email}
  accounts.push(person)
  person.token=data(await client.auth.signInWithPassword({email,password})).session.access_token
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:name}))
  return person
}

try {
  assert.equal((await (await fetch(endpoint)).json()).configured,true)
  const [owner,member]=await Promise.all([account('RoomLinkOwner'),account('RoomLinkMember')])
  const workspace=data(await owner.client.rpc('st_v2_create_workspace',{p_name:'Guest room browser workspace'}))
  data(await owner.client.rpc('st_v2_invite',{p_workspace:workspace,p_handle:member.handle}))
  const invite=data(await member.client.from('st_v2_invites').select('id').eq('workspace_id',workspace).single())
  data(await member.client.rpc('st_v2_reply_invite',{p_invite:invite.id,p_accept:true}))
  const room=randomUUID(),anotherRoom=randomUUID(),post=randomUUID(),keep=randomUUID(),foreign=randomUUID(),memberPost=randomUUID()
  const name='Room guest '+randomUUID().slice(0,8)
  for (const [id,title] of [[room,name],[anotherRoom,'Separate room']]) {
    data(await owner.client.rpc('st_v6_room_create',{p_id:id,p_workspace:workspace,p_name:title,p_kind:'public',p_template:'blank'}))
  }
  data(await member.client.rpc('st_v6_room_membership',{p_room:room,p_action:'join'}))
  const releaseText='Guest-readable agenda <script>fixture</script>'
  const privateText='Unselected owner-only text'
  const otherText='Member-only room text'
  await Promise.all([
    owner.client.rpc('st_v6_room_post',{p_room:room,p_id:post,p_body:releaseText}).then(data),
    owner.client.rpc('st_v6_room_post',{p_room:room,p_id:keep,p_body:privateText}).then(data),
    owner.client.rpc('st_v6_room_post',{p_room:anotherRoom,p_id:foreign,p_body:'Separate room content'}).then(data),
    member.client.rpc('st_v6_room_post',{p_room:room,p_id:memberPost,p_body:otherText}).then(data),
  ])
  function request(action,values={},authorization) {
    return fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json',
      ...(authorization?{Authorization:authorization}:{})},body:JSON.stringify({action,...values})})
  }
  const host=(action,values={})=>request(action,{room,...values},'Bearer '+owner.token)
  assert.equal((await host('create',{posts:[post]})).status,403)
  data(await owner.client.rpc('st_v6_set_room_forwarding',{p_room:room,p_allowed:false}))
  // Seed only the synthetic room's label. The rollback suite uses the real AAL2 classification RPC.
  execFileSync('docker',['exec','supabase_db_v4-auth-qa','psql','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1',
    '-c',`update public.st_v6_rooms set classification='public' where id='${room}'`],{stdio:'ignore'})
  assert.equal((await host('create',{posts:[post]})).status,403)
  data(await owner.client.rpc('st_v6_set_room_forwarding',{p_room:room,p_allowed:true}))
  assert.equal((await host('create',{posts:[foreign]})).status,403)
  assert.equal((await host('create',{posts:[memberPost]})).status,403)
  assert.equal((await request('create',{room,posts:[post]},'Bearer '+member.token)).status,403)
  assert.ok((await member.client.rpc('st_v6_room_guest_command',{p_action:'view',p_room:room,p_actor:owner.id})).error)

  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const page=await browser.newPage({locale:'en-US'})
  await page.goto(app.href)
  await page.getByLabel('Email address',{exact:true}).fill(owner.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Rooms',exact:true}).click()
  const directory=page.getByRole('region',{name:'Room directory',exact:true})
  await directory.getByRole('button',{name:new RegExp(name)}).click()
  const panel=directory.getByRole('region',{name,exact:true})
  await panel.getByRole('group',{name:'Room tabs'}).getByRole('button',{name:'Settings',exact:true}).click()
  const controls=panel.getByRole('region',{name:'Room guest links',exact:true})
  assert.equal(await controls.getByRole('checkbox',{name:otherText,exact:true}).count(),0)
  await controls.getByRole('checkbox',{name:releaseText,exact:true}).check()
  await controls.getByRole('button',{name:'Create room guest link',exact:true}).click()
  const field=controls.getByRole('textbox',{name:'Room guest link',exact:true})
  await field.waitFor()
  const url=new URL(await field.inputValue())
  const ticket=url.hash.slice(1)
  assert.equal(url.pathname,'/room-guest')
  assert.equal(url.search,'')
  const [link]=(await (await host('view')).json()).links
  assert.ok(Date.parse(link.expires_at)-Date.now()<=600000)
  assert.equal((await request('revoke',{room,link:link.id},'Bearer '+member.token)).status,403)

  const guest=await browser.newPage({locale:'en-US'})
  const redeemed=guest.waitForResponse(response=>response.url()===endpoint.href &&
    response.request().postDataJSON()?.action==='redeem')
  await guest.goto(url.href)
  const response=await redeemed
  assert.equal(response.status(),200)
  assert.match(response.headers()['cache-control'],/no-store/)
  const capability=await response.json()
  assert.deepEqual(Object.keys(capability).sort(),['access','expiresAt','name','posts'])
  assert.ok(Date.parse(capability.expiresAt)-Date.now()<=120000)
  await guest.getByRole('heading',{name,exact:true}).waitFor()
  await guest.getByText(releaseText,{exact:true}).waitFor()
  assert.equal(new URL(guest.url()).hash,'')
  assert.equal(await guest.getByText(privateText,{exact:true}).count(),0)
  assert.equal(await guest.getByText(otherText,{exact:true}).count(),0)
  assert.equal(await guest.getByRole('textbox').count(),0)
  assert.equal(await guest.getByRole('navigation').count(),0)
  assert.equal(await guest.evaluate(()=>Object.keys(localStorage).some(key=>/^sb-.*auth-token$/.test(key))),false)
  const guestAuth='Guest '+capability.access
  assert.equal((await request('read',{room:anotherRoom},guestAuth)).status,403)
  assert.equal((await request('view',{room},guestAuth)).status,401)
  assert.equal((await request('write',{room,body:'No'},guestAuth)).status,400)
  assert.ok((await createClient(supabase.href,key,{auth}).auth.getUser(capability.access)).error)

  data(await owner.client.rpc('st_v6_room_post_action',{p_room:room,p_post:post,p_action:'edit',p_body:'Private updated content'}))
  await guest.getByText('No shared posts are available.',{exact:true}).waitFor()
  assert.equal(await guest.getByText('Private updated content',{exact:true}).count(),0)
  await controls.getByRole('button',{name:'Revoke room guest link',exact:true}).click()
  await controls.getByText('Guest link revoked.',{exact:true}).waitFor()
  await guest.getByText('This guest room session is closed.',{exact:true}).waitFor()
  assert.equal((await request('read',{},guestAuth)).status,403)
  assert.equal((await request('redeem',{ticket})).status,403)

  const expiring=await (await host('create',{posts:[keep]})).json()
  const timerGuest=await browser.newPage({locale:'en-US'})
  await timerGuest.clock.install()
  let finishRead
  const stalledRead=new Promise(resolve=>{finishRead=resolve})
  await timerGuest.route(endpoint.href,async route=>{
    if (route.request().postDataJSON()?.action!=='read') return route.continue()
    await stalledRead
    await route.abort().catch(()=>{})
  })
  await timerGuest.goto(new URL('/room-guest#'+expiring.ticket,app).href)
  await timerGuest.getByText(privateText,{exact:true}).waitFor()
  try {
    await timerGuest.clock.fastForward(121000)
    await timerGuest.getByText('This guest room session is closed.',{exact:true}).waitFor()
    assert.equal(await timerGuest.getByText(privateText,{exact:true}).count(),0)
  } finally { finishRead() }
  console.log('Passed owner-scoped room guest sharing, unlinked browser read-only capabilities, content isolation and live revocation.')
} finally {
  await browser?.close()
  await Promise.allSettled(accounts.map(person=>admin.auth.admin.deleteUser(person.id)))
}
