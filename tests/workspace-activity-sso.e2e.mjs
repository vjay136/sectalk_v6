import assert from 'node:assert/strict'
import {execFileSync} from 'node:child_process'
import {randomUUID} from 'node:crypto'
import {setTimeout as delay} from 'node:timers/promises'
import {createClient} from '@supabase/supabase-js'

const origin=new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
assert.equal(origin,'http://127.0.0.1:56801')
const publicKey=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const serviceKey=process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
assert.ok(publicKey&&serviceKey)
const options={auth:{persistSession:false,autoRefreshToken:false}}
const service=createClient(origin,serviceKey,options)
const web=process.env.SECTALK_STORAGE_TEST_APP
if(web) assert.equal(new URL(web).origin,'http://127.0.0.1:3492')
const fixture=randomUUID().slice(0,8)
const domain='activity-'+fixture+'.example.invalid'
const provider='custom:activity-'+fixture
const password=randomUUID()+'!3q'
const clients=[]
let owner,sender,workspace,control,browser

function data(result) {
  if(result.error) throw result.error
  return result.data
}
const sql=input=>execFileSync('docker',['exec','-i','supabase_db_v6-bundle243-qa','psql','-Xq','-U','postgres',
  '-d','postgres','-v','ON_ERROR_STOP=1'],{input,windowsHide:true})

async function account(label) {
  const handle=label+'_'+fixture
  const email=handle+'@example.invalid'
  const {user}=data(await service.auth.admin.createUser({email,password,email_confirm:true}))
  return {id:user.id,handle,email}
}
async function signIn(person) {
  const client=createClient(origin,publicKey,options)
  clients.push(client)
  const {session}=data(await client.auth.signInWithPassword({email:person.email,password}))
  await client.realtime.setAuth(session.access_token)
  const id=JSON.parse(Buffer.from(session.access_token.split('.')[1],'base64url').toString()).session_id
  assert.match(id,/^[a-f0-9-]{36}$/)
  return {client,id}
}
function subscribe(client,topic,events) {
  const stream=client.channel(topic,{config:{private:true}})
  for(const event of ['room_activity','channel_activity','category_alert']) {
    stream.on('broadcast',{event},({payload})=>events.push({event,payload}))
  }
  return new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(new Error('No subscription result for '+topic)),15000)
    stream.subscribe(status=>{
      if(status==='SUBSCRIBED'||status==='CHANNEL_ERROR') {
        clearTimeout(timer)
        resolve(status)
      }
    })
  })
}
async function waitFor(condition,label) {
  const deadline=Date.now()+15000
  while(!condition()) {
    if(Date.now()>=deadline) throw new Error('Expected broadcast did not arrive: '+label)
    await delay(100)
  }
}

async function openInbox() {
  const page=await browser.newPage()
  await page.goto(new URL('/#account',web).href)
  await page.getByLabel('Email address',{exact:true}).fill(owner.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  const signIn=page.waitForResponse(response=>response.url().endsWith('/api/auth/sign-in'))
  await page.locator('button.submit-auth').click()
  const response=await signIn
  assert.equal(response.status(),200)
  const {access_token}=await response.json()
  const id=JSON.parse(Buffer.from(access_token.split('.')[1],'base64url').toString()).session_id
  assert.match(id,/^[a-f0-9-]{36}$/)
  await page.getByRole('navigation',{name:'SecTalk features'}).waitFor()
  return {page,id}
}

try {
  owner=await account('activity_owner')
  sender=await account('activity_sender')
  const [signed,plain,writer]=await Promise.all([signIn(owner),signIn(owner),signIn(sender)])
  data(await signed.client.rpc('st_save_profile',{p_handle:owner.handle,p_name:'Activity owner'}))
  data(await writer.client.rpc('st_save_profile',{p_handle:sender.handle,p_name:'Activity sender'}))
  sql(`insert into public.st_v2_subscriptions(user_id,plan,status,period_end)
    values('${owner.id}','enterprise','active',now()+interval '1 day');`)
  workspace=data(await signed.client.rpc('st_v2_create_workspace',{p_name:'Protected activity '+fixture}))
  control=data(await signed.client.rpc('st_v2_create_workspace',{p_name:'Ordinary activity '+fixture}))
  const room=randomUUID()
  const ordinaryRoom=randomUUID()
  for(const [space,id] of [[workspace,room],[control,ordinaryRoom]]) {
    data(await signed.client.rpc('st_v6_room_create',{p_id:id,p_workspace:space,p_name:'Activity room',
      p_kind:'public',p_template:'blank'}))
  }
  const channel=data(await signed.client.rpc('st_v2_create_channel',{p_workspace:workspace,p_name:'activity-protected'}))
  sql(`begin;
    insert into public.st_v2_members(workspace_id,user_id,role)
      values('${workspace}','${sender.id}','member'),('${control}','${sender.id}','member');
    insert into public.st_v6_room_members(room_id,user_id,role)
      values('${room}','${sender.id}','member'),('${ordinaryRoom}','${sender.id}','member');
    insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
      values('oidc','${provider}','Synthetic provider','fixture','fixture','https://${domain}',array['openid','email'],true);
    insert into sectalk_private.st_v7_oidc_domain_approvals values('${domain}','${provider}');
    insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values('${workspace}','${domain}',now());
    insert into sectalk_private.st_v7_workspace_sso(workspace,domain,protocol,provider)
      values('${workspace}','${domain}','oidc','${provider}');
    insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
      values('${signed.id}','${workspace}','${owner.id}','oidc','${provider}'),
        ('${writer.id}','${workspace}','${sender.id}','oidc','${provider}');
    insert into sectalk_private.st_v8_workspace_entry_sso values('${workspace}','oidc','${provider}'); commit;`)

  const signedTopic='st:workspace-session:'+owner.id+':'+signed.id
  const accountTopic='st:account:'+owner.id
  const signedSessionEvents=[],plainSessionEvents=[],signedAccountEvents=[],plainAccountEvents=[]
  const results=await Promise.all([
    subscribe(signed.client,signedTopic,signedSessionEvents),
    subscribe(plain.client,'st:workspace-session:'+owner.id+':'+plain.id,plainSessionEvents),
    subscribe(signed.client,accountTopic,signedAccountEvents),
    subscribe(plain.client,accountTopic,plainAccountEvents),
    subscribe(plain.client,signedTopic,[]),
  ])
  assert.deepEqual(results,['SUBSCRIBED','SUBSCRIBED','SUBSCRIBED','SUBSCRIBED','CHANNEL_ERROR'])
  const post=async (roomId,text,parent=null)=>{
    const id=randomUUID()
    data(await writer.client.rpc('st_v6_room_post',{p_room:roomId,p_id:id,p_body:text,p_parent:parent}))
    return id
  }
  const root=await post(room,'Protected plain activity')
  data(await signed.client.from('st_v6_thread_follows').insert({room_id:room,post_id:root}))
  await post(room,'Protected followed reply',root)
  await post(room,'Protected mention @'+owner.handle)
  data(await writer.client.rpc('st_v2_post',{p_channel:channel,p_id:randomUUID(),p_body:'Protected channel activity'}))
  await post(ordinaryRoom,'Ordinary control activity')
  await waitFor(()=>signedSessionEvents.some(({payload})=>payload.room_id===room&&!payload.mention_kind)
    &&signedSessionEvents.some(({payload})=>payload.room_id===room&&payload.mention_kind==='mention.user')
    &&signedSessionEvents.some(({payload})=>payload.channel_id===channel)
    &&signedSessionEvents.some(({payload})=>payload.kind==='thread.reply'),'protected room, mention, followed reply and channel')
  await waitFor(()=>[signedAccountEvents,plainAccountEvents].every(events=>events.some(({payload})=>payload.room_id===ordinaryRoom)),
    'ordinary account events for both sessions')
  for(const events of [signedAccountEvents,plainAccountEvents,plainSessionEvents]) {
    assert.ok(events.every(({payload})=>payload.room_id!==room&&payload.channel_id!==channel&&payload.kind!=='thread.reply'))
  }

  let verifiedInbox,passwordInbox
  const mention='You were mentioned directly in a room.'
  const channelNotice='New activity in one of your workspace channels.'
  const ordinaryNotice='New activity in one of your rooms.'
  const notice=(inbox,message)=>inbox.page.getByText(message,{exact:true})
  if(web) {
    const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
    browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
    ;[verifiedInbox,passwordInbox]=await Promise.all([openInbox(),openInbox()])
    sql(`insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
      values('${verifiedInbox.id}','${workspace}','${owner.id}','oidc','${provider}');`)
    await post(ordinaryRoom,'Browser subscription control')
    for(const inbox of [verifiedInbox,passwordInbox]) {
      await notice(inbox,ordinaryNotice).waitFor()
      await inbox.page.getByRole('button',{name:'Dismiss notice'}).click()
    }
    data(await writer.client.rpc('st_v2_post',{p_channel:channel,p_id:randomUUID(),p_body:'Protected browser channel alert'}))
    await notice(verifiedInbox,channelNotice).waitFor()
    await post(room,'Protected browser mention @'+owner.handle)
    await notice(verifiedInbox,mention).waitFor()
    assert.equal(await notice(passwordInbox,mention).count(),0)
    assert.equal(await notice(passwordInbox,channelNotice).count(),0)
    await verifiedInbox.page.getByRole('button',{name:'Dismiss notice'}).click()
    // A direct mention has higher priority than the earlier channel notice.
    if(await notice(verifiedInbox,channelNotice).count()) {
      await verifiedInbox.page.getByRole('button',{name:'Dismiss notice'}).click()
    }
  }

  sql(`update auth.custom_oauth_providers set enabled=false where identifier='${provider}';`)
  const previous=signedSessionEvents.length
  // The recipient-side check also covers a committed alert from an independent background writer.
  sql(`select sectalk_private.st_v8_send_conversation_activity('${room}',null,'${owner.id}','room_activity',
    '{"room_id":"${room}","mention_kind":"mention.user","priority":"high"}');`)
  const ordinaryCount=plainAccountEvents.length
  await post(ordinaryRoom,'Control after revocation')
  await waitFor(()=>plainAccountEvents.length>ordinaryCount,'ordinary account events after revocation')
  assert.equal(signedSessionEvents.length,previous)
  if(verifiedInbox) {
    for(const inbox of [verifiedInbox,passwordInbox]) {
      await notice(inbox,ordinaryNotice).waitFor()
      assert.equal(await notice(inbox,mention).count(),0)
    }
    console.log('Passed live browser alerts in two isolated Inbox sessions, including provider revocation.')
  }
  console.log('Passed native session routing, account isolation, room and channel alerts, and provider revocation.')
} finally {
  await browser?.close()
  await Promise.allSettled(clients.map(client=>client.removeAllChannels()))
  if(owner) sql(`begin; set local session_replication_role=replica;
    delete from public.st_v2_workspace_audit
      where workspace_id in (select id from public.st_v2_workspaces where owner='${owner.id}');
    delete from sectalk_private.st_v8_workspace_audit_custody
      where workspace in (select id from public.st_v2_workspaces where owner='${owner.id}');
    set local session_replication_role=origin;
    delete from public.st_v2_workspaces where owner='${owner.id}';
    delete from sectalk_private.st_v7_oidc_domain_approvals where domain='${domain}';
    delete from auth.custom_oauth_providers where identifier='${provider}'; commit;`)
  if(sender) data(await service.auth.admin.deleteUser(sender.id))
  if(owner) data(await service.auth.admin.deleteUser(owner.id))
}
