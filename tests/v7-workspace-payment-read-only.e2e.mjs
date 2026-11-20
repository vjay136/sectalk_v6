import assert from 'node:assert/strict'
import {spawn,execFileSync} from 'node:child_process'
import {createHmac,generateKeyPairSync,randomUUID,verify} from 'node:crypto'
import {createServer} from 'node:http'
import {readFileSync} from 'node:fs'
import {resolve} from 'node:path'
import {setTimeout} from 'node:timers/promises'
import {createClient} from '@supabase/supabase-js'
import {fixtureAuthenticator} from './workspace-admin-fixture.mjs'

const db=new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
assert.equal(db,'http://127.0.0.1:55321')
const app='http://127.0.0.1:3489'
const key=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const service=process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
const options={auth:{persistSession:false,autoRefreshToken:false}}
const admin=createClient(db,service,options)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const suffix=randomUUID().slice(0,8)
const providerKey='sk_test_readOnly'+suffix
const webhookSecret=randomUUID()
const customer='cus_ReadOnly'+suffix
const subscription='sub_ReadOnly'+suffix
const price='price_ReadOnly'+suffix
const room=randomUUID(),chat=randomUUID(),filename=randomUUID()
const roomName='Read-only test room '+suffix
const existingPost='Earlier workspace message '+suffix
const contents=Buffer.from('Synthetic file content before payment grace ended.')
const {privateKey,publicKey}=generateKeyPairSync('ed25519')
const users=[]
let owner,workspace,child,browser,latest='active',reason=null,artifact
function data(result) {if(result.error) throw result.error;return result.data}
function sql(statement) {
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true}).trim()
}
async function account(role) {
  const handle='lock_'+role+'_'+suffix
  const email=handle+'@example.invalid'
  const password=randomUUID()+'!7gQ'
  const user=data(await admin.auth.admin.createUser({email,password,email_confirm:true})).user
  users.push(user.id)
  const client=createClient(db,key,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:'Read-only '+role}))
  return {id:user.id,client}
}
const provider=createServer((request,response)=>{
  response.setHeader('Content-Type','application/json')
  if(request.method==='GET'&&request.headers.authorization==='Bearer '+providerKey&&request.url==='/v1/subscriptions/'+subscription) {
    return response.end(JSON.stringify({id:subscription,customer,metadata:{sectalk_user:owner.id},status:latest,
      cancellation_details:{reason},cancel_at_period_end:false,items:{data:[{current_period_end:Math.floor(Date.now()/1000)
        +(latest==='active'?604800:-30*86400),price:{id:price,unit_amount:1900,currency:'usd'}}]}}))
  }
  response.writeHead(404).end(JSON.stringify({error:{message:'Unbound local resource'}}))
})
async function snapshot(label) {
  const stamp=Math.floor(Date.now()/1000)
  const payload=JSON.stringify({id:'evt_readonly_'+suffix+label,type:'customer.subscription.updated',created:stamp,
    livemode:false,data:{object:{id:subscription}}})
  const sig=createHmac('sha256',webhookSecret).update(stamp+'.'+payload).digest('hex')
  const received=await fetch(app+'/api/billing/webhook',{method:'POST',headers:{'Stripe-Signature':'t='+stamp+',v1='+sig},body:payload})
  assert.equal(received.status,204,await received.text())
}
try {
  owner=await account('owner')
  const member=await account('member')
  workspace=data(await owner.client.rpc('st_v2_create_workspace',{p_name:'Workspace payment '+suffix}))
  const [first,second]=[owner.id,member.id].sort()
  sql("insert into public.st_v2_members(workspace_id,user_id,role) values ('"+workspace+"','"+member.id+"','member');"+
    "insert into public.st_chats(id,member_a,member_b,requester,status) values ('"+chat+"','"+first+"','"+second+"','"+owner.id+"','accepted');"+
    "select public.st_v2_sync_billing('evt_readonly_"+suffix+"Seed','"+owner.id+"','"+customer+"','"+subscription+
    "','business','active',now()+interval '1 day',false,now());")
  data(await owner.client.rpc('st_v6_room_create',{p_id:room,p_workspace:workspace,p_name:roomName,p_kind:'public',p_template:'blank'}))
  data(await member.client.rpc('st_v6_room_membership',{p_room:room,p_action:'join'}))
  data(await owner.client.rpc('st_v6_room_post',{p_room:room,p_id:randomUUID(),p_body:existingPost}))
  await fixtureAuthenticator(owner.client)
  const token=data(await owner.client.auth.getSession()).session.access_token
  const bearer={Authorization:'Bearer '+token}
  await new Promise((resolve,reject)=>provider.once('error',reject).listen(0,'127.0.0.1',resolve))
  child=spawn(process.execPath,[resolve('node_modules/next/dist/bin/next'),'start','--hostname','127.0.0.1','--port','3489'],{
    cwd:resolve('supabase/.temp/v4-auth-qa/device-commands-app'),stdio:'inherit',env:{...process.env,
      NEXT_PUBLIC_SUPABASE_URL:db,NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:key,SECTALK_BILLING_SUPABASE_KEY:service,
      SECTALK_APP_URL:app,STRIPE_SECRET_KEY:providerKey,STRIPE_WEBHOOK_SECRET:webhookSecret,STRIPE_PRICE_BUSINESS_MONTHLY:price,
      SECTALK_TEST_STRIPE_ORIGIN:'http://127.0.0.1:'+provider.address().port,
      SECTALK_FILE_STORAGE_KEY:service,SECTALK_MALWARE_SCANNER_URL:'http://127.0.0.1:3487',
      SECTALK_MALWARE_SCANNER_SECRET:readFileSync('supabase/.temp/attachment-scan-local-key.txt','utf8').trim(),
      SECTALK_AUDIT_SIGNING_PRIVATE_KEY:privateKey.export({format:'der',type:'pkcs8'}).toString('base64url')},
  })
  let ready=false
  for(let i=0;i<40&&child.exitCode===null;i++){
    ready=await fetch(app+'/api/health',{signal:AbortSignal.timeout(2000)}).then(r=>r.ok).catch(()=>false)
    if(ready)break
    await setTimeout(500)
  }
  assert(ready)
  const wsFiles='/api/workspace-files?workspace='+workspace+'&file='
  const upload=(route,id)=>fetch(app+route+id,{method:'POST',
    headers:{...bearer,'X-SecTalk-File-Name':'example.txt','Content-Type':'text/plain'},body:contents})
  const initial=await upload(wsFiles,filename)
  assert.equal(initial.status,200,await initial.text())

  latest='past_due'
  await snapshot('PastDue')
  assert.equal(data(await owner.client.rpc('st_v7_workspace_payment_state',{p_workspace:workspace})).mode,'read_only')
  const read=await fetch(app+wsFiles+filename,{headers:bearer})
  assert.equal(read.status,200,await read.clone().text())
  assert.deepEqual(Buffer.from(await read.arrayBuffer()),contents)
  assert.equal((await upload(wsFiles,randomUUID())).status,423)
  assert.equal((await upload('/api/room-files?room='+room+'&file=',randomUUID())).status,423)
  assert.equal((await member.client.rpc('st_v6_task_create',{p_id:randomUUID(),p_room:room,p_chat:null,p_title:'Blocked room task'})).error?.code,'PT423')
  data(await owner.client.rpc('st_v6_task_create',{p_id:randomUUID(),p_room:null,p_chat:chat,p_title:'Personal task allowed'}))

  const audit=await fetch(app+'/api/audit/export',{method:'POST',
    headers:{...bearer,'Content-Type':'application/json'},body:JSON.stringify({workspace,query:'',source:null,from:null,before:null})})
  assert.equal(audit.status,200,await audit.clone().text())
  const envelope=await audit.json()
  assert(verify(null,Buffer.from(envelope.payload),publicKey,Buffer.from(envelope.signature,'base64url')))
  assert(JSON.parse(envelope.payload).entries.length>0)
  artifact=audit.headers.get('X-SecTalk-Export-Location')?.split('/').at(-1)
  assert(artifact)
  assert.equal((await fetch(app+'/api/exports/'+artifact,{headers:bearer})).status,200)

  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const page=await browser.newPage()
  const memberSession=data(await member.client.auth.getSession()).session
  await page.addInitScript(({name,value})=>localStorage.setItem(name,JSON.stringify(value)),
    {name:'sb-'+new URL(db).hostname.split('.')[0]+'-auth-token',value:memberSession})
  await page.goto(app)
  const nav=page.getByRole('navigation',{name:'SecTalk features'})
  await nav.getByRole('button',{name:'Rooms',exact:true}).click()
  await page.getByText('Workspace is read-only',{exact:true}).waitFor()
  await page.getByRole('button',{name:new RegExp(roomName)}).click()
  await page.getByText(existingPost,{exact:true}).waitFor()
  const box=page.getByLabel('Write a room message',{exact:true})
  await box.fill('Queue should not bypass this lock')
  const rejected=page.waitForResponse(response=>response.url().includes('/rpc/st_v6_room_post'))
  await page.getByRole('button',{name:'Send',exact:true}).click()
  assert.equal((await rejected).status(),423)

  latest='canceled';reason='payment_failed'
  await snapshot('FailedCancellation')
  assert.equal(data(await owner.client.rpc('st_v7_workspace_payment_state',{p_workspace:workspace})).mode,'read_only')
  latest='active';reason=null
  await snapshot('PaidRecovery')
  assert.equal(data(await owner.client.rpc('st_v7_workspace_payment_state',{p_workspace:workspace})).mode,'active')
  const stored=page.waitForResponse(response=>response.url().includes('/rpc/st_v6_room_post'))
  await box.fill('Posting resumes after current Stripe payment')
  await page.getByRole('button',{name:'Send',exact:true}).click()
  assert.equal((await stored).status(),204)
  await page.getByText('Posting resumes after current Stripe payment',{exact:true}).waitFor()
  await page.getByText('Workspace is read-only',{exact:true}).waitFor({state:'detached',timeout:20000})
  await page.getByText(existingPost,{exact:true}).waitFor()
  console.log('Workspace read-only browser, 423 native sends/uploads/tasks, existing storage and signed export, and Stripe recovery passed')
} finally {
  await browser?.close()
  child?.kill()
  provider.closeAllConnections()
  await new Promise(resolve=>provider.close(resolve))
  if(artifact){
    await admin.storage.from('sectalk-exports').remove([artifact])
    sql("delete from sectalk_private.st_v6_export_objects where id='"+artifact+"';")
  }
  if(workspace){
    await admin.storage.from('sectalk-workspace-files').remove([workspace+'/'+filename])
    sql("delete from sectalk_private.st_v6_workspace_files where workspace='"+workspace+"';"+
      "delete from public.st_v2_workspaces where id='"+workspace+"';")
  }
  sql("delete from public.st_chats where id='"+chat+"'; delete from sectalk_private.st_v7_stripe_receipts where id like 'evt_readonly_"+suffix+"%';"+
    "delete from sectalk_private.st_v2_billing_events where event_id like 'evt_readonly_"+suffix+"%';")
  for(const user of users) await admin.auth.admin.deleteUser(user)
}
