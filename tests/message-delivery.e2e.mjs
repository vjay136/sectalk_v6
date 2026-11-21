// Run against the isolated loopback app and Supabase stack.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.href,app.origin+'/')
assert.match(app.origin,/^https?:\/\/127\.0\.0\.1(?::\d+)?$/)
assert.equal(supabase.href,supabase.origin+'/')
const database=new Map([
  ['http://127.0.0.1:55321','supabase_db_v4-auth-qa'],
  ['http://127.0.0.1:56801','supabase_db_v6-bundle243-qa'],
]).get(supabase.origin)
assert.ok(database,'Use a disposable local SecTalk database')
const key = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const serviceKey = process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
assert.ok(key&&serviceKey)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const options={auth:{persistSession:false,autoRefreshToken:false}}
const admin=createClient(supabase.href,serviceKey,options)
const suffix=randomUUID().slice(0,8)
const password=randomUUID()+'1!Q'
const users=[]
let browser
let chat

function sql(input){
  return execFileSync('docker',['exec','-i',database,'psql','-XqtA','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres'],{
    input,encoding:'utf8',timeout:10000,windowsHide:true,
  }).trim()
}

function removeFixtureChat(){
  if(!chat)return
  assert.equal(users.length,2)
  for(const id of [chat,...users])assert.match(id,/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/)
  const [first,second]=[...users].sort()
  sql(`begin;
    do $$ begin
      if not exists(select 1 from public.st_chats where id='${chat}' and member_a='${first}' and member_b='${second}') then
        raise exception 'Synthetic chat does not match its two fixture accounts';
      end if;
    end $$;
    delete from public.st_messages where chat_id='${chat}';
    delete from public.st_chats where id='${chat}';
    commit;`)
}

function data(result){
  if(result.error)throw new Error(result.error.message)
  return result.data
}

async function account(name,label){
  const handle=name+'_'+suffix
  const email=handle+'@example.org'
  const {user}=data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  users.push(user.id)
  const client=createClient(supabase.href,key,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:label}))
  return {client,email,handle,label}
}

async function open(account,contact,read=true){
  const page=await browser.newPage({locale:'en-US'})
  await page.goto(new URL('/#account',app).href)
  await page.getByLabel('Email address',{exact:true}).fill(account.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  const [signIn]=await Promise.all([
    page.waitForResponse(response=>response.url()===new URL('/api/auth/sign-in',app).href && response.request().method()==='POST'),
    page.locator('button.submit-auth').click(),
  ])
  assert.ok(signIn.ok(),`Application sign-in for ${account.label} returned HTTP ${signIn.status()}`)
  const inbox=page.getByRole('navigation',{name:'SecTalk features'})
  const rules=page.getByRole('button',{name:'Accept and continue',exact:true})
  const blocked=page.locator('main [role="alert"]').filter({hasText:/\S/})
    .or(page.getByRole('heading',{name:'Verify this sign-in',exact:true})).first()
  await inbox.or(rules).or(blocked).first().waitFor()
  if(await rules.isVisible()){
    await page.getByRole('checkbox',{name:'I accept the SecTalk Community Rules.'}).check()
    await rules.click()
  }
  await inbox.or(blocked).first().waitFor()
  if(!(await inbox.isVisible())&&await blocked.isVisible()){
    assert.fail(`Inbox access for ${account.label}: ${await blocked.textContent()}`)
  }
  await inbox.waitFor()
  if(!read)await page.evaluate(()=>{
    window.secTalkDeliveryVisible=false
    Object.defineProperty(document,'visibilityState',{configurable:true,get:()=>window.secTalkDeliveryVisible?'visible':'hidden'})
  })
  await page.locator('.chat-item').filter({hasText:contact.label}).click()
  return page
}

try{
  assert.equal(sql('select 1;'),'1','Use the matching disposable local database')
  const sender=await account('delivery_a','Delivery Sender')
  const recipient=await account('delivery_b','Delivery Recipient')
  chat=data(await sender.client.rpc('st_request',{p_handle:recipient.handle}))
  data(await recipient.client.rpc('st_respond',{p_chat:chat,p_accept:true}))
  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const first=await open(sender,recipient)
  const attempts=[]
  let releaseRequest
  const firstRequest=new Promise(resolve=>{releaseRequest=resolve})
  await first.route('**/rest/v1/rpc/st_send',async route=>{
    if(route.request().method()!=='POST'){await route.continue();return}
    attempts.push(route.request().postDataJSON().p_id)
    if(attempts.length===1){await firstRequest;await route.abort('failed')}
    else await route.continue()
  })
  const body='Delivery lifecycle '+suffix
  const status=first.locator('.message').filter({hasText:body})
  await first.getByRole('textbox',{name:'Write a message',exact:true}).fill(body)
  await first.getByRole('button',{name:'Send message',exact:true}).click()
  await status.getByText('Queued',{exact:true}).waitFor()
  releaseRequest()
  await status.getByText('Failed to send',{exact:true}).waitFor()
  await status.getByRole('button',{name:'Retry message',exact:true}).click()
  await status.getByText('Sent',{exact:true}).waitFor()
  assert.equal(attempts.length,2)
  assert.equal(attempts[0],attempts[1])

  const second=await open(recipient,sender,false)
  await second.getByText(body,{exact:true}).waitFor()
  await status.getByText('Delivered',{exact:true}).waitFor()
  assert.equal(await status.getByText('Read',{exact:true}).count(),0)
  await second.evaluate(()=>{
    window.secTalkDeliveryVisible=true
    document.dispatchEvent(new Event('visibilitychange'))
  })
  await status.getByText('Read',{exact:true}).waitFor()
  const saved=data(await sender.client.from('st_messages').select('id,delivered_at').eq('chat_id',chat).eq('body',body))
  assert.equal(saved.length,1)
  assert.equal(saved[0].id,attempts[0])
  assert.ok(saved[0].delivered_at)
  console.log('Passed queued, failed, stable-ID retry, sent, delivered and read states in two browsers.')
}finally{
  try{
    await browser?.close()
  }finally{
    try{
      removeFixtureChat()
    }catch(error){
      console.error('Could not delete the synthetic delivery chat:',error.message)
      process.exitCode=1
    }
    const cleanup=await Promise.allSettled(users.map(async id=>data(await admin.auth.admin.deleteUser(id))))
    for(const result of cleanup){
      if(result.status==='rejected'){
        console.error('Could not delete a synthetic delivery account:',result.reason)
        process.exitCode=1
      }
    }
  }
}
