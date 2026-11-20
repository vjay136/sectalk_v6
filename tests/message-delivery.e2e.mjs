// Run against the isolated loopback app and Supabase stack.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname,'127.0.0.1')
assert.equal(supabase.hostname,'127.0.0.1')
const key = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const serviceKey = process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
assert.ok(key&&serviceKey)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const options={auth:{persistSession:false,autoRefreshToken:false}}
const admin=createClient(supabase.href,serviceKey,options)
const suffix=randomUUID().slice(0,8)
const password=randomUUID()+'1!Q'

function data(result){
  if(result.error)throw new Error(result.error.message)
  return result.data
}

async function account(name,label){
  const handle=name+'_'+suffix
  const email=handle+'@example.org'
  data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  const client=createClient(supabase.href,key,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:label}))
  return {client,email,handle,label}
}

const sender=await account('delivery_a','Delivery Sender')
const recipient=await account('delivery_b','Delivery Recipient')
const chat=data(await sender.client.rpc('st_request',{p_handle:recipient.handle}))
data(await recipient.client.rpc('st_respond',{p_chat:chat,p_accept:true}))
const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})

async function open(account,contact,read=true){
  const page=await browser.newPage()
  if(!read)await page.addInitScript(()=>{
    window.secTalkDeliveryVisible=false
    Object.defineProperty(document,'visibilityState',{configurable:true,get:()=>window.secTalkDeliveryVisible?'visible':'hidden'})
  })
  await page.goto(new URL('/#account',app).href)
  await page.getByLabel('Email address',{exact:true}).fill(account.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation',{name:'SecTalk features'}).waitFor()
  await page.locator('.chat-item').filter({hasText:contact.label}).click()
  return page
}

try{
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
  await browser.close()
}
