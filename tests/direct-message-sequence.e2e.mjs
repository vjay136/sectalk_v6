// Run against the isolated loopback app and Supabase stack.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app=new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase=new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname,'127.0.0.1')
assert.equal(supabase.hostname,'127.0.0.1')
const key=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const serviceKey=process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
assert.ok(key&&serviceKey)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const options={auth:{persistSession:false,autoRefreshToken:false}}
const admin=createClient(supabase.href,serviceKey,options)
const suffix=randomUUID().slice(0,8)
const password=randomUUID()+'1!Q'

function result(response){
  if(response.error)throw new Error(response.error.message)
  return response.data
}

async function account(name,label){
  const handle=name+'_'+suffix
  const email=handle+'@example.org'
  const {user}=result(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  const client=createClient(supabase.href,key,options)
  result(await client.auth.signInWithPassword({email,password}))
  result(await client.rpc('st_save_profile',{p_handle:handle,p_name:label}))
  return {client,email,handle,label,id:user.id}
}

const sender=await account('sequence_a','Sequence Sender')
const recipient=await account('sequence_b','Sequence Recipient')
const chat=result(await sender.client.rpc('st_request',{p_handle:recipient.handle}))
result(await recipient.client.rpc('st_respond',{p_chat:chat,p_accept:true}))
const sameTimestamp=new Date().toISOString()

async function seed(prefix,count){
  const values=Array.from({length:count},(_,index)=>({
    id:randomUUID(),chat_id:chat,sender:sender.id,body:prefix+' '+String(index+1).padStart(3,'0'),
    created_at:sameTimestamp,
  }))
  return result(await admin.from('st_messages').insert(values).select('id,sequence,body'))
    .sort((a,b)=>a.sequence-b.sequence)
}

const starting=await seed('History',60)
const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
async function open(account,contact){
  const page=await browser.newPage()
  await page.goto(new URL('/#account',app).href)
  await page.getByLabel('Email address',{exact:true}).fill(account.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation',{name:'SecTalk features'}).waitFor()
  await page.locator('.chat-item').filter({hasText:contact.label}).click()
  return page
}

try {
  const first=await open(recipient,sender)
  const visible=first.locator('.message[data-sequence]')
  const sequences=()=>visible.evaluateAll(rows=>rows.map(row=>Number(row.dataset.sequence)))
  await first.getByText(starting.at(-1).body,{exact:true}).waitFor()
  assert.deepEqual(await sequences(),starting.slice(-50).map(row=>row.sequence))

  await first.context().setOffline(true)
  const missed=await seed('Missed while offline',120)
  const hidden=missed[9]
  result(await recipient.client.rpc('st_v5_message_action',{p_message:hidden.id,p_action:'hide'}))
  assert.equal(await first.getByText(missed.at(-1).body,{exact:true}).count(),0)
  await first.context().setOffline(false)
  await first.getByText(missed.at(-1).body,{exact:true}).waitFor()
  const expected=[...starting.slice(-50),...missed.filter(row=>row.id!==hidden.id)]
  assert.deepEqual(await sequences(),expected.map(row=>row.sequence))
  assert.equal(await first.getByText(hidden.body,{exact:true}).count(),0)

  await first.getByRole('button',{name:'Load earlier messages',exact:true}).click()
  await first.getByText(starting[0].body,{exact:true}).waitFor()
  assert.deepEqual(await sequences(),[...starting.slice(0,10),...expected].map(row=>row.sequence))

  const second=await open(sender,recipient)
  await second.getByRole('textbox',{name:'Write a message',exact:true}).fill('Live ordered delivery')
  await second.getByRole('button',{name:'Send message',exact:true}).click()
  await first.getByText('Live ordered delivery',{exact:true}).waitFor()
  const ordered=await sequences()
  assert.equal(ordered.at(-1),missed.at(-1).sequence+1)
  assert.equal(ordered.length,new Set(ordered).size)
  assert.deepEqual(ordered,ordered.toSorted((a,b)=>a-b))

  const concurrent=Array.from({length:12},(_,index)=>({
    client:index%2===0?sender.client:recipient.client,
    id:randomUUID(),body:'Concurrent reply '+index,
  }))
  await Promise.all(concurrent.flatMap(entry=>[0,1].map(async()=>result(await entry.client.rpc('st_send',{
    p_chat:chat,p_id:entry.id,p_body:entry.body,
  })))))
  const sent=result(await sender.client.from('st_messages').select('sequence,body')
    .eq('chat_id',chat).in('id',concurrent.map(entry=>entry.id)).order('sequence'))
  assert.deepEqual(sent.map(row=>row.sequence),Array.from({length:12},(_,index)=>ordered.at(-1)+index+1))
  await first.getByText(sent.at(-1).body,{exact:true}).waitFor()
  assert.deepEqual(await sequences(),[...ordered,...sent.map(row=>row.sequence)])
  console.log('Passed equal-time ordering, 120-message reconnect gap fill, hidden isolation, older pagination and concurrent duplicate-free delivery.')
}finally{
  await browser.close()
}
