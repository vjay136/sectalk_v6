// Use the loopback-only SecTalk QA app and Supabase Storage test credentials.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const url=process.env.SECTALK_STORAGE_TEST_URL
const app=process.env.SECTALK_STORAGE_TEST_APP
assert.equal(new URL(url).hostname,'127.0.0.1')
assert.equal(new URL(app).hostname,'127.0.0.1')
const options={auth:{persistSession:false,autoRefreshToken:false}}
const admin=createClient(url,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const password=randomUUID()+'1!Q'
const suffix=randomUUID().slice(0,8)
const bucket='sectalk-chat-files'

function data(result){
  if(result.error)throw result.error
  return result.data
}

async function account(name){
  const handle='dupe_'+name.split(' ').at(-1).toLowerCase()+'_'+suffix
  const email=handle+'@example.org'
  data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  const client=createClient(url,process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY,options)
  const {session}=data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:name}))
  return {client,handle,email,token:session.access_token}
}

async function connect(sender,recipient){
  const chat=data(await sender.client.rpc('st_request',{p_handle:recipient.handle}))
  data(await recipient.client.rpc('st_respond',{p_chat:chat,p_accept:true}))
  return chat
}

async function stage(actor,chat,name,bytes){
  const file=randomUUID()
  data(await actor.client.rpc('st_v5_stage_file',{p_chat:chat,p_id:file,p_filename:name,p_bytes:bytes.length}))
  data(await actor.client.storage.from(bucket).upload(file,bytes,{contentType:'application/octet-stream'}))
  return file
}

function publish(actor,file){
  return fetch(app+'/api/files/publish',{
    method:'POST',headers:{Authorization:'Bearer '+actor.token,'Content-Type':'application/json'},
    body:JSON.stringify({file,caption:'',mime:'text/plain',hash:'0'.repeat(64)}),
  })
}

async function publication(actor,file){
  const response=await publish(actor,file)
  const body=await response.json()
  assert.equal(response.status,200,body.error)
  assert.match(response.headers.get('cache-control'),/no-store/)
  assert.equal(body.id,file)
  assert.deepEqual(Object.keys(body).sort(),['duplicate','id'])
  return body.duplicate
}

const sender=await account('Duplicate Sender')
const recipient=await account('Duplicate Recipient')
const outsider=await account('Duplicate Outsider')
const chat=await connect(sender,recipient)
const otherChat=await connect(sender,outsider)
const bytes=Buffer.from('Matching attachment '+suffix)
const first=await stage(sender,chat,'original.txt',bytes)
const second=await stage(sender,chat,'renamed.txt',bytes)
const concurrent=await Promise.all([publication(sender,first),publication(sender,second)])
assert.deepEqual(concurrent.slice().sort(),[false,true])
assert.deepEqual(await Promise.all([publication(sender,first),publication(sender,second)]),concurrent)
assert.equal((await publish(recipient,first)).status,404)
assert.equal(await publication(recipient,await stage(recipient,chat,'original.txt',bytes)),false)
assert.equal(await publication(sender,await stage(sender,otherChat,'original.txt',bytes)),false)
assert.equal(await publication(sender,await stage(sender,chat,'original.txt',Buffer.from(bytes.toString().replace('Matching','Changed!')))),false)
assert.ok((await recipient.client.storage.from(bucket).download(second)).error)

const copy=concurrent[0]?first:second
const original=concurrent[0]?second:first
data(await sender.client.rpc('st_v5_message_action',{p_message:original,p_action:'revoke'}))
const authorization={Authorization:'Bearer '+recipient.token}
const grant=await fetch(app+'/api/files/download',{
  method:'POST',headers:{...authorization,'Content-Type':'application/json'},body:JSON.stringify({file:copy}),
})
assert.equal(grant.status,200)
const download=await fetch(new URL((await grant.json()).url,app),{headers:authorization})
assert.equal(download.status,200)
assert.deepEqual(Buffer.from(await download.arrayBuffer()),bytes)

const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
try{
  const page=await browser.newPage({locale:'en-US'})
  await page.goto(app)
  await page.getByLabel('Email address',{exact:true}).fill(sender.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await page.locator('.chat-item').filter({hasText:'Duplicate Recipient'}).click()
  await page.locator('.composer input[type=file]').setInputFiles({name:'browser-copy.txt',mimeType:'text/plain',buffer:bytes})
  await page.getByRole('button',{name:'Send message',exact:true}).click()
  await page.getByRole('status').getByText('Attachment sent. You previously shared the same file contents in this chat.').waitFor()
  await page.getByRole('button',{name:/browser-copy\.txt/}).waitFor()
}finally{
  await browser.close()
}

console.log('Passed duplicate detection through concurrent publication, isolated uploads and the browser composer.')
