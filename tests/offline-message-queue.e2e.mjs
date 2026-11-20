// Run against the isolated loopback app and Supabase stack.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app=new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase=new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname,'127.0.0.1')
assert.equal(supabase.hostname,'127.0.0.1')
const key=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const adminKey=process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
assert.ok(key&&adminKey)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const options={auth:{persistSession:false,autoRefreshToken:false}}
const admin=createClient(supabase.href,adminKey,options)
const suffix=randomUUID().slice(0,8)
const password=randomUUID()+'1!Q'

function data(result){
  if(result.error)throw new Error(result.error.message)
  return result.data
}

async function account(prefix,label){
  const handle=prefix+'_'+suffix
  const email=handle+'@example.org'
  const {user}=data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  const client=createClient(supabase.href,key,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:label}))
  return {client,handle,email,id:user.id,label}
}

const sender=await account('offline_a','Offline Sender')
const recipient=await account('offline_b','Offline Recipient')
const chat=data(await sender.client.rpc('st_request',{p_handle:recipient.handle}))
data(await recipient.client.rpc('st_respond',{p_chat:chat,p_accept:true}))
const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
const body='Private offline text '+suffix
const failedBody='Blocked offline text '+suffix
const attempts=[]
let commitWithoutResponse=true

try{
  const page=await browser.newPage()
  await page.addInitScript(()=>{
    Object.defineProperty(navigator,'onLine',{get:()=>localStorage.getItem('sectalk-test-offline')!=='1'})
    window.deliveryStoreRows=()=>new Promise((resolve,reject)=>{
      const open=indexedDB.open('sectalk-offline-messages',1)
      open.onerror=()=>reject(open.error)
      open.onsuccess=()=>{
        const db=open.result
        const request=db.transaction('messages').objectStore('messages').getAll()
        request.onsuccess=()=>{
          resolve(request.result.map(row=>({
            id:row.id,state:row.state,owner:row.owner,body:row.body,reply:row.reply,
            ciphertext:new TextDecoder().decode(row.ciphertext),
          })))
          db.close()
        }
        request.onerror=()=>{db.close();reject(request.error)}
      }
    })
  })
  await page.route('**/rest/v1/rpc/st_send',async route=>{
    if(route.request().method()!=='POST'){await route.continue();return}
    const payload=route.request().postDataJSON()
    attempts.push(payload.p_id)
    if(payload.p_body===body&&commitWithoutResponse){
      commitWithoutResponse=false
      const response=await route.fetch()
      assert.ok(response.ok(),'The loopback server must commit the intercepted send')
      await route.abort('failed')
    }else await route.continue()
  })
  await page.goto(new URL('/#account',app).href)
  const navigation=page.getByRole('navigation',{name:'SecTalk features'})
  async function signIn(person){
    await page.getByLabel('Email address',{exact:true}).fill(person.email)
    await page.getByLabel('Password',{exact:true}).fill(password)
    await page.locator('button.submit-auth').click()
    await navigation.waitFor()
  }
  async function offline(value){
    await page.evaluate(value=>{
      localStorage.setItem('sectalk-test-offline',value?'1':'0')
      window.dispatchEvent(new Event(value?'offline':'online'))
    },value)
  }
  const openChat=person=>page.locator('.chat-item').filter({hasText:person.label}).click()
  const status=text=>page.locator('.message').filter({hasText:text})
  async function compose(text){
    await page.getByRole('textbox',{name:'Write a message',exact:true}).fill(text)
    await page.getByRole('button',{name:'Send message',exact:true}).click()
    await status(text).getByText('Queued',{exact:true}).waitFor()
  }
  async function signOut(){
    await navigation.getByRole('button',{name:'Sign out',exact:true}).click()
    await page.getByLabel('Email address',{exact:true}).waitFor()
  }

  await signIn(sender)
  await openChat(recipient)
  await offline(true)
  await compose(body)
  assert.equal(attempts.length,0)
  const [sealed]=await page.evaluate(()=>window.deliveryStoreRows())
  assert.equal(sealed.owner,sender.id)
  assert.equal(sealed.body,undefined)
  assert.equal(sealed.reply,undefined)
  assert.ok(sealed.ciphertext&&!sealed.ciphertext.includes(body))
  const extractable=await page.evaluate(owner=>new Promise((resolve,reject)=>{
    const request=indexedDB.open('sectalk-offline-messages',1)
    request.onerror=()=>reject(request.error)
    request.onsuccess=()=>{
      const db=request.result
      const read=db.transaction('keys').objectStore('keys').get(owner)
      read.onerror=()=>{db.close();reject(read.error)}
      read.onsuccess=()=>{db.close();resolve(read.result.extractable)}
    }
  }),sender.id)
  assert.equal(extractable,false)

  await page.reload()
  await navigation.waitFor()
  await openChat(recipient)
  await status(body).getByText('Queued',{exact:true}).waitFor()
  assert.equal(attempts.length,0)
  await signOut()
  await signIn(recipient)
  await openChat(sender)
  await offline(false)
  await page.getByRole('heading',{name:'Say hello',exact:true}).waitFor()
  assert.equal(await page.getByText(body,{exact:true}).count(),0)
  assert.equal(attempts.length,0)
  await offline(true)
  await signOut()
  await signIn(sender)

  // Reconnect without opening the original conversation.
  await offline(false)
  await page.waitForFunction(id=>window.deliveryStoreRows().then(rows=>rows.some(row=>row.id===id&&row.state==='retry')),sealed.id)
  await page.reload()
  await navigation.waitFor()
  await page.waitForFunction(id=>window.deliveryStoreRows().then(rows=>!rows.some(row=>row.id===id)),sealed.id)
  assert.deepEqual(attempts,[sealed.id,sealed.id])
  const sent=data(await sender.client.from('st_messages').select('id').eq('chat_id',chat).eq('body',body))
  assert.deepEqual(sent,[{id:sealed.id}])

  await openChat(recipient)
  await offline(true)
  await compose(failedBody)
  data(await recipient.client.rpc('st_set_block',{p_chat:chat,p_block:true}))
  await offline(false)
  await status(failedBody).getByText('Failed to send',{exact:true}).waitFor()
  assert.equal(attempts.length,3)
  await page.reload()
  await navigation.waitFor()
  await openChat(recipient)
  await status(failedBody).getByText('Failed to send',{exact:true}).waitFor()
  assert.equal(attempts.length,3)
  data(await recipient.client.rpc('st_set_block',{p_chat:chat,p_block:false}))
  await status(failedBody).getByRole('button',{name:'Retry message',exact:true}).click()
  await status(failedBody).getByText('Sent',{exact:true}).waitFor()
  assert.equal(attempts.length,4)
  assert.equal(attempts[3],attempts[2])

  await page.waitForFunction(()=>window.deliveryStoreRows().then(rows=>rows.length===0))
  await offline(true)
  await compose('Synthetic damaged queue '+suffix)
  const [damaged]=await page.evaluate(()=>window.deliveryStoreRows())
  await page.evaluate(({id,owner})=>new Promise((resolve,reject)=>{
    const request=indexedDB.open('sectalk-offline-messages',1)
    request.onerror=()=>reject(request.error)
    request.onsuccess=()=>{
      const db=request.result
      const tx=db.transaction('messages','readwrite')
      const table=tx.objectStore('messages')
      const read=table.get([owner,id])
      read.onsuccess=()=>{
        const bytes=new Uint8Array(read.result.ciphertext)
        bytes[0]^=1
        table.put({...read.result,ciphertext:bytes.buffer})
      }
      tx.oncomplete=()=>{db.close();resolve()}
      tx.onerror=()=>{db.close();reject(tx.error)}
    }
  }),damaged)
  const healthy='Queue after damage '+suffix
  await compose(healthy)
  await page.reload()
  await navigation.waitFor()
  await openChat(recipient)
  await status('Encrypted message unavailable').getByText('Could not recover',{exact:true}).waitFor()
  await offline(false)
  await status(healthy).getByText('Sent',{exact:true}).waitFor()
  assert.equal(attempts.includes(damaged.id),false)
  assert.ok((await page.evaluate(()=>window.deliveryStoreRows())).some(row=>row.id===damaged.id))

  const parent=randomUUID()
  const parentBody='Offline quote source '+suffix
  const replyBody='Offline quote reply '+suffix
  data(await recipient.client.rpc('st_send',{p_chat:chat,p_id:parent,p_body:parentBody}))
  await status(parentBody).locator('summary[aria-label="Message actions"]').click()
  await status(parentBody).getByRole('button',{name:'Reply',exact:true}).click()
  await offline(true)
  await compose(replyBody)
  await page.reload()
  await navigation.waitFor()
  await openChat(recipient)
  await status(replyBody).getByText('Queued',{exact:true}).waitFor()
  await offline(false)
  await status(replyBody).getByText('Sent',{exact:true}).waitFor()
  const reply=data(await sender.client.from('st_messages').select('reply_to').eq('chat_id',chat).eq('body',replyBody).single())
  assert.equal(reply.reply_to,parent)
  console.log('Passed encrypted queue persistence, account isolation, reconnect and reply replay, deduplication, terminal recovery and damaged-entry isolation.')
}finally{
  await browser.close()
}
