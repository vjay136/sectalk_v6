import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app=new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase=new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname,'127.0.0.1')
assert.equal(supabase.origin,'http://127.0.0.1:55321')
const options={auth:{persistSession:false,autoRefreshToken:false}}
const admin=createClient(supabase.origin,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const password=randomUUID()+'1!Q'
const suffix=randomUUID().slice(0,8)

function data(result){
  if(result.error)throw new Error(result.error.message)
  return result.data
}
async function account(stem){
  const handle=stem+'_'+suffix
  const email=handle+'@example.org'
  const {user}=data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  const client=createClient(supabase.origin,process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:stem}))
  return {id:user.id,email,client,handle,stem}
}
const [author,peer]=await Promise.all([account('DraftAuthor'),account('DraftPeer')])
const chat=data(await author.client.rpc('st_request',{p_handle:peer.handle}))
data(await peer.client.rpc('st_respond',{p_chat:chat,p_accept:true}))
const workspace=data(await author.client.rpc('st_v2_create_workspace',{p_name:'Draft workspace '+suffix}))
const room=randomUUID()
const roomName='Draft room '+suffix
data(await author.client.rpc('st_v6_room_create',{p_id:room,p_workspace:workspace,p_name:roomName,p_kind:'public',p_template:'blank'}))

const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
try{
  const nav=page=>page.getByRole('navigation',{name:'SecTalk features'})
  const chatInput=page=>page.getByRole('textbox',{name:'Write a message',exact:true})
  const selectContact=page=>page.locator('.chat-item').filter({hasText:peer.stem}).click()
  const saved=page=>page.getByText('Draft saved to your devices.',{exact:true})
  async function open(){
    const page=await browser.newPage()
    await page.goto(new URL('/#account',app).href)
    await page.getByLabel('Email address',{exact:true}).fill(author.email)
    await page.getByLabel('Password',{exact:true}).fill(password)
    await page.locator('button.submit-auth').click()
    await nav(page).waitFor()
    await selectContact(page)
    return page
  }
  const [first,second]=await Promise.all([open(),open()])
  const awaitValue=(page,selector,value,timeout=7000)=>page.waitForFunction(
    ([selector,value])=>document.querySelector(selector)?.value===value,[selector,value],{timeout})
  const directSelector='textarea[aria-label="Write a message"]'
  await chatInput(first).fill('Private draft across devices')
  await saved(first).waitFor()
  await awaitValue(second,directSelector,'Private draft across devices')
  const peerView=data(await peer.client.rpc('st_v6_read_draft',{p_actor:peer.id,p_scope:'chat',p_conversation:chat,p_parent:null}))
  assert.deepEqual(peerView,{revision:0,body:''})
  await second.reload()
  await selectContact(second)
  await awaitValue(second,directSelector,'Private draft across devices')

  let release
  let arrived
  const held=new Promise(resolve=>{release=resolve})
  const arrivedPromise=new Promise(resolve=>{arrived=resolve})
  await first.route('**/rpc/st_v6_save_draft',async route=>{
    if(route.request().postDataJSON().p_body==='First device conflicting edit'){
      arrived()
      await held
    }
    await route.continue()
  })
  try{
    await chatInput(first).fill('First device conflicting edit')
    await arrivedPromise
    await chatInput(second).fill('Updated from the other device')
    await saved(second).waitFor()
  }finally{release()}
  await first.getByText('Your draft changed on another device.',{exact:true}).waitFor()
  await first.getByRole('button',{name:'Use synced draft',exact:true}).click()
  assert.equal(await chatInput(first).inputValue(),'Updated from the other device')
  await first.getByRole('button',{name:'Send message',exact:true}).click()
  await awaitValue(second,directSelector,'')
  await second.getByText('Updated from the other device',{exact:true}).waitFor()

  for(const page of [first,second]){
    await nav(page).getByRole('button',{name:'Rooms',exact:true}).click()
    await page.getByRole('button',{name:new RegExp(roomName)}).click()
    await page.getByLabel('Write a room message',{exact:true}).waitFor()
  }
  await first.getByLabel('Write a room message',{exact:true}).fill('Private room draft')
  await saved(first).waitFor()
  await awaitValue(second,'textarea[name="body"]','Private room draft')
  await first.getByRole('button',{name:'Send',exact:true}).click()
  await awaitValue(second,'textarea[name="body"]','')
  await second.getByText('Private room draft',{exact:true}).waitFor()
  console.log('Passed two-device private draft sync, reload, concurrent edits, send clearing and room composer.')
}finally{
  await browser.close()
}
