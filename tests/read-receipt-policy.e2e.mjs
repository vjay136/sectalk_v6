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

function data(result){
  if(result.error)throw new Error(result.error.message)
  return result.data
}

async function account(label){
  const handle=label.toLowerCase()+'_'+suffix
  const email=handle+'@example.org'
  data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  const client=createClient(supabase.href,key,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:label}))
  return {client,email,handle,label}
}

const [author,reader]=await Promise.all([account('ReceiptAuthor'),account('ReceiptReader')])
const chat=data(await author.client.rpc('st_request',{p_handle:reader.handle}))
data(await reader.client.rpc('st_respond',{p_chat:chat,p_accept:true}))
const workspace=data(await author.client.rpc('st_v2_create_workspace',{p_name:'Receipt workspace '+suffix}))
data(await author.client.rpc('st_v2_invite',{p_workspace:workspace,p_handle:reader.handle}))
const invitation=data(await reader.client.from('st_v2_invites').select('id').eq('workspace_id',workspace).single())
data(await reader.client.rpc('st_v2_reply_invite',{p_invite:invitation.id,p_accept:true}))
const room=randomUUID()
const roomName='Receipt room '+suffix
data(await author.client.rpc('st_v6_room_create',{p_id:room,p_workspace:workspace,p_name:roomName,p_kind:'public',p_template:'blank'}))
data(await reader.client.rpc('st_v6_room_membership',{p_room:room,p_action:'join'}))

const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
const button=(root,name)=>root.getByRole('button',{name,exact:true})

async function open(person,other){
  const page=await browser.newPage()
  await page.goto(new URL('/#account',app).href)
  await page.getByLabel('Email address',{exact:true}).fill(person.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation',{name:'SecTalk features'}).waitFor()
  await page.locator('.chat-item').filter({hasText:other.label}).click()
  return page
}

try{
  const [authorPage,readerPage]=await Promise.all([open(author,reader),open(reader,author)])
  const share=readerPage.getByRole('button',{name:'Share my read receipts',exact:true})
  await readerPage.getByRole('button',{name:'Share my read receipts',exact:true,pressed:true}).click()
  await readerPage.getByRole('button',{name:'Share my read receipts',exact:true,pressed:false}).waitFor()

  const privateText='Private direct view '+suffix
  await authorPage.getByRole('textbox',{name:'Write a message',exact:true}).fill(privateText)
  await button(authorPage,'Send message').click()
  await readerPage.getByText(privateText,{exact:true}).waitFor()
  const privateMessage=authorPage.locator('.message').filter({hasText:privateText})
  await privateMessage.getByText('Delivered',{exact:true}).waitFor()
  assert.equal(await privateMessage.getByText('Read',{exact:true}).count(),0)

  await share.click()
  await readerPage.getByRole('button',{name:'Share my read receipts',exact:true,pressed:true}).waitFor()
  const sharedText='Shared direct view '+suffix
  await authorPage.getByRole('textbox',{name:'Write a message',exact:true}).fill(sharedText)
  await button(authorPage,'Send message').click()
  await authorPage.locator('.message').filter({hasText:sharedText}).getByText('Read',{exact:true}).waitFor()
  assert.equal(await privateMessage.getByText('Delivered',{exact:true}).count(),1)

  const openRoom=async page=>{
    await button(page.getByRole('navigation',{name:'SecTalk features'}),'Rooms').click()
    const directory=page.getByRole('region',{name:'Room directory',exact:true})
    await directory.getByRole('button',{name:new RegExp(roomName)}).click()
    return directory.getByRole('region',{name:roomName,exact:true})
  }
  const [authorRoom,readerRoom]=await Promise.all([openRoom(authorPage),openRoom(readerPage)])
  const readerToggle=readerRoom.getByRole('button',{name:'Share my read receipts',exact:true,pressed:true})
  await readerToggle.waitFor()
  await authorRoom.getByRole('textbox',{name:'Write a room message',exact:true}).fill('First room receipt')
  await button(authorRoom,'Send').click()
  const firstPost=panel=>panel.locator('article').filter({hasText:'First room receipt'})
  await firstPost(readerRoom).scrollIntoViewIfNeeded()
  const count=panel=>firstPost(panel).getByText('Read by 1',{exact:true})
  await count(authorRoom).waitFor()
  assert.equal(await count(readerRoom).count(),0)

  await button(authorRoom,'Settings').click()
  const roomToggle=authorRoom.getByRole('button',{name:'Allow read receipts in this room',exact:true})
  await roomToggle.click()
  await authorRoom.getByRole('button',{name:'Allow read receipts in this room',exact:true,pressed:false}).waitFor()
  await button(authorRoom,'Messages').click()
  assert.equal(await count(authorRoom).count(),0)
  await button(authorRoom,'Settings').click()
  await roomToggle.click()
  await authorRoom.getByRole('button',{name:'Allow read receipts in this room',exact:true,pressed:true}).waitFor()

  const ownerDirectory=authorPage.getByRole('region',{name:'Room directory',exact:true})
  await ownerDirectory.getByText('Workspace read receipts',{exact:true}).click()
  await button(ownerDirectory,'Allow read receipts in workspace rooms').click()
  await ownerDirectory.getByRole('button',{name:'Allow read receipts in workspace rooms',exact:true,pressed:false}).waitFor()
  await authorRoom.getByText('Workspace policy disables read receipts.',{exact:true}).waitFor()
  assert.equal(await readerPage.getByText('Workspace read receipts',{exact:true}).count(),0)
  console.log('Passed personal direct receipts, continued delivery, author-only room counts, and workspace and room controls.')
}finally{
  await browser.close()
}
