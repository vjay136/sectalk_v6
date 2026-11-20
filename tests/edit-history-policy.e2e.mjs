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
  result(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  const client=createClient(supabase.href,key,options)
  result(await client.auth.signInWithPassword({email,password}))
  result(await client.rpc('st_save_profile',{p_handle:handle,p_name:label}))
  return {client,email,handle,label}
}

const sender=await account('edits_a','Edit Sender')
const recipient=await account('edits_b','Edit Recipient')
const chat=result(await sender.client.rpc('st_request',{p_handle:recipient.handle}))
result(await recipient.client.rpc('st_respond',{p_chat:chat,p_accept:true}))
const subject=randomUUID()
const expired=randomUUID()
const original='Original revision '+suffix
const replacement='Revised message '+suffix
const oldBody='Older than one day '+suffix
result(await sender.client.rpc('st_send',{p_chat:chat,p_id:subject,p_body:original}))
result(await sender.client.rpc('st_send',{p_chat:chat,p_id:expired,p_body:oldBody}))
result(await admin.from('st_messages').update({created_at:new Date(Date.now()-86460_000).toISOString()}).eq('id',expired))

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

const card=(page,body)=>page.locator('.message').filter({hasText:body})
const openMenu=card=>card.getByLabel('Message actions',{exact:true}).click()
const editButton=card=>card.getByRole('button',{name:'Edit message',exact:true})
const historyButton=card=>card.getByRole('button',{name:'View edit history',exact:true})
async function selectAudience(page,audience){
  await page.getByRole('button',{name:'Edit history settings',exact:true}).click()
  const dialog=page.getByRole('dialog',{name:'Edit history settings',exact:true})
  await dialog.getByRole('combobox',{name:/Who can see my edit history/}).selectOption(audience)
  await dialog.getByRole('button',{name:'Save history setting',exact:true}).click()
  await dialog.waitFor({state:'hidden'})
}

try{
  const first=await open(sender,recipient)
  const second=await open(recipient,sender)
  const past=card(first,oldBody)
  await openMenu(past)
  assert.equal(await editButton(past).count(),0)
  await openMenu(past)
  const editable=card(first,original)
  await openMenu(editable)
  await editButton(editable).click()
  const edit=first.getByRole('dialog',{name:'Edit message',exact:true})
  await edit.getByRole('textbox',{name:'Message',exact:true}).fill(replacement)
  await edit.getByRole('button',{name:'Save changes',exact:true}).click()
  await edit.waitFor({state:'hidden'})

  const peer=card(second,replacement)
  const peerHistory=second.getByRole('dialog',{name:'Edit history',exact:true})
  await historyButton(peer).click()
  await peerHistory.getByText(original,{exact:true}).waitFor()
  await selectAudience(first,'private')
  await peerHistory.waitFor({state:'hidden'})
  await peer.getByText('Edited',{exact:true}).waitFor()
  assert.equal(await historyButton(peer).count(),0)
  assert.deepEqual(result(await recipient.client.from('st_v2_message_edits').select('body').eq('message_id',subject)),[])

  await historyButton(card(first,replacement)).click()
  const ownHistory=first.getByRole('dialog',{name:'Edit history',exact:true})
  await ownHistory.getByText(original,{exact:true}).waitFor()
  await ownHistory.getByRole('button',{name:'Close dialog',exact:true}).click()
  await selectAudience(first,'shared')
  await historyButton(peer).click()
  await peerHistory.getByText(original,{exact:true}).waitFor()
  result(await sender.client.rpc('st_v5_message_action',{p_message:subject,p_action:'revoke'}))
  await peerHistory.waitFor({state:'hidden'})
  await second.getByText('Message removed',{exact:true}).waitFor()
  assert.equal(await second.getByText(original,{exact:true}).count(),0)
  assert.equal(await second.getByText(replacement,{exact:true}).count(),0)
  console.log('Passed edit window, live edited marker, per-author history audiences, raw denial, and revocation in two browsers.')
}finally{
  await browser.close()
}
