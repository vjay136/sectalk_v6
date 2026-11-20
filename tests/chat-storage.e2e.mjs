// Run with the Supabase CLI local stack, the app migrations and loopback-only API keys.
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const url = process.env.SECTALK_STORAGE_TEST_URL
assert.equal(new URL(url).hostname, '127.0.0.1')
const options = { auth:{persistSession:false, autoRefreshToken:false} }
const key = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const service = process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
assert.ok(key && service)
const admin = createClient(url, service, options)
const password = randomUUID() + '1!Q'
const suffix = randomUUID().slice(0, 8)

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

async function signIn(prefix) {
  const handle = prefix + '_' + suffix
  const email = handle + '@example.org'
  data(await admin.auth.admin.createUser({ email,password,email_confirm:true }))
  const client = createClient(url,key,options)
  const auth = data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:prefix}))
  return {client,user:auth.user.id,handle,email}
}

const sender=await signIn('Sender')
const recipient=await signIn('Receiver')
const outsider=await signIn('Outside')
const chat=data(await sender.client.rpc('st_request',{p_handle:recipient.handle}))
data(await recipient.client.rpc('st_respond',{p_chat:chat,p_accept:true}))

const file=randomUUID()
const raw=new TextEncoder().encode('An isolated attachment integration test.')
const bucket='sectalk-chat-files'
const storage=client=>client.storage.from(bucket)
assert.equal(data(await sender.client.rpc('st_v5_stage_file',{
  p_chat:chat,p_id:file,p_filename:'fixture.txt',p_bytes:raw.length,
})), false)
data(await storage(sender.client).upload(file,raw.buffer,{contentType:'application/octet-stream',upsert:false}))
assert.ok((await storage(recipient.client).download(file)).error, 'Pending file must stay private')
assert.equal(data(await sender.client.rpc('st_v5_send_file',{p_id:file,p_caption:'Example attachment'})), file)
assert.equal(await data(await storage(recipient.client).download(file)).text(), new TextDecoder().decode(raw))
assert.ok((await storage(outsider.client).download(file)).error, 'An unrelated account must not download a file')
data(await sender.client.rpc('st_v5_message_action',{p_message:file,p_action:'revoke'}))
assert.ok((await storage(recipient.client).download(file)).error, 'A new download must fail after revoke')

const avatarPath=sender.user+'.jpg'
const photo=new Uint8Array([255,216,255,217]).buffer
data(await sender.client.storage.from('sectalk-avatars').upload(avatarPath,photo,{contentType:'image/jpeg',upsert:true}))
assert.ok((await outsider.client.storage.from('sectalk-avatars').download(avatarPath)).error, 'An unrelated account must not see a photo')
data(await recipient.client.storage.from('sectalk-avatars').download(avatarPath))

const app=process.env.SECTALK_STORAGE_TEST_APP
if(app) {
  assert.equal(new URL(app).hostname,'127.0.0.1')
  const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
  const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  async function openChat(account,peerName) {
    const page=await browser.newPage()
    await page.goto(app)
    await page.getByLabel('Email address',{exact:true}).fill(account.email)
    await page.getByLabel('Password',{exact:true}).fill(password)
    await page.locator('button.submit-auth').click()
    await page.locator('.chat-item').filter({hasText:peerName}).click()
    return page
  }
  try{
    const first=await openChat(sender,'Receiver')
    const second=await openChat(recipient,'Sender')
    await first.getByLabel('Write a message').fill('Emoji reaction integration')
    await first.getByRole('button',{name:'Send message',exact:true}).click()
    const sample='.message'
    const message=second.locator(sample).filter({hasText:'Emoji reaction integration'})
    await message.getByRole('button',{name:'Add reaction',exact:true}).click()
    await second.getByRole('button',{name:'SecTalk combinations',exact:true}).click()
    await second.locator('.emoji-choice').first().click()
    await first.locator(sample).filter({hasText:'Emoji reaction integration'}).locator('.reaction-row .custom-emoji').waitFor()
    await message.locator('.reaction-row button[aria-pressed=true]').click()
    await first.locator(sample).filter({hasText:'Emoji reaction integration'}).locator('.reaction-row .custom-emoji').waitFor({state:'detached'})
    if(process.env.SECTALK_TEST_V6==='1') {
      const sampleMessage=first.locator(sample).filter({hasText:'Emoji reaction integration'})
      await sampleMessage.locator('summary[aria-label="Message actions"]').click()
      await sampleMessage.getByRole('button',{name:'Save message',exact:true}).click()
      await first.getByText('Message saved. Find it in Inbox → Saved messages.').waitFor()
      const savedResponse=first.waitForResponse(response=>response.request().method()==='GET'&&response.url().includes('/rest/v1/st_v6_saved_messages'))
      await first.getByRole('button',{name:'Saved messages',exact:true}).click()
      const savedList=await savedResponse
      assert.equal(savedList.status(),200,'Saved-message API did not return HTTP 200')
      const savedRows=await savedList.json()
      assert.ok(savedList.ok(),JSON.stringify(savedRows))
      assert.ok(savedRows.some(row=>row.message?.body==='Emoji reaction integration'),'Saved message was not returned by the API')
      await first.getByRole('heading',{name:'Saved messages'}).waitFor()
      await first.getByText('Emoji reaction integration',{exact:true}).waitFor()
      await first.getByRole('button',{name:'Remove from saved'}).click()
      await first.getByText('Use a message’s action menu to save it here.').waitFor()

      const libraryFile=randomUUID()
      data(await sender.client.rpc('st_v5_stage_file',{
        p_chat:chat,p_id:libraryFile,p_filename:'library-test.txt',p_bytes:raw.length,
      }))
      data(await storage(sender.client).upload(libraryFile,raw.buffer,{contentType:'application/octet-stream'}))
      data(await sender.client.rpc('st_v5_send_file',{p_id:libraryFile,p_caption:'Library test message'}))
      await second.getByRole('button',{name:'Files',exact:true}).click()
      await second.getByRole('heading',{name:'Files',exact:true}).waitFor()
      await second.getByLabel('Direction').selectOption('received')
      const files=second.getByRole('region',{name:'Chat files'})
      await files.getByRole('searchbox',{name:'Filename',exact:true}).fill('library-test')
      await files.getByRole('button',{name:'Search',exact:true}).click()
      await files.getByRole('checkbox',{name:'library-test.txt'}).check()
      const downloaded=second.waitForEvent('download')
      await second.getByRole('button',{name:/Download selected/}).click()
      const zip=await downloaded
      assert.equal(zip.suggestedFilename(),'sectalk-files.zip')
      const {unzipSync}=await import('fflate')
      const entries=unzipSync(await readFile(await zip.path()))
      assert.deepEqual(Object.keys(entries),['01-library-test.txt'])
      assert.equal(new TextDecoder().decode(entries['01-library-test.txt']),new TextDecoder().decode(raw))
      console.log('Passed saved-message creation and removal, file filters, and authorized ZIP download.')
      await first.getByRole('button',{name:'Inbox',exact:true}).click()
    }
    await first.getByRole('button',{name:'Find Friends',exact:true}).first().click()
    await first.getByRole('heading',{name:'Find Friends',exact:true}).waitFor()
    console.log('Passed two-browser chat, custom reaction synchronization, reaction removal, and Find Friends navigation.')
  }finally{await browser.close()}
}

data(await recipient.client.rpc('st_set_block',{p_chat:chat,p_block:true}))
assert.ok((await recipient.client.storage.from('sectalk-avatars').download(avatarPath)).error, 'Blocking must stop profile photo access')
data(await sender.client.storage.from('sectalk-avatars').remove([avatarPath]))
console.log('Passed real storage upload, authorized download, revoke, profile storage, and blocking.')
