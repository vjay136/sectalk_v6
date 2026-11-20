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
const app=process.env.SECTALK_STORAGE_TEST_APP
const v6=process.env.SECTALK_TEST_V6==='1'
const storage=client=>client.storage.from(bucket)
let recipientLink
async function grant(client,id){
  assert.equal(new URL(app).hostname,'127.0.0.1')
  const session=data(await client.auth.getSession()).session
  const authorization={Authorization:'Bearer '+session.access_token}
  return fetch(app+'/api/files/download',{method:'POST',
    headers:{...authorization,'Content-Type':'application/json'},body:JSON.stringify({file:id})})
}
async function retrieve(client,link){
  const session=data(await client.auth.getSession()).session
  return fetch(new URL(link,app),{headers:{Authorization:'Bearer '+session.access_token}})
}
async function publish(client,id,caption,mime){
  if(!v6)return data(await client.rpc('st_v5_send_file',{p_id:id,p_caption:caption}))
  const session=data(await client.auth.getSession()).session
  const response=await fetch(app+'/api/files/publish',{method:'POST',
    headers:{Authorization:'Bearer '+session.access_token,'Content-Type':'application/json'},
    body:JSON.stringify({file:id,caption,mime})})
  const body=await response.json()
  assert.equal(response.status,200,body.error)
  return body.id
}
assert.equal(data(await sender.client.rpc('st_v5_stage_file',{
  p_chat:chat,p_id:file,p_filename:'fixture.txt',p_bytes:raw.length,
})), false)
data(await storage(sender.client).upload(file,raw.buffer,{contentType:'application/octet-stream',upsert:false}))
assert.ok((await storage(recipient.client).download(file)).error, 'Pending file must stay private')
assert.equal(await publish(sender.client,file,'Example attachment','text/plain'),file)
if(v6){
  const renamed=randomUUID()
  data(await sender.client.rpc('st_v5_stage_file',{p_chat:chat,p_id:renamed,p_filename:'spoof.jpg',p_bytes:raw.length}))
  data(await storage(sender.client).upload(renamed,raw.buffer,{contentType:'application/octet-stream'}))
  const session=data(await sender.client.auth.getSession()).session
  const rejected=await fetch(app+'/api/files/publish',{method:'POST',
    headers:{Authorization:'Bearer '+session.access_token,'Content-Type':'application/json'},
    body:JSON.stringify({file:renamed,caption:'Spoofed image',mime:'image/jpeg'})})
  assert.equal(rejected.status,415)
  assert.ok((await sender.client.rpc('st_v5_send_file',{p_id:renamed,p_caption:'Bypass'})).error)
  assert.equal(data(await sender.client.from('st_messages').select('id').eq('id',renamed).maybeSingle()),null)
  console.log('Passed server file-type validation and raw publication bypass denial.')
  assert.ok((await storage(recipient.client).download(file)).error,'Direct Storage must not bypass the download log')
  const granted=await grant(recipient.client,file)
  assert.equal(granted.status,200)
  assert.match(granted.headers.get('cache-control'),/no-store/)
  const result=await granted.json()
  assert.equal(result.expiresIn,30)
  recipientLink=result.url
  assert.equal((await grant(outsider.client,file)).status,404)
  assert.equal((await retrieve(outsider.client,recipientLink)).status,404)
  const received=await retrieve(recipient.client,recipientLink)
  assert.equal(received.status,200)
  assert.equal(await received.text(),new TextDecoder().decode(raw))
  assert.ok((await recipient.client.rpc('st_v6_log_file_download',{p_file:file,p_actor:recipient.user,p_ticket:randomUUID()})).error)
}else{
  assert.equal(await data(await storage(recipient.client).download(file)).text(), new TextDecoder().decode(raw))
}
assert.ok((await storage(outsider.client).download(file)).error, 'An unrelated account must not download a file')
data(await sender.client.rpc('st_v5_message_action',{p_message:file,p_action:'revoke'}))
assert.ok((await storage(recipient.client).download(file)).error, 'A new download must fail after revoke')
if(v6){
  assert.equal((await retrieve(recipient.client,recipientLink)).status,404)
  assert.equal((await grant(recipient.client,file)).status,404)
  console.log('Passed signed attachment links, retrieval authorization and revoke.')
}

const avatarPath=sender.user+'.jpg'
const photo=new Uint8Array([255,216,255,217]).buffer
data(await sender.client.storage.from('sectalk-avatars').upload(avatarPath,photo,{contentType:'image/jpeg',upsert:true}))
assert.ok((await outsider.client.storage.from('sectalk-avatars').download(avatarPath)).error, 'An unrelated account must not see a photo')
data(await recipient.client.storage.from('sectalk-avatars').download(avatarPath))

if(app) {
  assert.equal(new URL(app).hostname,'127.0.0.1')
  const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
  const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER,args:[
    '--use-fake-device-for-media-stream','--use-fake-ui-for-media-stream',
  ]})
  async function openChat(account,peerName) {
    const page=await browser.newPage({locale:'en-US'})
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
      await message.locator('summary[aria-label="Message actions"]').click()
      await message.getByRole('button',{name:'Pin message',exact:true}).click()
      await first.locator('.thread-pin').getByText('Emoji reaction integration',{exact:true}).waitFor()
      await first.locator('.thread-pin').getByRole('button',{name:'Unpin',exact:true}).click()
      await second.locator('.thread-pin').getByText('Emoji reaction integration',{exact:true}).waitFor({state:'detached'})
      console.log('Passed live pin and unpin across two direct-chat participants.')
      const riskMessage=randomUUID()
      data(await sender.client.rpc('st_send',{p_chat:chat,p_id:riskMessage,p_body:'Please share your verification code.'}))
      const warning=second.getByRole('complementary',{name:'Message safety warning',exact:true})
      await warning.getByText('Possible safety concern',{exact:true}).waitFor()
      await warning.getByText(/may ask for an account code/).waitFor()
      await warning.getByRole('button',{name:'Report from safety warning',exact:true}).click()
      const report=second.getByRole('dialog',{name:'Report this message',exact:true})
      await report.getByText('Please share your verification code.',{exact:true}).waitFor()
      await report.getByRole('button',{name:'Close dialog',exact:true}).click()
      await warning.getByRole('button',{name:'Dismiss warning',exact:true}).click()
      await warning.waitFor({state:'detached'})
      data(await sender.client.rpc('st_v2_edit_message',{p_message:riskMessage,p_body:'Please send your account password.'}))
      await warning.getByText(/may ask for an account code/).waitFor()
      await warning.getByRole('button',{name:'Dismiss warning',exact:true}).click()
      console.log('Passed explanatory safety warnings, contextual report review, dismissal and reset on edit.')
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

      await first.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Inbox',exact:true}).click()
      await first.locator('.composer input[type=file]').setInputFiles({
        name:'composer-approved.txt',mimeType:'text/plain',buffer:Buffer.from(raw),
      })
      await first.getByRole('button',{name:'Send message',exact:true}).click()
      await second.getByRole('button',{name:/composer-approved\.txt/}).waitFor()
      const composerAttachment=data(await sender.client.from('st_v5_files').select('id').eq('chat_id',chat)
        .eq('filename','composer-approved.txt').single())
      data(await sender.client.rpc('st_v5_message_action',{p_message:composerAttachment.id,p_action:'revoke'}))
      console.log('Passed validated attachment publication from the chat composer.')

      const libraryFile=randomUUID()
      data(await sender.client.rpc('st_v5_stage_file',{
        p_chat:chat,p_id:libraryFile,p_filename:'library-test.txt',p_bytes:raw.length,
      }))
      data(await storage(sender.client).upload(libraryFile,raw.buffer,{contentType:'application/octet-stream'}))
      await publish(sender.client,libraryFile,'Library test message','text/plain')
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

      await first.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Search',exact:true}).click()
      await first.getByLabel('Search terms').fill('Emoji reaction integration')
      await first.getByRole('button',{name:'Save search',exact:true}).click()
      await first.getByText('Search saved.',{exact:true}).waitFor()
      await first.getByRole('button',{name:'Saved searches',exact:true}).click()
      await first.getByRole('button',{name:'Run search',exact:true}).click()
      await first.locator('article').getByText('Emoji reaction integration',{exact:true}).waitFor()
      await first.getByRole('button',{name:'Saved searches',exact:true}).click()
      await first.getByRole('button',{name:'Remove',exact:true}).click()
      await first.getByText('No saved searches yet.',{exact:true}).waitFor()

      const palette=first.getByRole('dialog',{name:'Command palette'})
      const paletteInput=palette.getByRole('textbox',{name:'Find commands or search SecTalk'})
      const openPalette=first.getByRole('button',{name:'Open command palette',exact:true})
      await openPalette.click()
      await paletteInput.waitFor()
      assert.equal(await paletteInput.evaluate(input=>document.activeElement===input),true)
      await first.keyboard.press('Escape')
      await palette.waitFor({state:'hidden'})
      assert.equal(await openPalette.evaluate(button=>document.activeElement===button),true)

      await first.keyboard.press('Control+k')
      await paletteInput.fill('bookmarks')
      await first.keyboard.press('ArrowDown')
      await first.keyboard.press('ArrowDown')
      await first.keyboard.press('Enter')
      await first.getByRole('heading',{name:'Saved messages',exact:true}).waitFor()
      const searchMessage=randomUUID()
      data(await sender.client.rpc('st_send',{p_chat:chat,p_id:searchMessage,p_body:'x'.repeat(240)+' [SecTalk-QA] <b>plain text</b>'}))
      await first.keyboard.press('Meta+k')
      await paletteInput.fill('[sectalk-qa]')
      await paletteInput.press('Enter')
      const snippet=first.locator('article').filter({hasText:'[SecTalk-QA]'})
      await snippet.locator('mark').getByText('[SecTalk-QA]',{exact:true}).waitFor()
      assert.match(await snippet.innerText(),/<b>plain text<\/b>/)
      assert.equal(await snippet.locator('b').count(),0)
      await second.keyboard.press('Control+k')
      await second.getByRole('dialog',{name:'Command palette'}).getByRole('button',{name:'Go to Calls',exact:true}).click()
      await second.getByRole('heading',{name:'Calls',exact:true}).waitFor()
      data(await sender.client.rpc('st_v5_message_action',{p_message:searchMessage,p_action:'revoke'}))
      await first.getByText('No matching items.',{exact:true}).waitFor()
      console.log('Passed command palette keyboard navigation, focus restoration, saved-message action, authorized search, literal highlighting and revocation.')

      await first.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Inbox',exact:true}).click()
      await second.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Inbox',exact:true}).click()
      const scheduleDialog=page=>page.getByRole('dialog',{name:'Scheduled messages',exact:true})
      async function scheduleDraft(body){
        await first.getByRole('textbox',{name:'Write a message',exact:true}).fill(body)
        await first.getByRole('button',{name:'Scheduled messages',exact:true}).click()
        const date=new Date(Date.now()+180_000)
        const localTime=new Date(date.getTime()-date.getTimezoneOffset()*60_000).toISOString().slice(0,16)
        await scheduleDialog(first).getByLabel('Send date and time',{exact:true}).fill(localTime)
        await scheduleDialog(first).getByRole('button',{name:'Schedule message',exact:true}).click()
        await scheduleDialog(first).getByText('Message scheduled.',{exact:true}).waitFor()
        await scheduleDialog(first).getByText(body,{exact:true}).waitFor()
      }
      await scheduleDraft('Browser scheduled delivery')
      await second.getByRole('button',{name:'Scheduled messages',exact:true}).click()
      await scheduleDialog(second).getByText('No messages are scheduled.',{exact:true}).waitFor()
      await scheduleDialog(second).getByRole('button',{name:'Close dialog',exact:true}).click()
      assert.equal(await second.getByText('Browser scheduled delivery',{exact:true}).count(),0)
      await scheduleDialog(first).getByRole('button',{name:'Close dialog',exact:true}).click()
      await scheduleDraft('Browser cancelled schedule')
      const cancelled=scheduleDialog(first).locator('article').filter({hasText:'Browser cancelled schedule'})
      await cancelled.getByRole('button',{name:'Cancel schedule',exact:true}).click()
      await scheduleDialog(first).getByText('Scheduled message cancelled.',{exact:true}).waitFor()
      await scheduleDialog(first).getByRole('button',{name:'History',exact:true}).click()
      await scheduleDialog(first).getByText('Cancelled',{exact:true}).waitFor()
      // Advance the one synthetic row, then let the real local scheduler deliver it.
      data(await admin.from('st_v6_scheduled_messages').update({send_at:new Date(Date.now()-1000).toISOString()})
        .eq('chat_id',chat).eq('body','Browser scheduled delivery'))
      await second.getByRole('log',{name:'Messages'}).getByText('Browser scheduled delivery',{exact:true}).waitFor({timeout:75000})
      await scheduleDialog(first).getByText('Sent',{exact:true}).waitFor()
      await scheduleDialog(first).getByRole('button',{name:'Close dialog',exact:true}).click()
      assert.equal(await second.getByText('Browser cancelled schedule',{exact:true}).count(),0)
      console.log('Passed private scheduling, cancellation, cron delivery and live status in two browsers.')

      const originalQuote=randomUUID()
      data(await sender.client.rpc('st_send',{p_chat:chat,p_id:originalQuote,p_body:'Browser quoted original'}))
      const quotedSource=second.locator('.message').filter({has:second.locator('.bubble').getByText('Browser quoted original',{exact:true})})
      await quotedSource.locator('summary[aria-label="Message actions"]').click()
      await quotedSource.getByRole('button',{name:'Reply',exact:true}).click()
      const replyBox=second.getByRole('textbox',{name:'Write a message',exact:true})
      await replyBox.fill('Browser reply body')
      await replyBox.press('Enter')
      const reply=first.locator('.message').filter({has:first.locator('.bubble').getByText('Browser reply body',{exact:true})})
      await reply.locator('blockquote').filter({hasText:'Browser quoted original'}).waitFor()
      data(await sender.client.rpc('st_v5_message_action',{p_message:originalQuote,p_action:'revoke'}))
      await reply.locator('blockquote').filter({hasText:'Original message unavailable'}).waitFor()
      await second.locator('.message').filter({has:second.locator('.bubble').getByText('Browser reply body',{exact:true})})
        .locator('blockquote').filter({hasText:'Original message unavailable'}).waitFor()
      console.log('Passed reply quotes and live source redaction in both browsers.')

      const workspace=data(await sender.client.rpc('st_v2_create_workspace',{p_name:'Browser workspace'}))
      data(await sender.client.rpc('st_v2_invite',{p_workspace:workspace,p_handle:recipient.handle}))
      const invitations=data(await recipient.client.from('st_v2_invites').select('id').eq('workspace_id',workspace))
      data(await recipient.client.rpc('st_v2_reply_invite',{p_invite:invitations[0].id,p_accept:true}))
      await first.getByRole('button',{name:'Rooms',exact:true}).click()
      await first.getByText('Create a room',{exact:true}).click()
      await first.getByLabel('Room name',{exact:true}).fill('Browser workspace room')
      const roomCreated=first.waitForResponse(response=>response.request().method()==='POST'&&response.url().includes('/rpc/st_v6_room_create'))
      await first.getByRole('button',{name:'Create room',exact:true}).click()
      assert.equal((await roomCreated).status(),200)
      await first.getByLabel('Write a room message').waitFor()

      await second.getByRole('button',{name:'Rooms',exact:true}).click()
      await second.getByRole('button',{name:/Browser workspace room/}).click()
      await second.getByRole('button',{name:'Join room',exact:true}).click()
      await second.getByLabel('Write a room message').waitFor()
      await first.getByLabel('Write a room message').fill('Room live sync')
      await first.getByRole('button',{name:'Send',exact:true}).click()
      await second.getByText('Room live sync',{exact:true}).waitFor()
      await second.getByRole('button',{name:'Open thread (0)',exact:true}).click()
      await second.getByRole('button',{name:'Follow thread',exact:true}).click()
      await second.getByRole('heading',{name:'Followed threads',exact:true}).waitFor()
      await second.getByLabel('Write a reply',{exact:true}).fill('Thread live reply')
      await second.getByRole('button',{name:'Send',exact:true}).click()
      await first.getByRole('button',{name:'Open thread (1)',exact:true}).click()
      await first.getByText('Thread live reply',{exact:true}).waitFor()
      assert.equal(await first.getByRole('heading',{name:'Followed threads',exact:true}).count(),0)
      await second.getByRole('button',{name:'Unfollow thread',exact:true}).click()
      await second.getByRole('heading',{name:'Followed threads',exact:true}).waitFor({state:'detached'})
      assert.equal(await second.getByRole('button',{name:'Audit',exact:true}).count(),0)
      await first.getByRole('button',{name:'Audit',exact:true}).click()
      await first.getByText('room created',{exact:true}).waitFor()
      console.log('Passed private saved searches, room creation, member join, live room messages and audit tab gating.')

      await first.getByRole('group',{name:'Room tabs'}).getByRole('button',{name:'Tasks',exact:true}).click()
      await first.getByText('Create a task',{exact:true}).click()
      await first.getByLabel('Task title',{exact:true}).fill('Browser room task')
      await first.getByLabel('Task due date',{exact:true}).fill('2020-02-01T10:00')
      await first.getByRole('button',{name:'Create task',exact:true}).click()
      await second.getByRole('group',{name:'Room tabs'}).getByRole('button',{name:'Tasks',exact:true}).click()
      const roomTasks=second.getByRole('region',{name:'Scoped tasks'})
      await roomTasks.getByRole('button',{name:'Browser room task',exact:true}).waitFor()
      await roomTasks.getByText('Overdue',{exact:true}).waitFor()
      await roomTasks.getByRole('button',{name:'Board',exact:true}).click()
      await roomTasks.getByRole('region',{name:'To do'}).getByRole('button',{name:'Browser room task',exact:true}).waitFor()
      await roomTasks.getByRole('button',{name:'Calendar',exact:true}).click()
      await roomTasks.getByRole('heading',{name:'Task deadlines'}).waitFor()
      await roomTasks.getByRole('button',{name:'Browser room task',exact:true}).waitFor()
      await roomTasks.getByRole('button',{name:'Month',exact:true}).click()
      const calendar=roomTasks.getByRole('group',{name:'Calendar month'})
      await calendar.waitFor()
      const scheduledDay=calendar.getByRole('button',{pressed:true})
      assert.match(await scheduledDay.getAttribute('aria-label')||'',/,[\s\u00a0]*1 tasks$/)
      await scheduledDay.click()
      await roomTasks.getByRole('button',{name:'Browser room task',exact:true}).waitFor()

      await first.getByRole('button',{name:'Inbox',exact:true}).click()
      const direct=first.locator(sample).filter({hasText:'Emoji reaction integration'})
      await direct.locator('summary[aria-label="Message actions"]').click()
      await direct.getByRole('button',{name:'Create task from message',exact:true}).click()
      await first.getByLabel('Task title',{exact:true}).fill('Browser source task')
      await first.getByLabel('Task priority').selectOption('high')
      await first.getByLabel('Task labels',{exact:true}).fill('review, customer')
      await first.getByRole('button',{name:'Create task',exact:true}).click()
      const details=first.getByRole('region',{name:'Task details'})
      await details.getByRole('button',{name:'Source',exact:true}).click()
      await details.getByText('Emoji reaction integration',{exact:true}).waitFor()
      await details.getByRole('button',{name:'Details',exact:true}).click()
      await details.getByLabel('Choose assignee').selectOption({label:'Receiver'})
      await details.getByRole('button',{name:'Assign',exact:true}).click()
      await details.getByRole('button',{name:'Remove assignee',exact:true}).waitFor()

      await second.getByRole('button',{name:'Inbox',exact:true}).click()
      await second.getByRole('button',{name:'Chat tasks',exact:true}).click()
      await second.getByRole('button',{name:'Browser source task',exact:true}).click()
      const receiverTask=second.getByRole('region',{name:'Task details'})
      await receiverTask.getByRole('button',{name:'Watch task',exact:true}).click()
      await receiverTask.getByRole('button',{name:'Stop watching',exact:true}).waitFor()

      await first.getByRole('button',{name:'Notifications',exact:true}).click()
      await first.getByRole('button',{name:'Task updates',exact:true}).click()
      await first.getByRole('button',{name:'Unread task updates',exact:true}).click()
      await receiverTask.getByLabel('New task status').selectOption('done')
      await receiverTask.getByRole('button',{name:'Change status',exact:true}).click()
      const completion=first.locator('.release-row').filter({hasText:'Browser source task'})
      await completion.getByText('Task completed',{exact:true}).waitFor()
      await completion.getByRole('button',{name:'Mark read',exact:true}).click()
      await completion.getByRole('button',{name:'Mark read',exact:true}).waitFor({state:'detached'})
      await first.getByText('No unread task updates.',{exact:true}).waitFor()
      await receiverTask.getByRole('button',{name:'Audit',exact:true}).click()
      await receiverTask.getByRole('listitem').filter({hasText:/status.*done/}).waitFor()
      const source=data(await sender.client.from('st_messages').select('id').eq('chat_id',chat).eq('body','Emoji reaction integration').single())
      data(await sender.client.rpc('st_v5_message_action',{p_message:source.id,p_action:'revoke'}))
      await receiverTask.getByRole('button',{name:'Source',exact:true}).click()
      await receiverTask.getByText('The source message is no longer available. The task record remains.',{exact:true}).waitFor()
      console.log('Passed room and chat task tabs, board, calendar, source, assignment, watching, audit, and live completion notice.')

      await second.getByRole('button',{name:'Notifications',exact:true}).click()
      const categories=second.getByRole('group',{name:'Notification categories'})
      await categories.getByRole('button',{name:'Meetings',exact:true}).click()
      await second.getByRole('button',{name:'Unread',exact:true}).click()
      await second.getByText('You have no unread notifications.',{exact:true}).waitFor()
      const startsAt=Date.now()+60_000
      const meeting=data(await sender.client.rpc('st_v3_schedule',{
        p_workspace:workspace,p_title:'Browser notification meeting',p_agenda:'',
        p_start:new Date(startsAt).toISOString(),p_end:new Date(startsAt+60*60_000).toISOString(),p_id:randomUUID(),
      }))
      const meetingNotice=second.locator('article').filter({hasText:'Browser notification meeting'})
      await meetingNotice.getByText('A workspace meeting was scheduled',{exact:true}).waitFor()
      await meetingNotice.getByRole('button',{name:'Mark read',exact:true}).click()
      await second.getByText('You have no unread notifications.',{exact:true}).waitFor()
      await second.getByRole('button',{name:'All updates',exact:true}).click()
      await meetingNotice.waitFor()
      assert.equal(await meetingNotice.getByRole('button',{name:'Mark read',exact:true}).count(),0)
      await categories.getByRole('button',{name:'Task updates',exact:true}).click()
      await second.getByRole('button',{name:'Unread task updates',exact:true}).waitFor()
      await meetingNotice.waitFor({state:'detached'})
      console.log('Passed live meeting notification, read and unread filters, and notification grouping.')

      const navigateMeeting=async page=>{
        await page.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Meetings',exact:true}).click()
        await page.getByRole('button',{name:'Browser notification meeting',exact:true}).click()
      }
      await Promise.all([navigateMeeting(first),navigateMeeting(second)])
      await first.getByRole('button',{name:'Open waiting room',exact:true}).click()
      await second.getByRole('button',{name:'Request admission',exact:true}).click()
      await second.getByText('Waiting for the host to admit you',{exact:true}).waitFor()
      assert.equal(await second.getByRole('button',{name:'Admit all eligible attendees',exact:true}).count(),0)
      assert.equal(data(await recipient.client.rpc('st_v3_media_access',{p_meeting:meeting})),false)
      const tokenRequest=async ()=>{
        const session=data(await recipient.client.auth.getSession()).session
        return fetch(app+'/api/meetings/token',{
          method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+session.access_token},
          body:JSON.stringify({meetingId:meeting}),
        })
      }
      if(process.env.SECTALK_TEST_LOCAL_MEETING_TOKEN==='1')assert.equal((await tokenRequest()).status,403)
      await first.getByRole('button',{name:'Admit all eligible attendees',exact:true}).click()
      await first.getByText('Admitted 1 attendee.',{exact:true}).waitFor()
      await second.getByText('Waiting for the host to admit you',{exact:true}).waitFor({state:'detached'})
      assert.equal(data(await recipient.client.rpc('st_v3_media_access',{p_meeting:meeting})),true)
      if(process.env.SECTALK_TEST_LOCAL_MEETING_TOKEN==='1'){
        const issued=await tokenRequest()
        assert.equal(issued.status,200)
        const {token}=await issued.json()
        const claims=JSON.parse(Buffer.from(token.split('.')[1],'base64url').toString())
        assert.equal(claims.sub,recipient.user)
        assert.equal(claims.video.room,'sectalk-v3-'+meeting)
      }
      console.log('Passed two-browser waiting room, host bulk admission, and server media admission.')

      const originalCall=data(await sender.client.rpc('st_place_call',{p_chat:chat,p_video:true}))
      data(await admin.from('st_calls').update({expires_at:new Date(Date.now()-1000).toISOString()}).eq('id',originalCall))
      await second.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Calls',exact:true}).click()
      await second.getByRole('group',{name:'Call history'}).getByRole('button',{name:'Missed',exact:true}).click()
      const history=second.locator('.report-row').filter({hasText:'Sender'})
      await history.getByText('Missed',{exact:true}).waitFor()
      await history.getByRole('button',{name:'Call back Sender',exact:true}).click()
      const incomingCall=first.getByRole('region',{name:'Video call',exact:true})
      await incomingCall.getByText('Video · Incoming call',{exact:true}).waitFor()
      await incomingCall.getByRole('button',{name:'Decline',exact:true}).click()
      await incomingCall.waitFor({state:'hidden'})
      await second.getByRole('group',{name:'Call history'}).getByRole('button',{name:'Video',exact:true}).click()
      await second.locator('.report-row').filter({hasText:'Outgoing video'}).getByText('Declined',{exact:true}).waitFor()
      console.log('Passed missed call history, same-mode video callback, live ringing and declined outcome.')

      await first.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Search',exact:true}).click()
      await first.getByRole('button',{name:'Audit logs',exact:true}).click()
      const auditSearch=first.getByRole('region',{name:'Audit log search',exact:true})
      await auditSearch.getByLabel('Audit event, room, or ID',{exact:true}).fill('Browser workspace room')
      await auditSearch.getByRole('combobox',{name:/Log source/}).selectOption('room')
      await auditSearch.getByRole('button',{name:'Search audit logs',exact:true}).click()
      const roomCreation=auditSearch.getByRole('article').filter({has:first.getByRole('heading',{name:'room created',exact:true})})
      await roomCreation.getByText('Browser workspace room',{exact:true}).waitFor()
      const checkedScope=second.waitForResponse(response=>response.url().includes('/rpc/st_v6_audit_workspaces'))
      await second.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Search',exact:true}).click()
      assert.deepEqual(await (await checkedScope).json(),[])
      assert.equal(await second.getByRole('button',{name:'Audit logs',exact:true}).count(),0)
      console.log('Passed separate workspace audit search and non-admin navigation gating.')

      await first.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Meetings',exact:true}).click()
      await first.getByRole('button',{name:'Schedule',exact:true}).click()
      await first.getByLabel('Title',{exact:true}).fill('Browser recurring meeting')
      const starts=new Date(Date.now()+86400_000)
      const localValue=date=>new Date(date.getTime()-date.getTimezoneOffset()*60_000).toISOString().slice(0,16)
      await first.getByLabel('Starts at',{exact:true}).fill(localValue(starts))
      await first.getByLabel('Ends at',{exact:true}).fill(localValue(new Date(starts.getTime()+3600_000)))
      await first.getByRole('combobox',{name:/Repeat/}).selectOption('weekly')
      await first.getByLabel('Occurrences',{exact:true}).fill('3')
      await first.getByRole('button',{name:'Schedule meeting',exact:true}).click()
      await first.getByText('Occurrence 3 of 3',{exact:true}).waitFor()
      const downloadPromise=first.waitForEvent('download')
      await first.getByRole('button',{name:'Add series to calendar',exact:true}).click()
      const seriesFile=await downloadPromise
      assert.equal(seriesFile.suggestedFilename(),'sectalk-meeting-series.ics')
      const calendarText=(await readFile(await seriesFile.path(),'utf8')).replace(/\r\n /g,'')
      assert.equal((calendarText.match(/^BEGIN:VEVENT$/gm)||[]).length,3)
      const joinLinks=[...calendarText.matchAll(/^URL:(.+)$/gm)].map(match=>match[1].trim())
      assert.equal(new Set(joinLinks).size,3)
      assert.equal(new URL(joinLinks[1]).origin,app)
      await second.goto(joinLinks[1])
      await second.getByRole('heading',{name:'Browser recurring meeting',exact:true}).waitFor()
      const unauthorised=await browser.newPage()
      await unauthorised.goto(joinLinks[1])
      await unauthorised.getByLabel('Email address',{exact:true}).fill(outsider.email)
      await unauthorised.getByLabel('Password',{exact:true}).fill(password)
      await unauthorised.locator('button.submit-auth').click()
      await unauthorised.getByText('This meeting is unavailable to your account.',{exact:true}).waitFor()
      assert.equal(await unauthorised.getByText('Browser recurring meeting',{exact:true}).count(),0)
      await unauthorised.close()
      console.log('Passed recurring scheduling, calendar series export and member-only join links.')
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
