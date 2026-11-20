import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { setTimeout } from 'node:timers/promises'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname,'127.0.0.1')
assert.equal(supabase.origin,'http://127.0.0.1:55321')
const options = { auth:{ persistSession:false,autoRefreshToken:false } }
const admin = createClient(supabase.origin,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const password=randomUUID()+'1!Q'
const suffix=randomUUID().slice(0,8)

function data(result){
  if(result.error)throw new Error(result.error.message)
  return result.data
}
async function account(name){
  const handle=name.toLowerCase()+'_'+suffix
  const email=handle+'@example.org'
  const {user}=data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  const client=createClient(supabase.origin,process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:name}))
  return {id:user.id,email,client,handle,name}
}
const [author, reader, outsider] = await Promise.all([account('ExpirySender'), account('ExpiryReader'), account('ExpiryOther')])
const chat = data(await author.client.rpc('st_request', {p_handle: reader.handle}))
data(await reader.client.rpc('st_respond', {p_chat: chat, p_accept: true}))
const body = 'Transient browser evidence ' + suffix
const durable = 'Durable response ' + suffix
const browser = await chromium.launch({executablePath: process.env.SECTALK_TEST_BROWSER})
for (const id of [chat,author.id,reader.id,outsider.id]) assert.match(id,/^[a-f0-9-]{36}$/)
function sql(input) {
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'],{input,encoding:'utf8'}).trim()
}
try {
  async function open(person, friend) {
    const page = await browser.newPage()
    await page.goto(new URL('/#account', app).href)
    await page.getByLabel('Email address', {exact: true}).fill(person.email)
    await page.getByLabel('Password', {exact: true}).fill(password)
    await page.locator('button.submit-auth').click()
    await page.locator('.chat-item').filter({hasText: friend.name}).click()
    return page
  }
  const [sender, recipient] = await Promise.all([open(author, reader), open(reader, author)])
  await sender.getByRole('combobox', {name: 'Message timer', exact: true}).selectOption('60')
  assert.ok(await sender.getByRole('button', {name: 'Attach file', exact: true}).isDisabled())
  await sender.getByLabel('Write a message', {exact: true}).fill(body)
  const accepted = sender.waitForResponse(response => response.url().endsWith('/rpc/st_v6_send_disappearing_message'))
  await sender.getByRole('button', {name: 'Send message', exact: true}).click()
  assert.ok((await accepted).ok())
  const sent = data(await author.client.from('st_messages').select('id,created_at,expires_at').eq('chat_id', chat).eq('body', body).single())
  assert.equal(Date.parse(sent.expires_at) - Date.parse(sent.created_at), 60_000)
  assert.deepEqual(data(await outsider.client.from('st_messages').select('id').eq('id', sent.id)), [])
  assert.deepEqual(data(await reader.client.rpc('st_v6_search', {p_query: body, p_kind: 'direct', p_filters: {}})), [])

  for (const page of [sender, recipient]) {
    await page.getByText(body, {exact: true}).waitFor()
    await page.getByText(/^Disappears at /).waitFor()
  }
  const received = recipient.locator('.message').filter({hasText: body})
  await received.locator('summary[aria-label="Message actions"]').click()
  assert.equal(await received.getByRole('button', {name:'Forward message', exact:true}).count(), 0)
  await received.getByRole('button', {name: 'Reply', exact: true}).click()
  await recipient.getByLabel('Write a message', {exact: true}).fill(durable)
  await recipient.getByRole('button', {name: 'Send message', exact: true}).click()
  const durableOnSender = sender.locator('.message').filter({hasText: durable})
  await durableOnSender.locator('.reply-preview').filter({hasText: body}).waitFor()

  // Ensure the displayed plaintext and quote expire from the open clients even without refresh responses.
  for (const page of [sender, recipient]) await page.route('**/rest/v1/**', route => route.abort())
  await Promise.all([sender, recipient].map(page =>
    page.getByText(body, {exact:true}).first().waitFor({state:'hidden', timeout:75_000})))
  assert.equal(await sender.locator('.reply-preview').filter({hasText: body}).count(), 0)
  assert.equal(await recipient.locator('.reply-preview').filter({hasText: body}).count(), 0)
  await durableOnSender.getByText('Original message unavailable', {exact: true}).waitFor()
  await durableOnSender.getByText(durable, {exact: true}).waitFor()
  assert.deepEqual(data(await reader.client.from('st_messages').select('body').eq('id', sent.id)), [])
  assert.deepEqual(data(await reader.client.rpc('st_v6_reply_quotes', {p_chat: chat, p_ids: [sent.id]})), [])
  assert.match(sent.id,/^[a-f0-9-]{36}$/)
  const scrubbed = () => sql(`select exists(select 1 from public.st_messages where id='${sent.id}'
    and chat_id='${chat}' and body='Message removed' and revoked_at is not null);`) === 't'
  const timeout = Date.now()+75_000
  while (!scrubbed() && Date.now()<timeout) await setTimeout(2000)
  assert.ok(scrubbed(), 'The scheduled local job did not scrub the actual fixture body')
  console.log('Passed real one-minute deadline on two open Edge clients, offline refresh failure, cached quote removal, durable reply, and independent server denial.')
} finally {
  await browser.close()
  sql(`begin;
    delete from public.st_messages where chat_id='${chat}';
    delete from public.st_chats where id='${chat}';
    commit;`)
  await Promise.all([author,reader,outsider].map(async person=>data(await admin.auth.admin.deleteUser(person.id))))
}
