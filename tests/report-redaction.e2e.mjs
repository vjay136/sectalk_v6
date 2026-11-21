import assert from 'node:assert/strict'
import { randomUUID, createHmac } from 'node:crypto'
import { spawnSync } from 'node:child_process'
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
function currentCode(encoded){
  const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bits=[...encoded.toUpperCase().replace(/=+$/,'')].map(character=>{
    const offset=alphabet.indexOf(character)
    assert.ok(offset>=0,'Invalid synthetic authenticator data')
    return offset.toString(2).padStart(5,'0')
  }).join('')
  const key=Buffer.from((bits.match(/.{8}/g)||[]).map(part=>parseInt(part,2)))
  const counter=Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)))
  const digest=createHmac('sha1',key).update(counter).digest()
  return String((digest.readUInt32BE(digest.at(-1)&15)&0x7fffffff)%1_000_000).padStart(6,'0')
}

const [author,reporter,staff]=await Promise.all([account('CaseAuthor'),account('CaseReporter'),account('CaseStaff')])
assert.match(staff.id,/^[0-9a-f-]{36}$/i)
const seed=spawnSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres'],{
  input:"insert into sectalk_private.staff(user_id) values('"+staff.id+"');",
  encoding:'utf8',windowsHide:true,
})
assert.equal(seed.status,0,seed.stderr)
const chat=data(await reporter.client.rpc('st_request',{p_handle:author.handle}))
data(await author.client.rpc('st_respond',{p_chat:chat,p_accept:true}))
const id=randomUUID()
const body='Shared redaction evidence '+suffix
data(await author.client.rpc('st_send',{p_chat:chat,p_id:id,p_body:body}))
assert.equal((await reporter.client.rpc('st_v6_abuse_queue')).error?.code,'42501')

const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
try{
  const nav=page=>page.getByRole('navigation',{name:'SecTalk features'})
  async function open(person){
    const page=await browser.newPage()
    await page.goto(new URL('/#account',app).href)
    await page.getByLabel('Email address',{exact:true}).fill(person.email)
    await page.getByLabel('Password',{exact:true}).fill(password)
    await page.locator('button.submit-auth').click()
    await nav(page).waitFor()
    return page
  }
  const [moderator,recipient]=await Promise.all([open(staff),open(reporter)])
  await recipient.locator('.chat-item').filter({hasText:author.name}).click()
  await recipient.getByText(body,{exact:true}).waitFor()
  const incoming=recipient.locator('.message').filter({hasText:body})
  await incoming.getByRole('button',{name:'Report message',exact:true}).click()
  const form=recipient.getByRole('dialog',{name:'Report this message',exact:true})
  await form.waitFor()
  await form.getByLabel('Report category',{exact:true}).selectOption('harassment')
  await form.getByLabel(/Details/).fill('Review fixture '+suffix)
  await form.getByRole('button',{name:'Submit report',exact:true}).click()
  const receipt=recipient.getByRole('status').filter({hasText:'Report submitted. Ticket '})
  await receipt.waitFor()
  const report=(await receipt.textContent()).match(/Ticket ([a-f0-9-]{36})\./)?.[1]
  assert.ok(report,'Reporter receives the native ticket ID')
  await nav(moderator).getByRole('button',{name:'Safety',exact:true}).click()
  await moderator.getByRole('button',{name:'Staff console',exact:true}).click()
  await moderator.getByRole('button',{name:'Set up authenticator',exact:true}).click()
  const secret=(await moderator.locator('.mfa-setup code').textContent()).trim()
  await moderator.getByLabel('Authenticator code',{exact:true}).fill(currentCode(secret))
  const verification=moderator.waitForResponse(response=>response.url().includes('/auth/v1/factors/')&&response.url().endsWith('/verify'))
  await moderator.getByRole('button',{name:'Verify access',exact:true}).click()
  assert.equal((await verification).status(),200)
  const filters=moderator.getByRole('group',{name:'Moderation queue filters'})
  await filters.getByRole('combobox',{name:'Report category'}).selectOption('harassment')
  await filters.getByRole('combobox',{name:'Deadline'}).selectOption('next_day')
  await moderator.getByRole('button',{name:new RegExp(author.handle)}).click()
  await moderator.getByText(body,{exact:true}).waitFor()
  await moderator.getByText('Acknowledge by',{exact:true}).waitFor()
  await moderator.getByText('Resolve by',{exact:true}).waitFor()
  await moderator.locator('select[name="action"]').selectOption('reviewing')
  await moderator.getByLabel('Reason',{exact:true}).fill('Verified initial review')
  await moderator.getByRole('button',{name:'Record decision',exact:true}).click()
  await moderator.getByText('Verified initial review',{exact:true}).waitFor()
  assert.ok(data(await reporter.client.rpc('st_v5_report_timeline',{p_report:report})).some(entry=>entry.action==='reviewing'))
  await moderator.locator('select[name="action"]').selectOption('redact_message')
  await moderator.getByLabel('Reason',{exact:true}).fill('Moderated shared evidence')
  moderator.once('dialog',dialog=>dialog.accept())
  await moderator.getByRole('button',{name:'Record decision',exact:true}).click()
  await moderator.getByText('Reported message removed',{exact:true}).waitFor()
  await moderator.getByText(body,{exact:true}).waitFor()
  await recipient.getByText('Message removed',{exact:true}).waitFor()
  assert.equal(await recipient.getByText(body,{exact:true}).count(),0)
  await nav(recipient).getByRole('button',{name:'Safety',exact:true}).click()
  await recipient.getByRole('group',{name:'My report scopes',exact:true}).getByRole('button',{name:'Chat reports',exact:true}).click()
  const filter=recipient.getByLabel('Filter recent reports by ticket number',{exact:true})
  await filter.fill(randomUUID())
  await recipient.getByText('No matching chat reports',{exact:true}).waitFor()
  await filter.fill('Ticket '+report.toUpperCase())
  const ownReports=recipient.getByRole('region',{name:'My chat reports',exact:true})
  await ownReports.getByText(report,{exact:true}).waitFor()
  await ownReports.getByRole('button',{name:/Harassment/}).click()
  await recipient.getByRole('heading',{name:'Report timeline',exact:true}).waitFor()
  await recipient.getByText(report,{exact:true}).waitFor()
  await recipient.getByText('Harassment or abuse · In review',{exact:true}).waitFor()
  await recipient.getByText('Report received',{exact:true}).waitFor()
  await recipient.getByText('Reported message removed',{exact:true}).waitFor()
  assert.deepEqual(data(await author.client.rpc('st_v5_report_timeline',{p_report:report})),[])
  const privateReason='Private staff decision detail '+suffix
  const reviewerReply='The reported message was removed. Thank you for reporting it.'
  await moderator.locator('select[name="action"]').selectOption('resolved')
  await moderator.getByLabel('Reason',{exact:true}).fill(privateReason)
  await moderator.getByLabel('Summary for reporter',{exact:true}).fill(reviewerReply)
  await moderator.getByRole('button',{name:'Record decision',exact:true}).click()
  await moderator.getByText(privateReason,{exact:true}).waitFor()
  await recipient.getByText(reviewerReply,{exact:false}).waitFor()
  await recipient.getByText('Harassment or abuse · Resolved',{exact:true}).waitFor()
  assert.equal(await recipient.getByText(privateReason,{exact:true}).count(),0)
  assert.deepEqual(data(await author.client.rpc('st_v8_my_message_report_timeline',{p_report:report})),[])
  console.log('Passed native ticket receipt and filter, real TOTP, reporter history, live redaction and shared resolution without the staff-only reason.')
}finally{
  await browser.close()
}
