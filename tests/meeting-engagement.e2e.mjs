// Run against the isolated loopback app and database.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app=new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase=new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname,'127.0.0.1')
assert.equal(supabase.hostname,'127.0.0.1')
const {SECTALK_STORAGE_TEST_PUBLIC_KEY:key,SECTALK_STORAGE_TEST_SERVICE_KEY:serviceKey}=process.env
assert.ok(key&&serviceKey)
const options={auth:{persistSession:false,autoRefreshToken:false}}
const admin=createClient(supabase.href,serviceKey,options)
const suffix=randomUUID().slice(0,8)
const password=randomUUID()+'1!Q'
function data(result){
  if(result.error)throw new Error(result.error.message)
  return result.data
}
async function account(name){
  const handle=name.toLowerCase()+'_'+suffix
  const email=handle+'@example.org'
  data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  const client=createClient(supabase.href,key,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:name}))
  return {email,handle,client}
}
const host=await account('HandHost')
const guest=await account('HandGuest')
const workspace=data(await host.client.rpc('st_v2_create_workspace',{p_name:'Meeting engagement checks'}))
data(await host.client.rpc('st_v2_invite',{p_workspace:workspace,p_handle:guest.handle}))
const invite=data(await guest.client.from('st_v2_invites').select('id').eq('workspace_id',workspace).single())
data(await guest.client.rpc('st_v2_reply_invite',{p_invite:invite.id,p_accept:true}))
const title='Raised hands '+suffix
const meeting=data(await host.client.rpc('st_v6_start_instant_meeting',{
  p_id:randomUUID(),p_workspace:workspace,p_title:title,p_minutes:15,
}))
const link=new URL(app.href)
link.searchParams.set('meeting',meeting)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})

async function open(person){
  const page=await browser.newPage()
  // Slow the engagement poll so the first cross-browser gesture requires Realtime.
  await page.addInitScript(()=>{
    const every=window.setInterval.bind(window)
    window.setInterval=(handler,delay,...args)=>every(handler,delay===5000?30000:delay,...args)
  })
  await page.goto(link.href)
  await page.getByLabel('Email address',{exact:true}).fill(person.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('heading',{name:title,exact:true}).waitFor()
  return page
}

try{
  const [hostPage,guestPage]=await Promise.all([open(host),open(guest)])
  const controls=page=>page.getByRole('region',{name:'Meeting participation',exact:true})
  const hands=page=>controls(page).getByRole('list',{name:'Raised hands'})
  const recent=page=>controls(page).getByRole('list',{name:'Recent meeting reactions'})
  await guestPage.getByRole('button',{name:'Request admission',exact:true}).click()
  await guestPage.getByText('Waiting for the host to admit you',{exact:true}).waitFor()
  assert.equal(await controls(guestPage).count(),0)
  const denied=await guest.client.rpc('st_v6_send_meeting_reaction',{p_meeting:meeting,p_reaction:'clap'})
  assert.equal(denied.error?.code,'42501')

  await hostPage.getByRole('button',{name:'Admit',exact:true}).click()
  await controls(guestPage).getByRole('button',{name:'Raise hand',exact:true}).click()
  await hands(hostPage).getByText('HandGuest',{exact:true}).waitFor({timeout:6500})
  await controls(guestPage).getByRole('button',{name:'Lower hand',exact:true}).click()
  await hands(hostPage).waitFor({state:'hidden',timeout:6500})

  await controls(hostPage).getByRole('button',{name:'Clap',exact:true}).click()
  await recent(guestPage).getByText(/HandHost clapped/).waitFor({timeout:6500})
  await recent(guestPage).waitFor({state:'hidden',timeout:11000})
  await controls(guestPage).getByRole('button',{name:'Raise hand',exact:true}).click()
  await hands(hostPage).getByText('HandGuest',{exact:true}).waitFor()
  await guestPage.getByRole('button',{name:'Leave',exact:true}).click()
  await controls(guestPage).waitFor({state:'hidden'})
  const handsAfterLeaving=data(await guest.client.from('st_v6_meeting_hands').select('user_id').eq('meeting_id',meeting))
  assert.deepEqual(handsAfterLeaving,[])
}finally{
  await browser.close()
}
console.log('Passed live raise/lower, expiring reactions, waiting-room authorization, and leave in two browsers.')
