// Run against the isolated local v6 app and Supabase.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app=new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase=new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname,'127.0.0.1')
assert.equal(supabase.hostname,'127.0.0.1')
const publicKey=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const serviceKey=process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
assert.ok(publicKey&&serviceKey)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
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
  const client=createClient(supabase.href,publicKey,options)
  const {user}=data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:name}))
  return {client,email,handle,id:user.id}
}

const [owner,member]=await Promise.all([account('SetupHost'),account('SetupMember')])
const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
try{
  const page=await browser.newPage()
  await page.goto(new URL('/#account',app).href)
  await page.getByLabel('Email address',{exact:true}).fill(owner.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  const nav=page.getByRole('navigation',{name:'SecTalk features'})
  await nav.getByRole('button',{name:'Workspaces',exact:true}).click()
  const wizard=page.getByRole('form',{name:'Workspace setup'})
  await wizard.getByRole('heading',{name:'Choose a workspace type'}).waitFor()
  await wizard.getByLabel('Workspace type').selectOption('family')
  await wizard.getByRole('button',{name:'Continue'}).click()
  await wizard.getByLabel('Workspace name',{exact:true}).fill('Browser family workspace')
  await wizard.getByRole('button',{name:'Continue'}).click()
  await wizard.getByText('Default policy requires private or admin-only rooms and individual meeting admission.').waitFor()
  await wizard.getByRole('button',{name:'Back'}).click()
  assert.equal(await wizard.getByLabel('Workspace name',{exact:true}).inputValue(),'Browser family workspace')
  await wizard.getByRole('button',{name:'Continue'}).click()
  await wizard.getByRole('button',{name:'Create workspace',exact:true}).click()
  await page.getByText('Family · Restricted policy',{exact:true}).waitFor()
  const workspace=data(await owner.client.from('st_v2_workspaces').select('id').eq('name','Browser family workspace').single()).id
  await page.reload()
  await nav.getByRole('button',{name:'Workspaces',exact:true}).click()
  await page.getByText('Family · Restricted policy',{exact:true}).waitFor()
  await nav.getByRole('button',{name:'Rooms',exact:true}).click()
  const directory=page.getByRole('region',{name:'Room directory',exact:true})
  await directory.getByText('Create a room',{exact:true}).click()
  const kinds=directory.getByLabel('Room type')
  assert.deepEqual(await kinds.locator('option').allTextContents(),['Private','Admins only'])
  assert.equal(await kinds.inputValue(),'private')
  await directory.getByLabel('Room name',{exact:true}).fill('Browser family room')
  await directory.getByRole('button',{name:'Create room',exact:true}).click()
  await directory.getByRole('button',{name:/Browser family room/}).waitFor()

  data(await owner.client.rpc('st_v2_invite',{p_workspace:workspace,p_handle:member.handle}))
  const invitation=data(await member.client.from('st_v2_invites').select('id').eq('workspace_id',workspace).single())
  data(await member.client.rpc('st_v2_reply_invite',{p_invite:invitation.id,p_accept:true}))
  const meeting=randomUUID()
  data(await owner.client.rpc('st_v6_start_instant_meeting',{
    p_id:meeting,p_workspace:workspace,p_title:'Browser family lobby',p_minutes:30,
  }))
  assert.equal(data(await member.client.rpc('st_v3_request_admission',{p_meeting:meeting})),'waiting')
  await nav.getByRole('button',{name:'Meetings',exact:true}).click()
  await page.getByRole('button',{name:'Browser family lobby',exact:true}).click()
  await page.getByRole('button',{name:'Admit',exact:true}).waitFor()
  assert.equal(await page.getByRole('button',{name:'Admit all eligible attendees',exact:true}).count(),0)
  await page.getByRole('button',{name:'Admit',exact:true}).click()
  await page.getByRole('button',{name:'Admit',exact:true}).waitFor({state:'detached'})
  assert.equal(data(await member.client.rpc('st_v3_media_access',{p_meeting:meeting})),true)
  console.log('Passed typed workspace wizard, persisted setup, allowed room options, and individual lobby admission.')
}finally{
  await browser.close()
}
