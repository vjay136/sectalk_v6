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

async function account(name){
  const handle=name.toLowerCase()+'_'+suffix
  const email=handle+'@example.org'
  data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  const client=createClient(supabase.href,key,options)
  const {user}=data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:name}))
  return {client,email,handle,id:user.id}
}

async function workspace(owner,label){
  const name=label+' test workspace'
  const id=data(await owner.client.rpc('st_v2_create_workspace',{p_name:name}))
  const room=randomUUID()
  const roomName=label+' test room'
  data(await owner.client.rpc('st_v6_room_create',{p_id:room,p_workspace:id,p_name:roomName,p_kind:'public',p_template:'blank'}))
  const event=label+' test event'
  const roomTask=label+' test room task'
  const workspaceTask=label+' test workspace task'
  const starts=new Date(Date.now()+3600_000)
  data(await owner.client.rpc('st_v2_add_item',{p_workspace:id,p_kind:'event',p_title:event,p_details:'',p_due:starts.toISOString()}))
  data(await owner.client.rpc('st_v2_add_item',{p_workspace:id,p_kind:'task',p_title:workspaceTask,p_details:'',p_due:null}))
  data(await owner.client.rpc('st_v6_task_create',{p_id:randomUUID(),p_room:room,p_chat:null,p_title:roomTask}))
  const meeting=randomUUID()
  const meetingTitle=label+' test meeting'
  data(await owner.client.rpc('st_v3_schedule',{p_workspace:id,p_id:meeting,p_title:meetingTitle,p_agenda:'',p_start:starts.toISOString(),p_end:new Date(starts.getTime()+3600_000).toISOString()}))
  return {id,name,room,roomName,event,roomTask,workspaceTask,meeting,meetingTitle}
}

const member=await account('ContextMember')
const otherOwner=await account('ContextHost')
const first=await workspace(member,'First')
const second=await workspace(otherOwner,'Second')
data(await otherOwner.client.rpc('st_v2_invite',{p_workspace:second.id,p_handle:member.handle}))

const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
try{
  const page=await browser.newPage()
  await page.goto(new URL('/#account',app).href)
  await page.getByLabel('Email address',{exact:true}).fill(member.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  const nav=page.getByRole('navigation',{name:'SecTalk features'})
  const feature=name=>nav.getByRole('button',{name,exact:true})
  const chooser=page.locator('select[name="workspace"]')
  const selected=(space)=>chooser.locator('option:checked').filter({hasText:space.name}).waitFor({state:'attached'})

  await feature('Workspaces').click()
  await selected(first)
  await page.getByRole('button',{name:'Activity',exact:true}).waitFor()
  assert.equal(await chooser.locator('option').count(),1)
  await page.getByRole('button',{name:'Join',exact:true}).click()
  await selected(second)
  await page.getByText('ContextHost',{exact:true}).waitFor()
  assert.equal(await page.getByRole('button',{name:'Activity',exact:true}).count(),0)
  data(await member.client.rpc('st_v6_room_membership',{p_room:second.room,p_action:'join'}))

  await feature('Rooms').click()
  await selected(second)
  await page.getByRole('button',{name:new RegExp(second.roomName)}).click()
  await page.getByRole('region',{name:second.roomName,exact:true}).waitFor()
  assert.equal(await page.getByRole('button',{name:new RegExp(first.roomName)}).count(),0)
  await chooser.selectOption(first.id)
  await page.getByRole('region',{name:second.roomName,exact:true}).waitFor({state:'detached'})
  await page.getByRole('button',{name:new RegExp(first.roomName)}).waitFor()

  await feature('Tasks').click()
  await selected(first)
  await page.getByRole('button',{name:first.roomTask,exact:true}).click()
  await page.getByRole('region',{name:'Task details',exact:true}).waitFor()
  await chooser.selectOption(second.id)
  await page.getByRole('button',{name:second.roomTask,exact:true}).waitFor()
  assert.equal(await page.getByRole('region',{name:'Task details',exact:true}).count(),0)
  assert.equal(await page.getByRole('button',{name:first.roomTask,exact:true}).count(),0)
  await page.getByRole('button',{name:'Workspace tasks',exact:true}).click()
  await selected(second)
  await page.getByRole('heading',{name:second.workspaceTask,exact:true}).waitFor()
  assert.equal(await page.getByText(first.workspaceTask,{exact:true}).count(),0)

  await feature('Calendar').click()
  await selected(second)
  await page.getByText(second.event,{exact:true}).waitFor()
  assert.equal(await page.getByText(first.event,{exact:true}).count(),0)
  await chooser.selectOption(first.id)
  await page.getByText(first.event,{exact:true}).waitFor()
  assert.equal(await page.getByText(second.event,{exact:true}).count(),0)

  await feature('Meetings').click()
  await page.getByRole('button',{name:first.meetingTitle,exact:true}).waitFor()
  await page.getByRole('button',{name:'Meet now',exact:true}).waitFor()
  assert.equal(await page.getByRole('button',{name:second.meetingTitle,exact:true}).count(),0)
  const link=new URL(app)
  link.searchParams.set('meeting',second.meeting)
  await page.goto(link.href)
  await page.getByRole('heading',{name:second.meetingTitle,exact:true}).waitFor()
  await selected(second)
  assert.equal(await page.getByRole('button',{name:'Meet now',exact:true}).count(),0)
  await chooser.selectOption(first.id)
  await page.getByRole('button',{name:first.meetingTitle,exact:true}).waitFor()
  assert.equal(await page.getByRole('heading',{name:second.meetingTitle,exact:true}).count(),0)
  await page.goto(app.href)
  await feature('Rooms').click()
  await selected(first)

  await chooser.selectOption(second.id)
  await page.getByRole('button',{name:new RegExp(second.roomName)}).waitFor()
  await page.getByRole('button',{name:new RegExp(second.roomName)}).click()
  await page.getByRole('region',{name:second.roomName,exact:true}).waitFor()
  const membershipRefresh=page.waitForResponse(response=>{
    const url=new URL(response.url())
    return response.status()===200&&url.pathname.endsWith('/st_v2_members')&&url.searchParams.get('user_id')==='eq.'+member.id
  },{timeout:8000})
  data(await otherOwner.client.rpc('st_v2_set_member',{p_workspace:second.id,p_member:member.id,p_role:'remove'}))
  await membershipRefresh
  await selected(first)
  assert.equal(await chooser.locator('option').count(),1)
  assert.equal(await page.getByRole('region',{name:second.roomName,exact:true}).count(),0)
  assert.deepEqual(data(await member.client.from('st_v2_workspaces').select('id').eq('id',second.id)),[])
  assert.deepEqual(data(await member.client.from('st_v3_meetings').select('id').eq('id',second.meeting)),[])
  assert.deepEqual(data(await member.client.from('st_v6_tasks').select('id').eq('room_id',second.room)),[])
  await feature('Sign out').click()
  await page.getByLabel('Email address',{exact:true}).fill(otherOwner.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await feature('Workspaces').click()
  await selected(second)
  assert.equal(await chooser.locator('option').count(),1)
  console.log('Passed workspace invitation, shared context, per-tenant roles, Rooms, Tasks, Calendar, meeting links, reload, live removal and account separation.')
}finally{
  await browser.close()
}
