// Run against the isolated local v6 app and Supabase.
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

const [owner,member]=await Promise.all([account('GroupHost'),account('GroupMember')])
const workspace=data(await owner.client.rpc('st_v2_create_workspace',{p_name:'Browser group workspace'}))
const unrelated=data(await member.client.rpc('st_v2_create_workspace',{p_name:'Member private workspace'}))
data(await member.client.rpc('st_v6_workspace_group_create',{
  p_workspace:unrelated,p_id:randomUUID(),p_kind:'team',p_name:'Other tenant team',p_description:'',
}))
data(await owner.client.rpc('st_v2_invite',{p_workspace:workspace,p_handle:member.handle}))
const invitation=data(await member.client.from('st_v2_invites').select('id').eq('workspace_id',workspace).single())
data(await member.client.rpc('st_v2_reply_invite',{p_invite:invitation.id,p_accept:true}))

const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
async function directory(account,space){
  const page=await browser.newPage()
  await page.goto(new URL('/#account',app).href)
  await page.getByLabel('Email address',{exact:true}).fill(account.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Workspaces',exact:true}).click()
  await page.locator('select[name="workspace"]').selectOption(space)
  await page.getByRole('button',{name:'Groups & teams',exact:true}).click()
  return page
}
const region=page=>page.getByRole('region',{name:'Workspace groups and teams'})
const button=(page,name)=>region(page).getByRole('button',{name,exact:true})

try {
  const [first,second]=await Promise.all([directory(owner,workspace),directory(member,workspace)])
  await region(second).getByText('No teams.',{exact:true}).waitFor()
  assert.equal(await region(second).getByText('New team',{exact:true}).count(),0)
  assert.equal(await button(second,'Other tenant team').count(),0)

  async function create(type,name,label){
    if(type!=='team')await button(first,label).click()
    await region(first).getByText('New '+type,{exact:true}).click()
    await region(first).getByLabel(new RegExp('^'+type+' name$','i')).fill(name)
    await region(first).getByLabel('Description',{exact:true}).fill('Purpose of '+name)
    await button(first,'Create '+type).click()
    await region(first).getByRole('heading',{name,exact:true}).waitFor()
  }
  await create('team','Product engineering','Teams')
  const peopleSelect=region(first).getByRole('combobox',{name:/Workspace member/})
  await peopleSelect.selectOption(member.id)
  await button(first,'Add member').click()
  await button(first,'Remove GroupMember').waitFor()

  await button(second,'Product engineering').click()
  await region(second).getByText('GroupMember',{exact:true}).waitFor()
  assert.equal(await button(second,'Remove GroupMember').count(),0)

  await region(first).getByText('Edit team',{exact:true}).click()
  await region(first).getByLabel('New name',{exact:true}).fill('Platform team')
  await button(first,'Save changes').click()
  await region(first).getByRole('heading',{name:'Platform team',exact:true}).waitFor()
  await region(second).getByRole('heading',{name:'Platform team',exact:true}).waitFor()
  await button(first,'Archive team').click()
  await region(first).getByText('No teams.',{exact:true}).waitFor()
  await region(first).getByLabel('Show archived entries').check()
  await button(first,'Platform team').click()
  await button(first,'Restore team').click()
  await region(first).getByText('No archived teams.',{exact:true}).waitFor()
  await region(first).getByLabel('Show archived entries').uncheck()
  await button(first,'Platform team').click()
  await button(first,'Remove GroupMember').click()
  await region(first).getByText('No members yet.',{exact:true}).waitFor()
  await create('group','First responders','Groups')
  await create('department','Engineering division','Departments')

  await second.locator('select[name="workspace"]').selectOption(unrelated)
  await second.getByRole('button',{name:'Groups & teams',exact:true}).click()
  await button(second,'Other tenant team').waitFor()
  assert.equal(await button(second,'Platform team').count(),0)
  console.log('Passed workspace groups, teams, departments, member roles, lifecycle, and workspace isolation in two browsers.')
}finally{
  await browser.close()
}
