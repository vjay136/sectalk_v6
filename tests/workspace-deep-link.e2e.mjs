import assert from 'node:assert/strict'
import {execFileSync} from 'node:child_process'
import {randomUUID} from 'node:crypto'
import {createClient} from '@supabase/supabase-js'

const app=new URL(process.env.SECTALK_WORKSPACE_LINK_APP)
const backend=new URL(process.env.SECTALK_RESIDENCY_TARGET_DATABASE)
assert.equal(app.origin,'http://127.0.0.1:3609')
assert.equal(backend.origin,'http://127.0.0.1:56801')
const options={auth:{persistSession:false,autoRefreshToken:false}}
const publishable=process.env.SECTALK_RESIDENCY_TARGET_PUBLIC_KEY
const service=createClient(backend.href,process.env.SECTALK_RESIDENCY_TARGET_KEY,options)
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
const createdUsers=[]
const createdWorkspaces=[]
const suffix=randomUUID().slice(0,8)
const unavailable='This workspace is unavailable. Choose one of your workspaces to continue.'

function data(result){
  if(result.error)throw result.error
  return result.data
}

function sql(statement){
  return execFileSync('docker',['exec','-i','supabase_db_v6-bundle243-qa','psql','-XqtA','-v',
    'ON_ERROR_STOP=1','-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true})
}

async function account(label){
  const handle=label+'_'+suffix
  const email=handle+'@example.invalid'
  const password=randomUUID()+'!9a'
  const {user}=data(await service.auth.admin.createUser({email,password,email_confirm:true}))
  createdUsers.push(user.id)
  const client=createClient(backend.href,publishable,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:'Local workspace QA'}))
  return {id:user.id,email,password,client}
}

async function ownedWorkspace(owner,name){
  const title=name+' '+suffix
  const id=data(await owner.client.rpc('st_v2_create_workspace',{p_name:title}))
  createdWorkspaces.push(id)
  return {id,title}
}

function workspaceUrl(id){
  const url=new URL('/',app)
  url.searchParams.set('workspace',id)
  return url.href
}

const switcher=page=>page.locator('select[name="workspace"]')
const feature=(page,name)=>page.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name,exact:true})

async function signIn(page,person){
  await page.getByLabel('Email address',{exact:true}).fill(person.email)
  const password=page.getByLabel('Password',{exact:true})
  await password.fill(person.password)
  const [response]=await Promise.all([
    page.waitForResponse(result=>new URL(result.url()).pathname==='/api/auth/sign-in'),
    password.press('Enter'),
  ])
  assert.equal(response.status(),200)
}

async function waitForWorkspace(page,id){
  await page.waitForFunction(expected=>document.querySelector('select[name="workspace"]')?.value===expected,id)
  assert.equal(await feature(page,'Workspaces').getAttribute('aria-current'),'page')
}

try{
  const [member,firstOwner,secondOwner,foreignOwner]=await Promise.all(
    ['link_member','link_first','link_second','link_foreign'].map(account),
  )
  const first=await ownedWorkspace(firstOwner,'First available workspace')
  const second=await ownedWorkspace(secondOwner,'Linked destination workspace')
  const foreign=await ownedWorkspace(foreignOwner,'Unrelated private workspace')
  sql(`insert into public.st_v2_members(workspace_id,user_id,role) values
    ('${first.id}','${member.id}','member'),('${second.id}','${member.id}','member');`)
  const context=await browser.newContext()
  await context.addInitScript(({user,workspace})=>{
    const key='sectalk.workspace.v1:'+user
    if(!localStorage.getItem(key))localStorage.setItem(key,workspace)
  },{user:member.id,workspace:first.id})
  const page=await context.newPage()
  let releaseMemberships
  const waitMemberships=new Promise(resolve=>{releaseMemberships=resolve})
  let observedMembershipQuery=false
  await page.route('**/rest/v1/st_v2_members?*',async route=>{
    const search=new URL(route.request().url()).searchParams
    if(search.get('user_id')==='eq.'+member.id){
      observedMembershipQuery=true
      assert.equal(search.get('workspace_id'),null)
      assert.equal(search.get('suspended_at'),'is.null')
      await waitMemberships
    }
    await route.continue()
  })
  try{
    await page.goto(workspaceUrl(second.id.toUpperCase()))
    await signIn(page,member)
    await page.getByRole('status').getByText('Loading workspaces…',{exact:true}).waitFor()
    assert.equal(await page.getByText(unavailable,{exact:true}).count(),0)
    assert.equal(await switcher(page).count(),0)
  }finally{releaseMemberships()}
  await waitForWorkspace(page,second.id)
  assert.equal(observedMembershipQuery,true)
  assert.equal(await switcher(page).locator('option:checked').textContent(),second.title)
  await switcher(page).selectOption(first.id)
  await waitForWorkspace(page,first.id)
  assert.equal(new URL(page.url()).searchParams.has('workspace'),false)

  async function unavailableLink(value){
    await page.goto(workspaceUrl(value))
    await page.getByRole('status').getByText(unavailable,{exact:true}).waitFor()
    assert.equal(await feature(page,'Workspaces').getAttribute('aria-current'),'page')
    assert.equal(await switcher(page).inputValue(),'')
    assert.equal(await page.getByText(foreign.title,{exact:true}).count(),0)
  }
  for(const value of [foreign.id,randomUUID(),'invalid-link'])await unavailableLink(value)
  await switcher(page).selectOption(first.id)
  await waitForWorkspace(page,first.id)
  assert.equal(new URL(page.url()).searchParams.has('workspace'),false)

  sql(`update public.st_v2_members set suspended_at=now() where (workspace_id,user_id)=('${second.id}','${member.id}');`)
  await unavailableLink(second.id)
  sql(`update public.st_v2_members set suspended_at=null where (workspace_id,user_id)=('${second.id}','${member.id}');`)
  await page.goto(workspaceUrl(second.id))
  await waitForWorkspace(page,second.id)
  await feature(page,'Sign out').press('Enter')
  await page.getByLabel('Email address',{exact:true}).waitFor()
  assert.equal(new URL(page.url()).searchParams.has('workspace'),false)
  await signIn(page,foreignOwner)
  await feature(page,'Inbox').waitFor()
  assert.equal(await feature(page,'Inbox').getAttribute('aria-current'),'page')
  assert.equal(await page.getByText(second.title,{exact:true}).count(),0)
  await context.close()

  const sso=await browser.newContext()
  const ssoPage=await sso.newPage()
  const {session}=data(await member.client.auth.getSession())
  await ssoPage.route('**/api/auth/workspace-sso',route=>{
    const input=route.request().postDataJSON()
    if(input.action==='start')return route.fulfill({json:{destination:new URL('/auth/workspace-sso?code=local-qa',app).href}})
    assert.equal(input.action,'complete')
    return route.fulfill({json:{access_token:session.access_token,refresh_token:session.refresh_token,workspace:first.id}})
  })
  await ssoPage.goto(workspaceUrl(second.id))
  await ssoPage.getByText('Sign in with workspace SSO',{exact:true}).click()
  await ssoPage.getByLabel('Workspace email domain',{exact:true}).fill('example.invalid')
  await ssoPage.getByRole('button',{name:'Continue with workspace SSO',exact:true}).click()
  await waitForWorkspace(ssoPage,second.id)
  assert.equal(new URL(ssoPage.url()).searchParams.get('workspace'),second.id)
  await sso.close()
  console.log('Verified member deep-link landing, signed-out password and SSO return, generic unavailable state, normal switching, and sign-out in Edge.')
}finally{
  await browser.close()
  for(const id of createdWorkspaces)sql(`delete from public.st_v2_workspaces where id='${id}';`)
  for(const id of createdUsers)data(await service.auth.admin.deleteUser(id))
}
