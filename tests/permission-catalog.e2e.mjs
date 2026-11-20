import assert from 'node:assert/strict'
import {execFileSync} from 'node:child_process'
import {randomUUID} from 'node:crypto'
import {createClient} from '@supabase/supabase-js'

const app=new URL(process.env.SECTALK_STORAGE_TEST_APP)
const origin=new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
assert.equal(app.hostname,'127.0.0.1')
assert.equal(origin,'http://127.0.0.1:55321')
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const options={auth:{persistSession:false,autoRefreshToken:false}}
const key=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const admin=createClient(origin,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const suffix=randomUUID().slice(0,8)
const password=randomUUID()+'!9a'
const accounts=[]
const workspaces=[]
const room=randomUUID()
const privateRoom='Permission room '+suffix
function data(result) {if(result.error)throw new Error(result.error.message);return result.data}
function sql(input) {
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres'],
    {input,encoding:'utf8'}).trim()
}
async function account(label) {
  const handle='perm_'+label+'_'+suffix
  const email=handle+'@example.org'
  const {user}=data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  accounts.push(user.id)
  const client=createClient(origin,key,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:'Permission '+label}))
  return {user,email,handle,client}
}
const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
async function open(identity) {
  const page=await browser.newPage()
  await page.goto(new URL('/#account',app).href)
  await page.getByLabel('Email address',{exact:true}).fill(identity.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Profile',exact:true}).click()
  await page.getByRole('button',{name:'Security',exact:true}).click()
  const catalog=page.getByRole('region',{name:'Permission catalog',exact:true})
  await catalog.getByRole('button',{name:'View my permissions',exact:true}).click()
  return catalog
}
async function decision(panel,label,expected) {
  const row=panel.locator('.release-row').filter({hasText:label})
  await row.getByText(expected,{exact:true}).waitFor()
}
try {
  const [owner,member,foreign]=await Promise.all([account('owner'),account('member'),account('foreign')])
  const workspace=data(await owner.client.rpc('st_v2_create_workspace',{p_name:'Permission workspace '+suffix}))
  const hidden=data(await foreign.client.rpc('st_v2_create_workspace',{p_name:'Hidden workspace '+suffix}))
  workspaces.push(workspace,hidden)
  data(await owner.client.rpc('st_v2_invite',{p_workspace:workspace,p_handle:member.handle}))
  const invite=data(await member.client.from('st_v2_invites').select('id').eq('workspace_id',workspace).single())
  data(await member.client.rpc('st_v2_reply_invite',{p_invite:invite.id,p_accept:true}))
  data(await owner.client.rpc('st_v6_room_create',{p_workspace:workspace,p_id:room,p_name:privateRoom,p_kind:'private',p_template:'blank'}))
  data(await owner.client.rpc('st_v6_room_membership',{p_room:room,p_action:'invite',p_target:member.user.id,p_role:'read_only'}))
  data(await member.client.rpc('st_v6_room_membership',{p_room:room,p_action:'accept'}))
  sql("insert into sectalk_private.st_v7_account_operators(user_id,capability) values('"+owner.user.id+"','reviewer');")
  const [ownerPanel,memberPanel]=await Promise.all([open(owner),open(member)])
  await Promise.all([ownerPanel,memberPanel].map(async panel=>{
    const selector=panel.getByLabel('Workspace for permissions')
    await selector.selectOption(workspace)
    assert.ok(!(await selector.locator('option').allTextContents()).some(name=>name.includes('Hidden workspace')))
    await panel.getByLabel('Room for permissions').selectOption(room)
  }))
  await ownerPanel.getByRole('heading',{name:'Workspace role: owner'}).waitFor()
  await memberPanel.getByRole('heading',{name:'Workspace role: member'}).waitFor()
  await memberPanel.getByRole('heading',{name:'Room role: read only'}).waitFor()
  await decision(ownerPanel,'Change workspace roles','Fresh security verification required')
  await decision(ownerPanel,'Change permissions for the room member role','Allowed for this role')
  await decision(memberPanel,'Post in the room','Unavailable for this role or scope')
  await decision(memberPanel,'Change workspace roles','Unavailable for this role or scope')
  await decision(ownerPanel,'Review a recovery request independently','Fresh security verification required')
  await decision(ownerPanel,'End an eligible account session','Unavailable for this role or scope')
  const cross=data(await member.client.rpc('st_v7_permission_catalog',{p_workspace:hidden,p_room:room}))
  assert.equal(cross.workspace_role,null)
  assert.deepEqual(cross.rooms,[])
  assert.equal((await member.client.rpc('st_v6_set_room_role_overrides',{p_room:room,p_role:'member',p_rules:{post:'allow'}})).error?.code,'42501')
  data(await owner.client.rpc('st_v6_set_room_role_overrides',{p_room:room,p_role:'owner',p_rules:{post:'deny'}}))
  await ownerPanel.getByRole('button',{name:'Refresh permissions'}).click()
  await decision(ownerPanel,'Post in the room','Unavailable for this role or scope')
  console.log('Live Profile permissions, tenant isolation, scoped read-only denial, reviewer separation, and updated room access passed.')
} finally {
  await browser.close()
  for(const id of workspaces)sql("delete from public.st_v2_workspaces where id='"+id+"';")
  for(const id of accounts)await admin.auth.admin.deleteUser(id)
}
