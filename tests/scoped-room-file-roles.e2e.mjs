// Run against the isolated loopback app and Supabase stack.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const serviceKey = process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const admin = createClient(supabase.origin, serviceKey, options)
const password = randomUUID() + '1!Q'
const suffix = randomUUID().slice(0, 8)

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

async function account(handlePrefix) {
  const handle = handlePrefix + '_' + suffix
  const email = handle + '@example.org'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(supabase.origin, publicKey, options)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: handle }))
  return { id: user.id, handle, email, client }
}
const { readFile } = await import('node:fs/promises')
const { verifyStaffPanel } = await import('./workspace-admin-fixture.mjs')
const owner = await account('scope_owner')
const member = await account('scope_member')
const outsider = await account('scope_other')
const workspace = data(await owner.client.rpc('st_v2_create_workspace',{p_name:'Scoped room and files '+suffix}))
for (const person of [member, outsider]) {
  data(await owner.client.rpc('st_v2_invite',{p_workspace:workspace,p_handle:person.handle}))
  const invite = data(await person.client.from('st_v2_invites').select('id').eq('workspace_id',workspace).single())
  data(await person.client.rpc('st_v2_reply_invite',{p_invite:invite.id,p_accept:true}))
}
const room=randomUUID()
const file=randomUUID()
const post=randomUUID()
const filename='scoped-file-'+suffix+'.txt'
const roomName='Eligible moderated room '+suffix
const bytes=Buffer.from('Private managed workspace attachment '+suffix)
const obj=workspace+'/'+file
function sql(statement) {
  execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres'],
    { input:statement,windowsHide:true })
}
data(await owner.client.rpc('st_v6_room_create',{p_id:room,p_workspace:workspace,p_name:roomName,p_kind:'private',p_template:'blank'}))
data(await owner.client.rpc('st_v6_room_membership',{p_room:room,p_action:'invite',p_target:member.id,p_role:'member'}))
data(await member.client.rpc('st_v6_room_membership',{p_room:room,p_action:'accept'}))
data(await owner.client.rpc('st_v6_room_post',{p_room:room,p_id:post,p_body:'Synthetic moderation target'}))
sql("insert into sectalk_private.st_v6_workspace_files(workspace,id,uploader,filename,size_bytes,published_at) values('" +
  workspace+"','"+file+"','"+owner.id+"','"+filename+"',"+bytes.length+",now());")
const storage=admin.storage.from('sectalk-workspace-files')
data(await storage.upload(obj,bytes,{contentType:'application/octet-stream'}))

const browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
const btn=(scope,name)=>scope.getByRole('button',{name,exact:true})
const nav=page=>page.getByRole('navigation',{name:'SecTalk features'})
async function open(person) {
  const page=await browser.newPage({acceptDownloads:true})
  await page.goto(new URL('/#account',app).href,{waitUntil:'domcontentloaded'})
  await page.getByLabel('Email address',{exact:true}).fill(person.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await btn(nav(page),'Workspaces').click()
  return page
}
const action=(actor,name)=>actor.client.rpc('st_v6_room_settings',{p_room:room,p_action:name,p_post:post})
const decision=(actor,op)=>actor.client.rpc('st_v7_explain_file_egress',{p_scope_type:'workspace',p_scope:workspace,p_file:file,p_operation:op})
try {
  const a=await open(owner)
  const b=await open(member)
  await btn(a,'Custom roles').click()
  const panel=a.getByRole('region',{name:'Workspace custom roles'})
  await verifyStaffPanel(panel)
  async function create(scope,name,target,permissions) {
    await panel.getByRole('combobox',{name:/Custom role/}).selectOption('')
    await panel.getByLabel('Resource type').selectOption(scope)
    await panel.getByLabel('Role name').fill(name)
    await panel.getByRole('combobox',{name:scope==='room'?/Room to moderate/:/Workspace file/}).selectOption(target)
    for(const permission of permissions) await panel.getByRole('checkbox',{name:permission,exact:true}).check()
    await btn(panel,'Save role revision').click()
    await panel.getByText('Role revision saved.',{exact:true}).waitFor()
  }
  async function assign(person) {
    await panel.getByRole('combobox',{name:/Assign to member/}).selectOption(person.id)
    await btn(panel,'Assign role').click()
    await panel.getByText('Role assigned.',{exact:true}).waitFor()
  }
  await create('room','Classroom-independent moderator',room,['Pin messages','Unpin messages','Change slow mode'])
  await assign(member)
  await assign(outsider)
  assert.equal((await action(outsider,'pin')).error?.code,'42501')
  assert.equal((await action(member,'lock')).error?.code,'42501')
  await btn(nav(b),'Rooms').click()
  await b.getByRole('button',{name:new RegExp(roomName)}).click()
  const roomPanel=b.getByRole('region',{name:roomName,exact:true})
  const message=roomPanel.getByRole('article').filter({hasText:'Synthetic moderation target'})
  await btn(message,'Pin').click()
  await btn(message,'Unpin').click()
  await btn(message,'Pin').waitFor()
  await roomPanel.getByLabel('Slow mode in seconds',{exact:true}).fill('20')
  const slowSaved=b.waitForResponse(response=>response.ok()&&response.url().endsWith('/rpc/st_v6_room_settings'))
  await btn(roomPanel,'Save slow mode').click()
  await slowSaved
  const saved=data(await owner.client.from('st_v6_rooms').select('slow_seconds').eq('id',room).single())
  assert.equal(saved.slow_seconds,20)
  await panel.getByRole('list',{name:'Role assignments'}).getByRole('listitem').filter({hasText:member.handle})
    .getByRole('button',{name:'Revoke role'}).click()
  await panel.getByText('Role revoked.',{exact:true}).waitFor()
  assert.equal((await action(member,'pin')).error?.code,'42501')

  await create('file','Privately shared file reader',file,['Download workspace file','Create private workspace file link'])
  await btn(panel,'Require a custom role for this file').click()
  await panel.getByText('File protection updated.',{exact:true}).waitFor()
  assert.deepEqual(data(await decision(member,'download')).reasons,['custom_role_required'])
  await btn(nav(b),'Workspaces').click()
  await btn(b.getByRole('group',{name:'Workspace sections'}),'Files').click()
  await b.getByRole('article').filter({hasText:filename}).getByRole('button',{name:'View file details'}).click()
  const details=b.getByRole('region',{name:'Workspace file details'})
  await btn(details,'Check download access').click()
  await details.getByText('This file requires a matching custom role.',{exact:true}).waitFor()
  await assign(member)
  await btn(details,'Copy workspace link').click()
  await details.getByRole('textbox',{name:'Workspace file link'}).waitFor()
  const response=b.waitForEvent('download')
  await btn(details,'Download workspace file').click()
  assert.deepEqual(await readFile(await (await response).path()),bytes)
  await btn(a,'File policy').click()
  const filePolicy=a.getByRole('region',{name:'Workspace file policy'})
  await filePolicy.getByRole('combobox').first().selectOption('block')
  await btn(filePolicy,'Save file policy').click()
  await filePolicy.getByText('File policy saved.',{exact:true}).waitFor()
  assert.deepEqual(data(await decision(member,'download')).reasons,['tenant_block'])
  assert.deepEqual(data(await decision(member,'share')).reasons,['tenant_block'])
  await filePolicy.getByRole('combobox').first().selectOption('inherit')
  await btn(filePolicy,'Save file policy').click()
  await filePolicy.getByText('File policy saved.',{exact:true}).waitFor()
  await btn(a,'Custom roles').click()
  await panel.getByRole('combobox',{name:/Custom role/}).selectOption({label:'Privately shared file reader'})
  await btn(panel,'Revoke role').click()
  await panel.getByText('Role revoked.',{exact:true}).waitFor()
  await btn(details,'Check download access').click()
  await details.getByText('This file requires a matching custom role.',{exact:true}).waitFor()
  console.log('Passed actual room moderation, selected-file bytes and private link, existing SEC-02 deny precedence and revocation.')
} finally {
  await browser.close()
  await storage.remove([obj])
  await Promise.allSettled([owner,member,outsider].map(person=>admin.auth.admin.deleteUser(person.id)))
}
