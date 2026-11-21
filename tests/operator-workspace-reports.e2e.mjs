import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { fixtureAuthenticator, totpCode } from './workspace-admin-fixture.mjs'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const database = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(database.origin, 'http://127.0.0.1:55321')
const auth = {persistSession:false,autoRefreshToken:false}
const service = createClient(database.origin,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,{auth})
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const {chromium} = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const password = randomUUID()+'!5Qa'
const run = randomUUID().slice(0,8)
const actors = []
const workspaces = []
let staff, browser

function data(result) {if (result.error) throw result.error; return result.data}

function sql(statement) {
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true}).trim()
}

async function account(name, operator=false) {
  const handle='wr_'+name+'_'+run, email=handle+'@example.invalid'
  const {user}=data(await service.auth.admin.createUser({email,password,email_confirm:true}))
  assert.match(user.id,/^[a-f0-9-]{36}$/)
  actors.push(user.id)
  const client=createClient(database.origin,publicKey,{auth})
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:handle}))
  return {id:user.id,handle,email,client,factor:operator?await fixtureAuthenticator(client):null}
}

async function workspace(actor,name) {
  const id=data(await actor.client.rpc('st_v2_create_workspace',{p_name:name+' '+run}))
  assert.match(id,/^[a-f0-9-]{36}$/)
  workspaces.push(id)
  return id
}

async function operator(actor) {
  const page=await browser.newPage()
  await page.goto(app.href)
  await page.getByLabel('Email',{exact:true}).fill(actor.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.getByRole('button',{name:'Sign in',exact:true}).click()
  await page.getByRole('heading',{name:'Verify your authenticator'}).waitFor()
  await page.getByLabel('Authenticator code',{exact:true}).fill(await totpCode(actor.factor.secret))
  await page.getByRole('button',{name:'Verify code',exact:true}).click()
  const tabs=page.getByRole('group',{name:'Operator sections'})
  await tabs.getByRole('button',{name:'Workspace reports',exact:true}).click()
  return {page,tabs}
}

async function roomAction(panel, action) {
  await panel.getByRole('combobox',{name:'Review action',exact:true}).selectOption(action)
  await panel.getByLabel('Review reason',{exact:true}).fill('Disposable room workflow '+run)
  await panel.getByRole('button',{name:'Update room report',exact:true}).click()
  await panel.getByText('Room report updated.',{exact:true}).waitFor()
}

async function channelAction(panel, action) {
  await panel.getByLabel('Channel review decision',{exact:true}).selectOption(action)
  await panel.getByLabel('Decision reason',{exact:true}).fill('Disposable channel workflow '+run)
  await panel.getByRole('button',{name:'Save channel decision',exact:true}).click()
}

try {
  const home=await fetch(app)
  assert.equal(home.status,200)
  assert.equal(home.headers.get('x-content-type-options'),'nosniff')
  assert.equal(home.headers.get('x-frame-options'),'DENY')
  assert.equal(home.headers.get('referrer-policy'),'no-referrer')
  assert.equal(home.headers.get('permissions-policy'),'camera=(), microphone=(), display-capture=(), geolocation=()')
  const [owner,other,platform,author,reporter]=await Promise.all([
    account('owner',true),account('other',true),account('platform',true),account('author'),account('reporter'),
  ])
  staff=platform.id
  sql(`insert into sectalk_private.staff(user_id) values('${staff}');
    insert into sectalk_private.st_v6_case_on_call(user_id,tier,starts_at,ends_at) values
      ('${staff}',1,now(),now()+interval '1 hour'),('${staff}',2,now(),now()+interval '1 hour');`)
  const space=await workspace(owner,'Operator report workspace')
  await workspace(other,'Unrelated report workspace')
  for (const person of [author,reporter]) {
    data(await owner.client.rpc('st_v2_invite',{p_workspace:space,p_handle:person.handle}))
    const invite=data(await person.client.from('st_v2_invites').select('id').eq('workspace_id',space).single())
    data(await person.client.rpc('st_v2_reply_invite',{p_invite:invite.id,p_accept:true}))
  }
  const room=randomUUID(), roomName='Operator report room '+run
  const channelName='ops-report-'+run
  const channel=data(await owner.client.rpc('st_v2_create_channel',{p_workspace:space,p_name:channelName}))
  data(await owner.client.rpc('st_v6_room_create',{p_id:room,p_workspace:space,p_name:roomName,p_kind:'public',p_template:'blank'}))
  for (const person of [author,reporter]) data(await person.client.rpc('st_v6_room_membership',{p_room:room,p_action:'join'}))
  const roomPost=randomUUID(), channelPost=randomUUID()
  const roomEvidence='Consented room evidence '+run, channelEvidence='Consented channel evidence '+run
  const privateNotes='Private reporter notes '+run
  data(await author.client.rpc('st_v6_room_post',{p_room:room,p_id:roomPost,p_body:roomEvidence}))
  data(await author.client.rpc('st_v2_post',{p_channel:channel,p_id:channelPost,p_body:channelEvidence}))
  const roomCase=data(await reporter.client.rpc('st_v6_submit_room_report',{p_room:room,p_post:roomPost,p_category:'spam',
    p_details:privateNotes,p_share:true}))
  const channelCase=data(await reporter.client.rpc('st_v7_submit_channel_report',{p_channel:channel,p_post:channelPost,p_category:'spam',
    p_details:privateNotes,p_share_with_safety:true,p_share_with_workspace:true}))
  assert.match(roomCase,/^[a-f0-9-]{36}$/)
  assert.match(channelCase,/^[a-f0-9-]{36}$/)
  assert.equal((await owner.client.rpc('st_v6_room_report_queue',{p_scope:'platform'})).error?.code,'42501')
  assert.equal((await reporter.client.rpc('st_v7_channel_report_queue',{p_scope:'workspace'})).error?.code,'42501')
  const noToken=await fetch(new URL('/api/managed-room-evidence/'+roomCase,app))
  assert.equal(noToken.status,401)

  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const [safety,tenant,foreign]=await Promise.all([operator(platform),operator(owner),operator(other)])
  const reportedRoom=safety.page.getByRole('region',{name:'Platform room reports'})
  const workspaceRoom=tenant.page.getByRole('region',{name:'Workspace room reports'})
  const foreignRoom=foreign.page.getByRole('region',{name:'Workspace room reports'})
  assert.equal(await tenant.tabs.getByRole('button',{name:'Moderation',exact:true}).count(),0)
  assert.equal(await tenant.page.getByRole('button',{name:'Platform Safety',exact:true}).count(),0)
  assert.equal(await safety.page.getByRole('button',{name:'Workspace',exact:true}).count(),0)
  await workspaceRoom.getByText('No room reports to review.',{exact:true}).waitFor()
  await reportedRoom.getByRole('button',{name:new RegExp(roomName)}).click()
  await reportedRoom.getByText(privateNotes,{exact:true}).waitFor()
  await roomAction(reportedRoom,'route')
  await roomAction(reportedRoom,'acknowledge')
  await roomAction(reportedRoom,'route')
  await roomAction(reportedRoom,'acknowledge')
  await roomAction(reportedRoom,'route')
  await workspaceRoom.getByRole('button',{name:'Refresh room reports',exact:true}).click()
  await workspaceRoom.getByRole('button',{name:new RegExp(roomName)}).click()
  await workspaceRoom.getByText(roomEvidence,{exact:true}).waitFor()
  assert.equal(await workspaceRoom.getByText(privateNotes,{exact:true}).count(),0)
  await roomAction(workspaceRoom,'acknowledge')
  await roomAction(workspaceRoom,'resolved')
  await foreignRoom.getByRole('button',{name:'Refresh room reports',exact:true}).click()
  await foreignRoom.getByText('No room reports to review.',{exact:true}).waitFor()

  for (const view of [safety,tenant,foreign]) await view.page.getByRole('button',{name:'Channel reports',exact:true}).click()
  const platformChannel=safety.page.getByRole('region',{name:'Channel report queue'}).locator('details').filter({hasText:channelName})
  await platformChannel.locator('summary').click()
  await platformChannel.getByText(privateNotes,{exact:true}).waitFor()
  await channelAction(platformChannel,'handoff')
  const localChannel=tenant.page.getByRole('region',{name:'Channel report queue'}).locator('details').filter({hasText:channelName})
  await localChannel.locator('summary').click()
  await localChannel.getByText(channelEvidence,{exact:true}).waitFor()
  assert.equal(await localChannel.getByText(privateNotes,{exact:true}).count(),0)
  await channelAction(localChannel,'resolved')
  await tenant.page.getByText('Channel report decision saved.',{exact:true}).waitFor()
  await foreign.page.getByText('No channel reports are available.',{exact:true}).waitFor()
  assert.equal(await foreign.page.getByText(channelEvidence,{exact:true}).count(),0)
  const roomStatus=data(await reporter.client.rpc('st_v7_my_room_report_status')).find(report => report.id===roomCase)
  const channelStatus=data(await reporter.client.rpc('st_v7_my_channel_reports')).find(report => report.id===channelCase)
  assert.equal(roomStatus.status,'resolved')
  assert.equal(roomStatus.decision_scope,'workspace')
  assert.equal(channelStatus.state,'resolved')
  assert.equal(sql(`select actor from sectalk_private.st_v7_channel_report_actions where report_id='${channelCase}' and action='resolved';`),owner.id)
  console.log('PASS standalone Platform Safety and workspace room/channel actions, scoped evidence, owner-only decisions and reporter outcomes')
} finally {
  await browser?.close()
  for (const id of workspaces) sql(`delete from sectalk_private.st_v6_room_reports where workspace_id='${id}';
    delete from sectalk_private.st_v7_channel_reports where workspace_id='${id}';
    delete from public.st_v2_workspaces where id='${id}';`)
  if (staff) sql(`delete from sectalk_private.staff where user_id='${staff}';`)
  for (const id of actors) data(await service.auth.admin.deleteUser(id))
}
