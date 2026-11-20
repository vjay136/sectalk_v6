import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { createClient } from '@supabase/supabase-js'
import { fixtureAuthenticator, verifyStaffPanel } from './workspace-admin-fixture.mjs'

const origin = new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
const app = new URL(process.env.SECTALK_STORAGE_TEST_APP).origin
assert.equal(origin,'http://127.0.0.1:55321')
assert.equal(new URL(app).hostname,'127.0.0.1')
const key = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const service = createClient(origin,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,{
  ...options, global:{ fetch:(input,init) => fetch(input,{ ...init,signal:AbortSignal.timeout(15000) }) },
})
const storage = service.storage.from('sectalk-exports')
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const password = randomUUID() + '!1Q'
const run = randomUUID().slice(0,8)
const users = []
const workspaces = []
let browser
const sha = input => createHash('sha256').update(input).digest('hex')
function data(result) {
  if (result.error) throw result.error
  return result.data
}
function sql(statement) {
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At',
    '-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres'],{ input: statement, encoding: 'utf8', windowsHide: true }).trim()
}
async function account(role) {
  const handle = 'ev_' + role + '_' + run
  const email = handle + '@example.invalid'
  const { user } = data(await service.auth.admin.createUser({ email,password,email_confirm:true }))
  users.push(user.id)
  const client = createClient(origin,key,options)
  data(await client.auth.signInWithPassword({ email,password }))
  data(await client.rpc('st_save_profile',{ p_handle:handle,p_name:'Evidence QA ' + role }))
  return { id:user.id,email,handle,client }
}
async function createTenant(owner,name) {
  const id = data(await owner.client.rpc('st_v2_create_workspace',{ p_name:name }))
  workspaces.push(id)
  return id
}
const sections = page => page.getByRole('group',{ name:'Workspace sections' })
const vault = page => page.getByRole('region',{ name:'Evidence vault',exact:true })
async function verify(page,actor) {
  await page.goto(app)
  await page.getByLabel('Email address',{ exact:true }).fill(actor.email)
  await page.getByLabel('Password',{ exact:true }).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation',{ name:'SecTalk features' }).getByRole('button',{ name:'Workspaces',exact:true }).click()
  await sections(page).getByRole('button',{ name:'Compliance exports',exact:true }).click()
  await verifyStaffPanel(page)
  await page.getByRole('button',{ name:'Refresh export cases',exact:true }).waitFor()
  return page.evaluate(() => {
    const auth = Object.keys(localStorage).find(name => /^sb-.+-auth-token$/.test(name))
    return JSON.parse(localStorage.getItem(auth)).access_token
  })
}
const client = token => createClient(origin,key,{ ...options,global:{ headers:{ Authorization:'Bearer ' + token } } })
const call = (token,snapshot,input) => fetch(app + '/api/evidence-vault' + (snapshot ? '?snapshot=' + snapshot : ''),{
  method: input ? 'POST' : 'GET',headers:{ Authorization:'Bearer ' + token,...(input ? {'Content-Type':'application/json'} : {}) },
  body: input ? JSON.stringify(input) : undefined,
})

try {
  const [owner,admin,outside] = await Promise.all(['owner','admin','outside'].map(account))
  const tenant = await createTenant(owner,'Evidence QA ' + run)
  const otherTenant = await createTenant(outside,'Other evidence QA ' + run)
  data(await owner.client.rpc('st_v2_invite',{ p_workspace:tenant,p_handle:admin.handle }))
  const invite = data(await admin.client.from('st_v2_invites').select('id').eq('workspace_id',tenant).single())
  data(await admin.client.rpc('st_v2_reply_invite',{ p_invite:invite.id,p_accept:true }))
  sql("update public.st_v2_members set role='admin' where workspace_id='" + tenant + "' and user_id='" + admin.id + "';")
  const room = randomUUID()
  const roomName = 'Held evidence room ' + run
  data(await owner.client.rpc('st_v6_room_create',{ p_id:room,p_workspace:tenant,p_name:roomName,p_kind:'public',p_template:'blank' }))
  data(await admin.client.rpc('st_v6_room_membership',{ p_room:room,p_action:'join' }))
  const original = 'Exact consented evidence stayed unchanged in the vault.'
  async function report(text,shared) {
    const post = randomUUID()
    data(await owner.client.rpc('st_v6_room_post',{ p_room:room,p_id:post,p_body:text }))
    const id = data(await admin.client.rpc('st_v6_submit_room_report',{
      p_room:room,p_post:post,p_category:'threat',p_details:'Reporter-only note stays outside snapshot',p_share:shared,
    }))
    return { id,post }
  }
  const selected = await report(original,true)
  const unshared = await report('Unshared report is outside the vault.',false)

  await fixtureAuthenticator(outside.client)
  const outsideToken = data(await outside.client.auth.getSession()).session.access_token
  const foreignHold = randomUUID()
  data(await outside.client.rpc('st_v6_place_workspace_hold',{
    p_workspace:otherTenant,p_id:foreignHold,p_room:null,p_member:outside.id,p_from:null,p_until:null,
    p_reason:'Other tenant fixture preservation reason',
  }))
  assert.deepEqual(data(await outside.client.rpc('st_v7_evidence_vault',{ p_workspace:tenant })),{ access:'none' })
  browser = await chromium.launch({ executablePath:process.env.SECTALK_TEST_BROWSER })
  const [ownerPage,adminPage] = await Promise.all([browser.newPage(),browser.newPage()])
  const [ownerToken,adminToken] = await Promise.all([verify(ownerPage,owner),verify(adminPage,admin)])
  const ownerApi = client(ownerToken)
  const adminApi = client(adminToken)
  const reference = 'VAULT-' + run
  const caseId = data(await adminApi.rpc('st_v7_request_compliance_export',{
    p_workspace:tenant,p_reference:reference,p_reason:'Preserve the exact customer-shared evidence revision for this case.',
    p_sources:[{ kind:'room_report',id:selected.id }],
  }))
  const reason = 'Preserve this approved evidence under the active legal hold.'
  const wrongHold = randomUUID()
  data(await ownerApi.rpc('st_v6_place_workspace_hold',{
    p_workspace:tenant,p_id:wrongHold,p_room:room,p_member:admin.id,p_from:null,p_until:null,
    p_reason:'Wrong author in this preservation fixture',
  }))
  assert.equal((await call(adminToken,null,{ caseId,report:selected.id,hold:wrongHold,reason })).status,404)
  data(await ownerApi.rpc('st_v7_review_compliance_export',{
    p_case:caseId,p_action:'approved',p_reason:'Independently approved the exact shared room report in this case.',
  }))
  await sections(ownerPage).getByRole('button',{ name:'Governance',exact:true }).click()
  const holds = ownerPage.getByRole('region',{ name:'Legal holds',exact:true })
  await holds.getByText('Place a preservation hold',{ exact:true }).click()
  const placement = holds.locator('details').filter({ has:ownerPage.getByText('Place a preservation hold',{ exact:true }) })
  await placement.locator('[name=room]').selectOption(room)
  await placement.locator('[name=member]').selectOption(owner.id)
  const holdReason = 'Preserve original exact case evidence under room and author scope.'
  await placement.getByLabel('Preservation reason',{ exact:true }).fill(holdReason)
  await placement.getByRole('button',{ name:'Place hold',exact:true }).click()
  const active = holds.getByRole('article').filter({ has:ownerPage.getByText(holdReason,{ exact:true }) })
  await active.getByRole('heading',{ name:'Active hold',exact:true }).waitFor()
  const holdId = sql("select id from sectalk_private.st_v6_workspace_holds where workspace_id='" + tenant + "' and room_id='" + room
    + "' and member_id='" + owner.id + "';")
  assert.match(holdId,/^[a-f0-9-]{36}$/)
  for (const wrong of [
    { caseId,report:selected.id,hold:wrongHold,reason },
    { caseId,report:selected.id,hold:foreignHold,reason },
    { caseId,report:unshared.id,hold:holdId,reason },
    { caseId:randomUUID(),report:selected.id,hold:holdId,reason },
  ]) assert.equal((await call(adminToken,null,wrong)).status,404)
  assert.equal((await call(outsideToken,null,{ caseId,report:selected.id,hold:holdId,reason })).status,404)
  await sections(adminPage).getByRole('button',{ name:'Governance',exact:true }).click()
  await adminPage.getByText('Evidence vault',{ exact:true }).click()
  await vault(adminPage).getByLabel('Approved report and matching hold',{ exact:true }).selectOption([caseId,selected.id,holdId].join(':'))
  await vault(adminPage).getByLabel('Preservation reason',{ exact:true }).fill(reason)
  const captured = adminPage.waitForResponse(response => response.url().endsWith('/api/evidence-vault') && response.request().method()==='POST')
  await vault(adminPage).getByRole('button',{ name:'Preserve snapshot',exact:true }).click()
  const capture = await captured
  assert.equal(capture.status(),201,capture.ok() ? '' : await capture.text())
  await vault(adminPage).getByText('Evidence snapshot preserved.',{ exact:true }).waitFor()
  const snapshot = JSON.parse(sql("select jsonb_build_object('id',id,'sha256',sha256,'artifact',artifact)"
    + " from sectalk_private.st_v7_evidence_snapshots where case_id='" + caseId + "' and hold_id='" + holdId + "';"))
  const { artifact } = snapshot
  const saved = Buffer.from(await data(await storage.download(artifact)).arrayBuffer())
  assert.equal(sha(saved),snapshot.sha256)
  assert.equal(JSON.parse(saved.toString()).body,original)
  assert.ok(!saved.toString().includes('Reporter-only note'))
  assert.ok((await adminApi.storage.from('sectalk-exports').download(artifact)).error)
  assert.ok((await storage.remove([artifact])).error)
  assert.equal((await call(ownerToken,snapshot.id)).status,404)
  assert.equal((await call(outsideToken,snapshot.id)).status,404)
  assert.equal((await call(adminToken,null,{ caseId,report:selected.id,hold:holdId,reason })).status,409)

  sql("update public.st_v6_room_posts set body='Changed source body after capture',edited_at=clock_timestamp()"
    + " where room_id='" + room + "' and id='" + selected.post + "';")
  assert.equal(sql("select count(*) from sectalk_private.st_v6_preserved_post_versions where hold_id='" + holdId + "';"),'1')
  const article = vault(adminPage).getByRole('article').filter({ has:adminPage.getByRole('heading',{ name:reference,exact:true }) })
  await article.getByText(holdId,{ exact:true }).waitFor()
  const downloading = adminPage.waitForEvent('download')
  await article.getByRole('button',{ name:'Download evidence snapshot',exact:true }).click()
  assert.deepEqual(await readFile(await (await downloading).path()),saved)
  sql("update sectalk_private.st_v6_room_reports set share_with_workspace=false where id='" + selected.id + "';")
  assert.equal((await call(adminToken,snapshot.id)).status,404)
  sql("update sectalk_private.st_v6_room_reports set share_with_workspace=true where id='" + selected.id + "';"
    + " update sectalk_private.st_v7_compliance_cases set expires_at=now()-interval '1 minute' where id='" + caseId + "';")
  assert.equal((await call(adminToken,snapshot.id)).status,404)
  assert.equal(sql("select expires_at='infinity' from sectalk_private.st_v6_export_objects where id='" + artifact + "';"),'t')
  sql("update sectalk_private.st_v7_compliance_cases set expires_at=approved_at+interval '24 hours' where id='" + caseId + "';")

  await active.getByRole('button',{ name:'Release hold',exact:true }).click()
  await active.getByLabel('Release reason',{ exact:true }).fill('Preservation review completed and this hold can now be released.')
  await active.getByRole('button',{ name:'Confirm release',exact:true }).click()
  await active.getByRole('heading',{ name:'Released hold',exact:true }).waitFor()
  assert.equal((await call(adminToken,snapshot.id)).status,404)
  assert.equal(sql("select expires_at<=now() from sectalk_private.st_v6_export_objects where id='" + artifact + "';"),'t')
  await vault(adminPage).getByRole('button',{ name:'Refresh evidence vault',exact:true }).click()
  await article.getByText(/Hold ended/).waitFor()
  await article.getByText('Chain of custody',{ exact:true }).click()
  await article.getByText('Hold released',{ exact:true }).waitFor()
  const state = data(await adminApi.rpc('st_v7_evidence_vault',{ p_workspace:tenant }))
  const events = state.snapshots.find(item => item.id===snapshot.id).custody.reverse()
  let previous = '0'.repeat(64)
  assert.deepEqual(events.map(entry => {
    assert.equal(entry.previous_sha256,previous)
    assert.equal(entry.sha256,sha(previous + entry.payload))
    previous = entry.sha256
    return JSON.parse(entry.payload).event
  }),['captured','downloaded','hold_released'])
  data(await storage.remove([artifact]))
  assert.ok((await storage.download(artifact)).error)
} finally {
  await browser?.close()
  for (const id of workspaces) {
    sql("update sectalk_private.st_v6_workspace_holds set released_at=clock_timestamp(),release_reason='Dispose exact QA fixture'"
      + " where workspace_id='" + id + "' and released_at is null;")
    const artifacts = sql("select artifact from sectalk_private.st_v7_evidence_snapshots where workspace_id='" + id + "';")
    if (artifacts) data(await storage.remove(artifacts.split(/\r?\n/)))
    sql("delete from sectalk_private.st_v6_export_objects a using sectalk_private.st_v7_evidence_snapshots s"
      + " where a.id=s.artifact and s.workspace_id='" + id + "'; begin; set local session_replication_role=replica;"
      + " delete from sectalk_private.st_v7_evidence_custody c using sectalk_private.st_v7_evidence_snapshots s"
      + " where c.snapshot_id=s.id and s.workspace_id='" + id + "'; delete from sectalk_private.st_v7_evidence_snapshots"
      + " where workspace_id='" + id + "'; commit; delete from sectalk_private.st_v7_compliance_audit where workspace_id='" + id + "';"
      + " delete from sectalk_private.st_v6_room_reports where workspace_id='" + id + "'; delete from public.st_v2_workspaces where id='" + id + "';")
  }
  for (const user of users) sql("delete from auth.users where id='" + user + "';")
}
console.log('Passed exact approved evidence and hold matching, immutable private Storage, original revision download, consent and case expiry, hold release, and chained custody.')
