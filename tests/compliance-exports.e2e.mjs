import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { createClient } from '@supabase/supabase-js'
import { fixtureAuthenticator, verifyStaffPanel } from './workspace-admin-fixture.mjs'

const origin = new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
const app = new URL(process.env.SECTALK_STORAGE_TEST_APP).origin
assert.equal(origin, 'http://127.0.0.1:55321')
assert.equal(new URL(app).hostname, '127.0.0.1')
const key = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const service = createClient(origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const suffix = randomUUID().slice(0,8)
const password = randomUUID() + '!1A'
const exerciseKeys = process.env.SECTALK_KMS_QA === '1'
const exerciseRewrap = exerciseKeys && process.env.SECTALK_ARTIFACT_REWRAP_QA === '1'
const users = []
const workspaces = []
let artifact, browser
const digest = value => createHash('sha256').update(value).digest('hex')
function data(result) {
  if (result.error) throw result.error
  return result.data
}
function sql(statement) {
  return execFileSync('docker', ['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'], { input: statement, encoding: 'utf8', windowsHide: true }).trim()
}
async function account(role) {
  const handle = 'cex_' + role + '_' + suffix
  const email = handle + '@example.invalid'
  const { user } = data(await service.auth.admin.createUser({ email, password, email_confirm: true }))
  users.push(user.id)
  const client = createClient(origin, key, options)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: 'Compliance QA ' + role }))
  return { id: user.id, email, handle, client }
}
async function workspace(owner, name) {
  const id = data(await owner.client.rpc('st_v2_create_workspace', { p_name: name }))
  workspaces.push(id)
  return id
}
async function join(owner, chosen, id) {
  data(await owner.client.rpc('st_v2_invite', { p_workspace: id, p_handle: chosen.handle }))
  const invite = data(await chosen.client.from('st_v2_invites').select('id').eq('workspace_id', id).single())
  data(await chosen.client.rpc('st_v2_reply_invite', { p_invite: invite.id, p_accept: true }))
}
async function open(actor) {
  const page = await browser.newPage()
  await page.goto(app)
  await page.getByLabel('Email address', { exact: true }).fill(actor.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation', { name: 'SecTalk features' }).getByRole('button', { name: 'Workspaces', exact: true }).click()
  await page.getByRole('group', { name: 'Workspace sections' }).getByRole('button', { name: 'Compliance exports', exact: true }).click()
  await verifyStaffPanel(page)
  return page
}
function browserToken(page) {
  return page.evaluate(() => {
    const sessionKey = Object.keys(localStorage).find(key => /^sb-.+-auth-token$/.test(key))
    return JSON.parse(localStorage.getItem(sessionKey)).access_token
  })
}
const authClient = token => createClient(origin, key, { ...options, global: { headers: { Authorization: 'Bearer ' + token } } })
const panel = page => page.getByRole('region', { name: 'Compliance exports', exact: true })
const card = (page, name) => panel(page).getByRole('article').filter({
  has: page.getByRole('heading', { name, exact: true }),
})
const call = (path, token, method = 'GET') => fetch(app + path, {
  method, headers: { Authorization: 'Bearer ' + token },
})
async function decision(approval, label, reason) {
  await approval.getByRole('button', { name: label, exact: true }).click()
  await approval.getByLabel('Decision reason', { exact: true }).fill(reason)
  const recorded = approval.page().waitForResponse(response => response.url().endsWith('/rpc/st_v7_review_compliance_export'))
  await approval.getByRole('button', { name: 'Confirm ' + label.toLowerCase(), exact: true }).click()
  const response = await recorded
  assert.ok(response.ok(), response.ok() ? '' : await response.text())
}

try {
  const [owner, administrator, author, outsider] = await Promise.all(['owner','admin','author','outside'].map(account))
  const tenant = await workspace(owner,'Compliance tenant ' + suffix)
  const otherTenant = await workspace(outsider,'Other tenant ' + suffix)
  await join(owner,administrator,tenant)
  await join(owner,author,tenant)
  sql("update public.st_v2_members set role='admin' where workspace_id='" + tenant + "' and user_id='" + administrator.id + "';")
  const seed = (workspaceId, actorId, event) => sql("with added as (insert into public.st_v2_workspace_audit(workspace_id,actor,event)"
    + " values('" + workspaceId + "','" + actorId + "','" + event + "') returning id) select id from added;")
  const selectedAudit = seed(tenant,owner.id,'compliance.fixture.selected')
  const extraAudit = seed(tenant,owner.id,'compliance.fixture.unselected')
  const otherAudit = seed(otherTenant,outsider.id,'compliance.fixture.outside')
  const room = randomUUID()
  data(await owner.client.rpc('st_v6_room_create', {
    p_id: room, p_workspace: tenant, p_name: 'Compliance QA room', p_kind: 'public', p_template: 'blank',
  }))
  for (const member of [administrator,author]) {
    data(await member.client.rpc('st_v6_room_membership', { p_room: room, p_action: 'join' }))
  }
  async function report(body, shared) {
    const post = randomUUID()
    data(await author.client.rpc('st_v6_room_post', { p_room: room, p_id: post, p_body: body }))
    const id = data(await administrator.client.rpc('st_v6_submit_room_report', {
      p_room: room, p_post: post, p_category: 'threat', p_details: 'Reporter-only notes must remain outside the export.',
      p_share: shared,
    }))
    return { id, post, body }
  }
  const target = await report('Authorized evidence from the exact selected report.',true)
  const unselected = await report('Unselected shared room post must remain outside the export.',true)
  const privateReport = await report('Unshared room evidence must remain outside the export.',false)
  assert.equal((await administrator.client.rpc('st_v7_compliance_sources', { p_workspace: tenant })).error?.code,'42501')
  await fixtureAuthenticator(outsider.client)
  const outsiderToken = data(await outsider.client.auth.getSession()).session.access_token
  assert.equal((await outsider.client.rpc('st_v7_compliance_cases', { p_workspace: tenant })).error?.code,'42501')

  browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
  const [adminPage,ownerPage] = await Promise.all([open(administrator),open(owner)])
  await panel(adminPage).getByText('Request an export', { exact: true }).click()
  const request = panel(adminPage)
  const reference = 'QA case ' + suffix
  await request.getByLabel('Case reference', { exact: true }).fill(reference)
  await request.getByLabel('Case purpose', { exact: true }).fill('Review the exact workspace audit event and shared room report.')
  await request.getByRole('checkbox', { name: /compliance\.fixture\.selected/ }).check()
  await request.getByRole('checkbox', { name: new RegExp(target.id) }).check()
  assert.equal(await request.getByRole('checkbox', { name: new RegExp(privateReport.id) }).count(),0)
  await request.getByRole('button', { name: 'Submit export request', exact: true }).click()
  const ownCase = card(adminPage,reference)
  await ownCase.getByText('pending', { exact: true }).waitFor()
  const [adminToken,ownerToken] = await Promise.all([browserToken(adminPage),browserToken(ownerPage)])
  const verifiedAdmin = authClient(adminToken)
  const [created] = data(await verifiedAdmin.rpc('st_v7_compliance_cases', { p_workspace: tenant }))
  assert.ok(created.sources.every(source => !('sha256' in source)))
  const path = '/api/compliance-exports/' + created.id
  assert.equal((await call(path,adminToken,'POST')).status,404)
  assert.equal((await call(path,outsiderToken,'POST')).status,404)
  assert.equal((await verifiedAdmin.rpc('st_v7_review_compliance_export', {
    p_case: created.id, p_action: 'approved', p_reason: 'Requester attempts to approve its own scope.',
  })).error?.code,'42501')
  for (const source of [{ kind: 'room_report', id: privateReport.id },{ kind: 'audit', id: otherAudit }]) {
    assert.equal((await verifiedAdmin.rpc('st_v7_request_compliance_export', {
      p_workspace: tenant, p_reference: 'QA invalid scope', p_reason: 'Check exact source authorization boundaries.',
      p_sources: [source],
    })).error?.code,'42501')
  }

  await panel(ownerPage).getByRole('button', { name: 'Refresh export cases', exact: true }).click()
  const ownerCase = card(ownerPage,reference)
  await ownerCase.getByText(target.id, { exact: true }).waitFor()
  assert.equal(await ownerCase.getByText(target.body, { exact: true }).count(),0)
  await decision(ownerCase,'Approve exact records','Confirmed requested records and the stated case purpose.')
  await ownerCase.getByText('approved', { exact: true }).waitFor()
  assert.equal((await call(path,ownerToken,'POST')).status,404)
  await request.getByRole('button', { name: 'Refresh export cases', exact: true }).click()
  const building=adminPage.waitForResponse(response=>response.url().endsWith(path)&&response.request().method()==='POST')
  await ownCase.getByRole('button', { name: 'Build private bundle', exact: true }).click()
  const build=await building
  assert.equal(build.status(),200,build.ok()?'':await build.text())
  const download = ownCase.getByRole('button', { name: 'Download approved bundle', exact: true })
  await download.waitFor()
  artifact = sql("select artifact from sectalk_private.st_v7_compliance_cases where id='" + created.id + "';")
  assert.match(artifact,/^[0-9a-f-]{36}$/)
  assert.ok((await verifiedAdmin.storage.from('sectalk-exports').download(artifact)).error)
  assert.equal((await call('/api/exports/' + artifact,adminToken)).status,404)
  assert.equal((await call(path,outsiderToken)).status,404)
  assert.ok((await verifiedAdmin.rpc('st_v7_read_compliance_operation',{ p_ticket: randomUUID() })).error)
  const saving = adminPage.waitForEvent('download')
  await download.click()
  const bytes = await readFile(await (await saving).path())
  const stored = Buffer.from(await data(await service.storage.from('sectalk-exports').download(artifact)).arrayBuffer())
  assert.equal(bytes.length,stored.length)
  assert.notDeepEqual(bytes,stored)
  assert.ok(!stored.includes(Buffer.from(target.body)))
  const bundle = JSON.parse(bytes.toString('utf8'))
  assert.equal(digest(bundle.manifest),bundle.manifest_sha256)
  const manifest = JSON.parse(bundle.manifest)
  assert.equal(manifest.format,'sectalk-compliance-v1')
  assert.equal(manifest.case,created.id)
  assert.equal(manifest.workspace,tenant)
  assert.equal(manifest.requested_by,administrator.id)
  assert.equal(manifest.approved_by,owner.id)
  assert.deepEqual(manifest.entries.map(item => [item.kind,item.id]),[['audit',selectedAudit],['room_report',target.id]])
  assert.deepEqual(bundle.records.map(({json,...entry}) => {
    assert.equal(digest(json),entry.sha256)
    return entry
  }),manifest.entries)
  assert.equal(JSON.parse(bundle.records[1].json).body,target.body)
  const exportedText = bytes.toString('utf8')
  assert.ok(!manifest.entries.some(entry => [extraAudit,otherAudit].includes(entry.id)))
  for (const forbidden of [unselected.body,privateReport.body,'Reporter-only notes']) {
    assert.ok(!exportedText.includes(forbidden))
  }
  const [live] = data(await verifiedAdmin.rpc('st_v7_compliance_cases', { p_workspace: tenant }))
  assert.equal(live.bundle_sha256,digest(bytes))
  assert.equal(live.manifest_sha256,bundle.manifest_sha256)
  const tampered = Buffer.from(stored)
  tampered[tampered.length-1] ^= 1
  const exports = service.storage.from('sectalk-exports')
  data(await exports.update(artifact,tampered,{ contentType: 'application/json', cacheControl: '0' }))
  assert.equal((await call(path,adminToken)).status,404)
  data(await exports.update(artifact,stored,{ contentType: 'application/json', cacheControl: '0' }))

  if (exerciseKeys) {
    const originalEnvelope=exerciseRewrap ? sql(`select to_jsonb(e) from sectalk_private.st_v7_artifact_envelopes e where artifact='${artifact}';`) : null
    if(exerciseRewrap) {
      const policy=data(await authClient(ownerToken).rpc('st_v8_tenant_rotation_schedule',{p_workspace:tenant,p_days:30}))
      assert.equal(policy.schedule.days,30)
    }
    const legacy=randomUUID()
    sql(`insert into sectalk_private.st_v6_export_objects(id,actor_id,kind,scope_id,filename,media_type,bytes,sha256,ready)
      values('${legacy}','${administrator.id}','compliance','${created.id}','sectalk-compliance-export.json',
        'application/json',${bytes.length},'${digest(bytes)}',true);`)
    try {
      data(await exports.upload(legacy,bytes,{contentType:'application/json'}))
      sql(`update sectalk_private.st_v7_compliance_cases set artifact='${legacy}' where id='${created.id}';`)
      const old=await call(path,adminToken)
      assert.equal(old.status,200)
      assert.deepEqual(Buffer.from(await old.arrayBuffer()),bytes)
    } finally {
      sql(`update sectalk_private.st_v7_compliance_cases set artifact='${artifact}' where id='${created.id}';
        delete from sectalk_private.st_v6_export_objects where id='${legacy}';`)
      data(await exports.remove([legacy]))
    }
    const ownerKeys=ownerPage.getByRole('region',{name:'Managed artifact keys',exact:true})
    await ownerKeys.getByRole('button',{name:'Refresh key status',exact:true}).click()
    await ownerKeys.getByText('Version 1 · Managed custody',{exact:true}).waitFor()
    await ownerKeys.getByLabel('Key rotation reason',{exact:true}).fill('Activate the next synthetic tenant key version.')
    await ownerKeys.getByRole('button',{name:'Rotate workspace key',exact:true}).click()
    await ownerKeys.getByText('Workspace key version 2 is active.',{exact:true}).waitFor()
    if(exerciseRewrap) {
      assert.equal((await call(path,ownerToken)).status,404)
      const args={p_ticket:randomUUID(),p_artifact:artifact,p_policy_revision:randomUUID(),p_source_revision:'a'.repeat(64),
        p_previous:1,p_target:2,p_wrapped_dek:'A'.repeat(80)}
      assert.equal((await verifiedAdmin.rpc('st_v8_commit_protected_artifact_rewrap',args)).error?.code,'42501')
      assert.equal(data(await service.rpc('st_v8_commit_protected_artifact_rewrap',args)),false)
      assert.equal(sql(`select count(*) from sectalk_private.st_v8_protected_artifact_wraps where artifact='${artifact}';`),'0')
    }
    const afterRotation=await call(path,adminToken)
    assert.equal(afterRotation.status,200)
    assert.deepEqual(Buffer.from(await afterRotation.arrayBuffer()),bytes)
    if(exerciseRewrap) {
      assert.equal(sql(`select to_jsonb(e) from sectalk_private.st_v7_artifact_envelopes e where artifact='${artifact}';`),originalEnvelope)
      assert.equal(sql(`select kind||':'||previous_version||':'||wrapping_version from sectalk_private.st_v8_protected_artifact_rewrap_audit
        where artifact='${artifact}';`),'compliance:1:2')
      const afterRewrap=await call(path,adminToken)
      assert.equal(afterRewrap.status,200)
      assert.deepEqual(Buffer.from(await afterRewrap.arrayBuffer()),bytes)
      assert.deepEqual(Buffer.from(await data(await exports.download(artifact)).arrayBuffer()),stored)
      console.log('Passed ticket-bound compliance rewrap with exact private Storage bytes and denied owner and stale tickets.')
    }
    const rotate=async (workspace,token,custody='managed')=>fetch(app+'/api/tenant-keys',{
      method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},
      body:JSON.stringify({workspace,custody,reason:'Disposable tenant custody test rotation.'}),
    })
    assert.equal((await rotate(tenant,outsiderToken)).status,403)
    assert.equal((await rotate(otherTenant,outsiderToken,'byok')).status,403)
    assert.equal((await rotate(otherTenant,outsiderToken)).status,200)
    assert.equal(sql(`select count(*) from sectalk_private.st_v7_tenant_key_versions where workspace='${tenant}';`),'2')
    const hold=randomUUID()
    sql(`insert into sectalk_private.st_v7_tenant_destroy_reviewers values('${tenant}','${administrator.id}');
      insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
        values('${hold}','${tenant}','${administrator.id}','Retain synthetic evidence until review ends','${owner.id}');`)
    try {
      await ownerKeys.getByRole('button',{name:'Refresh key status',exact:true}).click()
      await ownerKeys.getByText('Managed key destruction',{exact:true}).click()
      await ownerKeys.getByLabel('Confirm the workspace ID',{exact:true}).fill(tenant)
      await ownerKeys.getByLabel('Key destruction reason',{exact:true}).fill('Request destruction solely for this disposable fixture.')
      await ownerKeys.getByRole('button',{name:'Request managed key destruction',exact:true}).click()
      await ownerKeys.getByText('Destruction requested. A separate reviewer must decide.',{exact:true}).waitFor()
      const requestId=sql(`select id from sectalk_private.st_v7_tenant_key_destroy where workspace='${tenant}';`)
      const args={p_request:requestId,p_approve:true,p_confirmation:tenant,p_reason:'Verify synthetic hold and independent review.'}
      assert.equal((await authClient(ownerToken).rpc('st_v7_decide_tenant_key_destroy',args)).error?.code,'42501')
      assert.equal((await authClient(outsiderToken).rpc('st_v7_decide_tenant_key_destroy',args)).error?.code,'42501')
      assert.equal((await verifiedAdmin.rpc('st_v7_decide_tenant_key_destroy',args)).error?.code,'PT409')
      sql(`update sectalk_private.st_v6_workspace_holds set released_at=now(),released_by='${owner.id}',
        release_reason='End the synthetic key custody test hold' where id='${hold}';`)
      const adminKeys=adminPage.getByRole('region',{name:'Managed artifact keys',exact:true})
      await adminKeys.getByRole('button',{name:'Refresh key status',exact:true}).click()
      await adminKeys.getByText('Managed key destruction',{exact:true}).click()
      await adminKeys.getByLabel('Key destruction decision',{exact:true}).selectOption('approve')
      await adminKeys.getByLabel('Confirm the workspace ID',{exact:true}).fill(tenant)
      await adminKeys.getByLabel('Key destruction reason',{exact:true}).fill('Approved exact disposable tenant and confirmed hold release.')
      await adminKeys.getByRole('button',{name:'Apply key destruction decision',exact:true}).click()
      await adminKeys.getByText('Managed key copies have been destroyed.',{exact:true}).waitFor()
      assert.equal(sql(`select count(*) from sectalk_private.st_v7_tenant_key_versions where workspace='${tenant}';`),'0')
      assert.equal(sql(`select count(*) from sectalk_private.st_v7_tenant_key_versions where workspace='${otherTenant}';`),'1')
      assert.equal((await call(path,adminToken)).status,404)
      assert.deepEqual(Buffer.from(await data(await exports.download(artifact)).arrayBuffer()),stored)
      assert.equal((await rotate(tenant,ownerToken)).status,409)
    } finally {
      sql(`delete from sectalk_private.st_v6_workspace_holds where id='${hold}';`)
    }
  }

  sql("update public.st_v6_room_posts set body='Edited evidence revision',edited_at=clock_timestamp() where room_id='" + room
    + "' and id='" + target.post + "';")
  assert.equal((await call(path,adminToken)).status,404)
  await decision(ownerCase,'Revoke export','The authorized case export should now be closed and removed.')
  assert.equal((await call(path,adminToken)).status,404)
  assert.equal(sql("select expires_at<=now() from sectalk_private.st_v6_export_objects where id='" + artifact + "';"),'t')
  assert.equal(sql("select string_agg(action,',' order by id) from sectalk_private.st_v7_compliance_audit where case_id='" + created.id + "';"),
    'requested,approved,built,downloaded' + (exerciseKeys ? ',downloaded,downloaded' : '') + (exerciseRewrap ? ',downloaded' : '') + ',revoked')
} finally {
  await browser?.close()
  if (artifact) {
    data(await service.storage.from('sectalk-exports').remove([artifact]))
    sql("delete from sectalk_private.st_v6_export_objects where id='" + artifact + "';")
  }
  for (const id of workspaces) sql("delete from sectalk_private.st_v7_compliance_audit where workspace_id='" + id
    + "'; begin; set local session_replication_role=replica; delete from sectalk_private.st_v7_tenant_key_audit where workspace='" + id
    + (exerciseRewrap ? `'; delete from sectalk_private.st_v8_protected_artifact_rewrap_audit where workspace='${id}` : '')
    + "'; commit; delete from sectalk_private.st_v7_tenant_key_destroy where workspace='" + id
    + "'; delete from sectalk_private.st_v7_tenant_key_versions where workspace='" + id
    + "'; delete from sectalk_private.st_v7_tenant_key_state where workspace='" + id
    + "'; delete from public.st_v2_workspaces where id='" + id + "';")
  for (const user of users) sql("delete from auth.users where id='" + user + "';")
}
console.log('Passed two-person approval, exact report and audit scope, hashed manifest, private Storage, denied access, revision revalidation, revocation, and durable audit.')
