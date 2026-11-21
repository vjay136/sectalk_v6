import assert from 'node:assert/strict'
import { execFileSync, spawn } from 'node:child_process'
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { resolve } from 'node:path'
import { setTimeout } from 'node:timers/promises'
import { createClient } from '@supabase/supabase-js'
import { fixtureAuthenticator, totpCode } from './workspace-admin-fixture.mjs'

const database = new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
assert.equal(database, 'http://127.0.0.1:55321')
const webOrigin = 'http://127.0.0.1:3593'
const operatorOrigin = 'http://127.0.0.1:3597'
const key = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const service = process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
const auth = {persistSession: false, autoRefreshToken: false}
const admin = createClient(database, service, {auth})
const {chromium} = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const password = randomUUID() + '1!Qa'
const accounts = []
const children = []
let browser, reportId

function data(result) {
  if (result.error) throw result.error
  return result.data
}

function sql(statement) {
  return execFileSync('docker', ['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'], {input: statement, encoding: 'utf8', windowsHide: true}).trim()
}

async function person(role) {
  const handle = 'disc_' + role + '_' + randomUUID().slice(0,8)
  const email = handle + '@example.invalid'
  const {user} = data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  accounts.push(user.id)
  const client = createClient(database, key, {auth})
  const {session: passwordSession} = data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile', {p_handle:handle,p_name:handle}))
  return {id:user.id,email,passwordSession,factor:await fixtureAuthenticator(client)}
}

function queue(session, input) {
  return fetch(operatorOrigin+'/api/security/disclosure/queue', {method:'POST',
    headers:{Authorization:'Bearer '+session.access_token,'Content-Type':'application/json'},body:JSON.stringify(input)})
}

async function start(directory, origin, common, extra) {
  const child = spawn(process.execPath, [resolve('node_modules/next/dist/bin/next'),'start', '--hostname','127.0.0.1',
    '--port',new URL(origin).port], {cwd:resolve(directory),stdio:'inherit',env:{...process.env,...common,...extra}})
  children.push(child)
  for (let attempt=0; attempt<40 && child.exitCode===null; attempt++) {
    if (await fetch(origin+'/api/ready',{signal:AbortSignal.timeout(2000)}).then(response=>response.ok).catch(()=>false)) return
    await setTimeout(500)
  }
  throw new Error('Local production server did not become ready at '+origin)
}

try {
  const common={NEXT_PUBLIC_SUPABASE_URL:database,NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:key,
    SECTALK_DISCLOSURE_ENCRYPTION_KEY:randomBytes(32).toString('base64url'),SECTALK_DISCLOSURE_TEST_LOOPBACK:'yes'}
  const expires=new Date(Math.floor(Date.now()/1000)*1000+86400000).toISOString().replace('.000Z','Z')
  const [, , reviewer,mod,ordinary] = await Promise.all([
    start(process.env.SECTALK_DISCLOSURE_WEB_BUILD || 'apps/web',webOrigin,common,{
      SECTALK_APP_URL:'https://disclosure-qa.example.invalid',SECTALK_DISCLOSURE_SERVICE_KEY:service,
      SECTALK_SECURITY_CONTACT_EXPIRES:expires,SECTALK_SECURITY_CONTACT:undefined}),
    start('apps/admin',operatorOrigin,common,{SECTALK_APP_URL:operatorOrigin,SECTALK_DISCLOSURE_SERVICE_KEY:undefined}),
    person('reviewer'),person('moderator'),person('ordinary'),
  ])
  sql(`insert into sectalk_private.staff(user_id) values('${reviewer.id}'),('${mod.id}');
    insert into sectalk_private.st_v8_disclosure_operators(account) values('${reviewer.id}');`)

  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const publicPage=await browser.newPage()
  const title='Synthetic disclosure '+randomUUID()
  await publicPage.goto(webOrigin+'/security/report')
  await publicPage.getByLabel('Title').fill(title)
  await publicPage.getByLabel('Affected feature or version').fill('Synthetic intake verification')
  await publicPage.getByLabel('Report details').fill('Standalone console case. Contains no real credentials or accounts.')
  await publicPage.getByRole('button',{name:'Submit private report'}).click()
  await publicPage.getByText('Report received. Save this receipt for your records.').waitFor()
  const receipt=(await publicPage.getByRole('status').locator('code').textContent()).trim()
  const hash=createHash('sha256').update(receipt).digest('hex')
  reportId=sql(`select id from sectalk_private.st_v8_disclosure_intake where receipt_hash='${hash}';`)
  assert.match(reportId,/^[0-9a-f-]{36}$/)
  const openBody={action:'open',id:reportId}
  for (const session of [ordinary.factor.session,mod.factor.session,reviewer.passwordSession]) {
    const denied=await queue(session, openBody)
    assert.equal(denied.status,403)
    assert.ok(!(await denied.text()).includes(title))
  }
  const moderateAccess = await fetch(operatorOrigin+'/api/operator/access', {
    headers:{Authorization:'Bearer '+mod.factor.session.access_token}})
  assert.deepEqual(await moderateAccess.json(), {access:'verified',moderation:true,queue:'none',disclosures:'none',workspaceReports:'none',accounts:'none',
    triage:{status:'none'},responses:false})

  const page=await browser.newPage()
  await page.goto(operatorOrigin)
  await page.getByLabel('Email',{exact:true}).fill(reviewer.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.getByRole('button',{name:'Sign in',exact:true}).click()
  await page.getByLabel('Authenticator code',{exact:true}).fill(await totpCode(reviewer.factor.secret))
  await page.getByRole('button',{name:'Verify code',exact:true}).click()
  const tabGroup=page.getByRole('group',{name:'Operator sections'})
  const disclosures=tabGroup.getByRole('button',{name:'Vulnerability disclosures',exact:true})
  await disclosures.click()
  assert.equal(await tabGroup.getByRole('button',{name:'Queue operations',exact:true}).count(),0)
  await page.getByRole('button',{name:'Open disclosure '+reportId.slice(0,8),exact:true}).click()
  await page.getByRole('heading',{name:title,exact:true}).waitFor()
  await page.getByRole('button',{name:'Begin review',exact:true}).click()
  await page.getByText('Report moved to in review.',{exact:true}).waitFor()
  assert.equal(sql(`select actor from sectalk_private.st_v8_disclosure_audit where report='${reportId}' and action='reviewing';`),reviewer.id)

  sql(`update auth.mfa_amr_claims set updated_at=now()-interval '6 minutes' where authentication_method='totp'
    and session_id in (select id from auth.sessions where user_id='${reviewer.id}');`)
  assert.equal((await queue(reviewer.factor.session, openBody)).status,403)
  await page.getByRole('heading',{name:'Verify your authenticator'}).waitFor({timeout:20000})
  await page.getByLabel('Authenticator code',{exact:true}).fill(await totpCode(reviewer.factor.secret))
  await page.getByRole('button',{name:'Verify code',exact:true}).click()
  await page.getByRole('heading',{name:'Vulnerability disclosures',exact:true}).waitFor()

  sql(`delete from sectalk_private.st_v8_disclosure_operators where account='${reviewer.id}';`)
  assert.equal((await queue(reviewer.factor.session, openBody)).status,403)
  await disclosures.waitFor({state:'hidden',timeout:20000})
  await page.getByRole('heading',{name:'Moderation queue',exact:true}).waitFor()
  assert.equal(await page.getByRole('heading',{name:title,exact:true}).count(),0)
  console.log('PASS public disclosure receipt, standalone review, audit attribution, role denial and live revocation')
} finally {
  await browser?.close()
  for (const child of children) child.kill()
  if (reportId) sql(`delete from sectalk_private.st_v8_disclosure_intake where id='${reportId}';`)
  for (const id of accounts) {
    sql(`delete from sectalk_private.staff where user_id='${id}';`)
    data(await admin.auth.admin.deleteUser(id))
  }
}
