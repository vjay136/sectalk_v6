import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { fixtureAuthenticator, totpCode } from './workspace-admin-fixture.mjs'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const db = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname,'127.0.0.1')
assert.equal(db.origin,'http://127.0.0.1:55321')
const options = {auth:{persistSession:false,autoRefreshToken:false}}
const service = createClient(db.origin,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const {chromium} = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const suffix = randomUUID().slice(0,8)
const password = randomUUID()+'!5Qa'
const users = []
let browser

function data(result) {if (result.error) throw result.error; return result.data}

function sql(statement) {
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'],{input:statement,encoding:'utf8',windowsHide:true}).trim()
}

async function person(label, enroll=true) {
  const name='Standalone account '+label+' '+suffix
  const handle='oa_'+label+'_'+suffix, email=handle+'@example.invalid'
  const {user}=data(await service.auth.admin.createUser({email,password,email_confirm:true}))
  assert.match(user.id,/^[a-f0-9-]{36}$/)
  users.push(user.id)
  const client=createClient(db.origin,publicKey,options)
  const {session}=data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:name}))
  const factor=enroll?await fixtureAuthenticator(client):null
  return {id:user.id,name,handle,email,client,session,factor}
}

async function signIn(actor) {
  const page=await browser.newPage()
  await page.goto(app.href)
  await page.getByLabel('Email',{exact:true}).fill(actor.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.getByRole('button',{name:'Sign in',exact:true}).click()
  await page.getByRole('heading',{name:'Verify your authenticator'}).waitFor()
  assert.equal(await page.getByRole('group',{name:'Operator sections'}).count(),0)
  await page.getByLabel('Authenticator code',{exact:true}).fill(await totpCode(actor.factor.secret))
  await page.getByRole('button',{name:'Verify code',exact:true}).click()
  return page
}

async function selectAccount(page, actor) {
  await page.getByRole('group',{name:'Operator sections'}).getByRole('button',{name:'Account administration',exact:true}).click()
  const directory=page.getByRole('region',{name:'Account administration',exact:true})
  await directory.getByLabel('Name or handle',{exact:true}).fill(actor.handle)
  await directory.getByRole('button',{name:'Search accounts',exact:true}).click()
  await directory.getByRole('button',{name:actor.name+' (@'+actor.handle+')',exact:true}).click()
  await directory.getByRole('heading',{name:actor.name,exact:true}).waitFor()
  return directory
}

try {
  const [operator,reviewer,moderator,target]=await Promise.all([
    person('operator'),person('reviewer'),person('moderator'),person('target',false),
  ])
  function provision(person, capability, email=person.email) {
    return sql(`select sectalk_private.st_v8_provision_operator(
      '${person.id}','${email}','${capability}','Local operator test ${suffix}');`)
  }
  assert.throws(()=>provision(operator,'account_operator','different@example.invalid'),/exact active, confirmed account/)
  assert.throws(()=>provision(target,'moderation'),/enroll and verify a TOTP/)
  assert.equal(provision(operator,'account_operator'),'t')
  assert.equal(provision(operator,'account_operator'),'f')
  assert.throws(()=>provision(operator,'account_reviewer'),/other account-administration role/)
  assert.equal(provision(reviewer,'account_reviewer'),'t')
  assert.equal(provision(moderator,'moderation'),'t')
  assert.equal(sql(`select count(*) from sectalk_private.st_v8_operator_provisioning_audit
    where account in ('${operator.id}','${reviewer.id}','${moderator.id}');`),'3')
  assert.equal(sql(`select exists(select 1 from unnest(array['anon','authenticated','service_role']) role
    where has_function_privilege(role,'sectalk_private.st_v8_provision_operator(uuid,text,text,text)','EXECUTE')
    or has_table_privilege(role,'sectalk_private.st_v8_operator_provisioning_audit','SELECT'));`),'f')
  const reason='QA '+suffix+' native session close'
  const action={p_user:target.id,p_action:'force_logout',p_reason:reason}
  for (const denied of [reviewer.client,moderator.client,target.client]) {
    assert.equal((await denied.rpc('st_v7_account_admin_action',action)).error?.code,'42501')
  }
  const passwordOnly=createClient(db.origin,publicKey,{...options,global:{headers:{Authorization:'Bearer '+operator.session.access_token}}})
  assert.equal((await passwordOnly.rpc('st_v7_account_admin_action',action)).error?.code,'PT403')
  assert.ok((await operator.client.rpc('st_v7_account_admin_action',{...action,p_user:moderator.id})).error)

  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const [operatorPage,reviewerPage,moderatorPage]=await Promise.all([signIn(operator),signIn(reviewer),signIn(moderator)])
  const moderationTabs=moderatorPage.getByRole('group',{name:'Operator sections'})
  await moderationTabs.getByRole('button',{name:'Moderation',exact:true}).waitFor()
  assert.equal(await moderationTabs.getByRole('button',{name:'Account administration',exact:true}).count(),0)
  const [directory,readOnly]=await Promise.all([selectAccount(operatorPage,target),selectAccount(reviewerPage,target)])
  assert.equal(await operatorPage.getByRole('group',{name:'Operator sections'}).getByRole('button',{name:'Moderation',exact:true}).count(),0)
  assert.equal(await readOnly.getByRole('button',{name:'End all sessions',exact:true}).count(),0)
  assert.equal(await readOnly.getByRole('button',{name:'Request authenticator reset',exact:true}).count(),0)
  assert.equal(data(await target.client.rpc('st_v7_current_session_valid')),true)
  await directory.getByRole('button',{name:'End all sessions',exact:true}).click()
  await directory.getByLabel('Case reference and reason',{exact:true}).fill(reason)
  await directory.getByRole('button',{name:'Confirm end all sessions',exact:true}).click()
  await directory.getByRole('status').getByText('All sessions ended.',{exact:true}).waitFor()
  await directory.getByText(reason,{exact:true}).waitFor()
  assert.equal(data(await target.client.rpc('st_v7_current_session_valid')),false)
  assert.equal(sql(`select actor from sectalk_private.st_v7_account_admin_audit
    where target='${target.id}' and action='force_logout';`),operator.id)

  sql(`delete from sectalk_private.st_v7_account_operators where user_id='${operator.id}';`)
  assert.equal((await operator.client.rpc('st_v7_account_admin_directory')).error?.code,'42501')
  await operatorPage.getByRole('heading',{name:'Access unavailable'}).waitFor({timeout:20000})
  assert.equal(await directory.count(),0)
  console.log('PASS audited named operator provisioning, standalone role isolation, native session revocation and role removal')
} finally {
  await browser?.close()
  for (const id of users) {
    sql(`delete from sectalk_private.st_v7_account_operators where user_id='${id}';
      delete from sectalk_private.staff where user_id='${id}';
      delete from sectalk_private.st_v8_operator_provisioning_audit where account='${id}';`)
    data(await service.auth.admin.deleteUser(id))
  }
}
