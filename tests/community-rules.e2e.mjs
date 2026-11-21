import assert from 'node:assert/strict'
import {execFileSync} from 'node:child_process'
import {randomUUID} from 'node:crypto'
import {createClient} from '@supabase/supabase-js'

const app=process.env.SECTALK_COMMUNITY_TEST_APP
const api=process.env.SECTALK_RESIDENCY_TARGET_DATABASE
assert.equal(app,'http://127.0.0.1:3602')
assert.equal(api,'http://127.0.0.1:56801')
const options={auth:{persistSession:false,autoRefreshToken:false}}
const admin=createClient(api,process.env.SECTALK_RESIDENCY_TARGET_KEY,options)
const account=createClient(api,process.env.SECTALK_RESIDENCY_TARGET_PUBLIC_KEY,options)
const suffix=randomUUID().slice(0,8)
const versions=['qa-'+suffix+'-a','qa-'+suffix+'-b']
const email='community_'+suffix+'@example.invalid'
const password=randomUUID()+'!aA1'
const {chromium}=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
let browser
let user

function sql(statement) {
  return execFileSync('docker',['exec','-i','supabase_db_v6-bundle243-qa','psql','-U','postgres','-d','postgres',
    '-XqtA','-v','ON_ERROR_STOP=1'],{input:statement,encoding:'utf8',windowsHide:true}).trim()
}
function data(result){if(result.error)throw new Error(result.error.message);return result.data}
function publish(version,time,rule) {
  sql(`insert into sectalk_private.st_v8_community_rules values('${version}',${time},'SecTalk Community Rules',
    jsonb_build_array('${rule}'));`)
}

try{
  assert.equal(sql('select count(*) from sectalk_private.st_v8_community_rules;'),'0','Use the empty disposable policy registry')
  user=data(await admin.auth.admin.createUser({email,password,email_confirm:true})).user
  data(await account.auth.signInWithPassword({email,password}))
  data(await account.rpc('st_save_profile',{p_handle:'community_'+suffix,p_name:'Community rules QA'}))
  assert.deepEqual(data(await account.rpc('st_v8_community_rules_check')),{required:false})
  const first='Respect others. Harassment, threats, impersonation, scams and repeated unwanted contact are prohibited.'
  const second='Report abusive or deceptive conduct. Share relevant evidence and avoid including unrelated personal details.'
  publish(versions[0],"now()-interval '1 hour'",first)
  browser=await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const page=await browser.newPage()
  const rules=page.getByRole('region',{name:'Community Rules',exact:true})
  const navigation=page.getByRole('navigation',{name:'SecTalk features'})
  await page.goto(app+'/#account')
  await page.getByLabel('Email address',{exact:true}).fill(email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await rules.getByText(first,{exact:true}).waitFor()
  assert.equal(await navigation.count(),0)
  await rules.getByRole('button',{name:'Accept and continue',exact:true}).click()
  assert.equal(sql(`select count(*) from sectalk_private.st_v8_community_rules_acceptance where actor='${user.id}';`),'0')
  await rules.getByRole('checkbox').check()
  await rules.getByRole('button',{name:'Accept and continue',exact:true}).click()
  await navigation.waitFor()
  assert.deepEqual(data(await account.rpc('st_v8_community_rules_check')),{required:false,version:versions[0]})
  await page.reload()
  await navigation.waitFor()

  publish(versions[1],'now()',second)
  assert.equal((await account.rpc('st_v8_community_rules_check',{p_accept_version:versions[0]})).error?.code,'PT409')
  await page.reload()
  await rules.getByText(second,{exact:true}).waitFor()
  assert.equal(await navigation.count(),0)
  await rules.getByRole('checkbox').check()
  await rules.getByRole('button',{name:'Accept and continue',exact:true}).click()
  await navigation.waitFor()
  assert.deepEqual(data(await account.rpc('st_v8_community_rules_check')),{required:false,version:versions[1]})
  assert.equal(sql(`select count(*) from sectalk_private.st_v8_community_rules_acceptance where actor='${user.id}';`),'2')
  console.log('Edge verified Community Rules after password login, explicit acceptance, persistent version receipts and renewed acceptance for the next version.')
}finally{
  await browser?.close()
  if(user)data(await admin.auth.admin.deleteUser(user.id))
  sql(`begin; set local session_replication_role=replica;
    delete from sectalk_private.st_v8_community_rules where version in ('${versions[0]}','${versions[1]}'); commit;`)
}
