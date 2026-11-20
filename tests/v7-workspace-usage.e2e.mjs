import assert from 'node:assert/strict'
import {execFileSync} from 'node:child_process'
import {randomUUID} from 'node:crypto'
import {createClient} from '@supabase/supabase-js'

const local = new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
const app = new URL(process.env.SECTALK_STORAGE_TEST_APP).origin
assert.equal(local,'http://127.0.0.1:55321')
assert.equal(app,'http://127.0.0.1:3489')
const settings = {auth:{persistSession:false,autoRefreshToken:false}}
const admin = createClient(local,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,settings)
const key = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const {chromium} = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const accounts = []
const suffix = randomUUID().slice(0,8)
const password = randomUUID()+'!qA3'
const file = randomUUID()
const bucket = 'sectalk-workspace-files'
const contents = Buffer.from('Synthetic usage example. '.repeat(150))
let workspace, browser

function data(result) {
  if (result.error) throw result.error
  return result.data
}
function sql(statement) {
  return execFileSync('docker', ['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'], {input:statement, encoding:'utf8', windowsHide:true})
}
async function person(role) {
  const handle = 'bill10_'+role+'_'+suffix
  const email = handle+'@example.invalid'
  const {user} = data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  accounts.push(user.id)
  const client = createClient(local,key,settings)
  const {session} = data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:'Usage fixture '+role}))
  return {client,session}
}
try {
  const owner = await person('owner')
  const outside = await person('outside')
  workspace = data(await owner.client.rpc('st_v2_create_workspace',{p_name:'Usage '+suffix}))
  const upload = app+'/api/workspace-files?'+new URLSearchParams({workspace,file})
  const auth = {Authorization:'Bearer '+owner.session.access_token}
  const post = () => fetch(upload,{method:'POST',headers:{...auth,'Content-Type':'text/plain','X-SecTalk-File-Name':'usage.txt'},body:contents})
  for (let i=0;i<2;i++) {
    const response = await post()
    assert.equal(response.status,200,await response.text())
  }
  const usage = () => owner.client.rpc('st_v7_workspace_usage',{p_workspace:workspace}).then(data)
  assert.equal((await usage()).ai_scans,1)
  assert.equal((await usage()).storage_bytes,contents.byteLength)
  assert.equal((await outside.client.rpc('st_v7_workspace_usage',{p_workspace:workspace})).status,403)
  assert.equal((await createClient(local,key,settings).rpc('st_v7_workspace_usage',{p_workspace:workspace})).status,401)
  const sampled = sql("begin; select sectalk_private.st_v7_sample_workspace_storage(); " +
    "select sectalk_private.st_v7_sample_workspace_storage(); " +
    "select count(*) || ':' || sum(amount) from sectalk_private.st_v7_usage_events where metric='storage_byte_hours' " +
    "and workspace='"+workspace+"'; rollback;")
  assert(sampled.includes('1:'+contents.byteLength))

  browser = await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const page = await browser.newPage({locale:'en-US'})
  await page.addInitScript(({name,value})=>localStorage.setItem(name,JSON.stringify(value)),
    {name:'sb-'+new URL(local).hostname.split('.')[0]+'-auth-token',value:owner.session})
  await page.goto(app+'/?billing=usage')
  await page.getByRole('link',{name:'Workspace usage',exact:true}).click()
  await page.getByLabel('Workspace',{exact:true}).selectOption(workspace)
  await page.getByRole('region',{name:'Metered usage'}).waitFor()
  const scan = await page.locator('dt').filter({hasText:'Completed file inspections'}).evaluate(el=>el.nextElementSibling.textContent)
  assert.equal(scan,'1')
  const response = await fetch(upload,{method:'DELETE',headers:auth})
  assert.equal(response.status,204)
  const removed = await admin.storage.from(bucket).remove([workspace+'/'+file])
  if (removed.error) throw removed.error
  assert.equal((await usage()).storage_bytes,0)
  assert.equal((await usage()).ai_scans,1)
  console.log('Workspace billing UI and native API, real scanned upload, physical storage, hourly replay, and tenant isolation passed')
} finally {
  await browser?.close()
  if (workspace) {
    await admin.storage.from(bucket).remove([workspace+'/'+file])
    sql("delete from sectalk_private.st_v6_workspace_files where workspace='"+workspace+"'; " +
      "delete from public.st_v2_workspaces where id='"+workspace+"';")
  }
  for (const id of accounts) await admin.auth.admin.deleteUser(id)
}
