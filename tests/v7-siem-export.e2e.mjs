import assert from 'node:assert/strict'
import {execFileSync, spawn} from 'node:child_process'
import {generateKeyPairSync, randomBytes, randomUUID, verify} from 'node:crypto'
import {createServer} from 'node:http'
import {resolve} from 'node:path'
import {readFile} from 'node:fs/promises'
import {setTimeout} from 'node:timers/promises'
import {createClient} from '@supabase/supabase-js'
import {fixtureAuthenticator} from './workspace-admin-fixture.mjs'

const dbUrl = new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
const appUrl = 'http://127.0.0.1:3489'
assert.equal(dbUrl, 'http://127.0.0.1:55321')
const key = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const serviceKey = process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
const opts = {auth:{persistSession:false, autoRefreshToken:false}}
const admin = createClient(dbUrl, serviceKey, opts)
const {chromium} = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const users = []
const spaces = []
const suffix = randomUUID().slice(0, 8)
const password = randomUUID() + '1aA!'
const period = new Date(Math.floor(Date.now() / 3600000) * 3600000 - 3600000).toISOString()

function data(value) {
  if (value.error) throw value.error
  return value.data
}
function sql(statement) {
  return execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-At',
    '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres'], {input:statement, encoding:'utf8', windowsHide:true})
}
async function user(role) {
  const handle = 'siem_' + role + '_' + suffix
  const email = handle + '@example.invalid'
  const identity = data(await admin.auth.admin.createUser({email,password,email_confirm:true})).user
  users.push(identity.id)
  const client = createClient(dbUrl, key, opts)
  const session = data(await client.auth.signInWithPassword({email,password})).session
  data(await client.rpc('st_save_profile', {p_handle:handle,p_name:'SIEM ' + role}))
  const workspace = data(await client.rpc('st_v2_create_workspace', {p_name:'SIEM ' + role + ' ' + suffix}))
  spaces.push(workspace)
  return {identity, client, workspace, session}
}
function headers(session) {return {Authorization:'Bearer ' + session.access_token, 'Content-Type':'application/json'}}
const receipts = []
const collector = createServer(async (request, response) => {
  let body = ''
  for await (const chunk of request) body += chunk
  receipts.push({body, id: request.headers['webhook-id']})
  response.writeHead(204).end()
})
let browser, child
try {
  const owner = await user('owner')
  const foreign = await user('foreign')
  data(await admin.rpc('st_v2_sync_billing', {p_event:'evt_siem_'+suffix,p_user:owner.identity.id,
    p_customer:'cus_siem_'+suffix,p_subscription:'sub_siem_'+suffix,p_plan:'enterprise',p_status:'active',
    p_end:new Date(Date.now()+3600000).toISOString(),p_cancel:false,p_synced:new Date().toISOString()}))
  sql("insert into public.st_v2_workspace_audit(workspace_id,actor,event,target,created_at) values ('" +
    owner.workspace + "','" + owner.identity.id + "','member.suspend','" + foreign.identity.id + "','" + period +
    "'::timestamptz+interval '1 minute');")
  await new Promise((resolve, reject) => collector.once('error', reject).listen(0,'127.0.0.1',resolve))
  const origin = 'http://127.0.0.1:' + collector.address().port
  const {privateKey,publicKey} = generateKeyPairSync('ed25519')
  const secret = randomBytes(32).toString('base64url')
  child = spawn(process.execPath, [resolve('node_modules/next/dist/bin/next'),'start','--hostname','127.0.0.1','--port','3489'],{
    cwd:resolve('supabase/.temp/v4-auth-qa/device-commands-app'), stdio:'inherit',
    env:{...process.env,NEXT_PUBLIC_SUPABASE_URL:dbUrl,NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:key,
      SECTALK_APP_URL:appUrl,SECTALK_TEST_WEBHOOK_ORIGIN:origin,SECTALK_SIEM_DRAIN_SECRET:secret,SECTALK_SIEM_SERVICE_KEY:serviceKey,
      SECTALK_SIEM_SIGNING_KEY:privateKey.export({format:'der',type:'pkcs8'}).toString('base64url'),
      SECTALK_SIEM_CONNECTORS:JSON.stringify([{workspace:owner.workspace,channel:'webhook',
        url:origin+'/siem',secret:randomBytes(32).toString('base64url')}])},
  })
  let ready = false
  for (let n = 0; n < 45 && child.exitCode === null; n++) {
    ready = await fetch(appUrl+'/api/siem',{signal:AbortSignal.timeout(10000)}).then(response=>response.status===401).catch(()=>false)
    if (ready) break
    await setTimeout(1000)
  }
  assert(ready, 'isolated SIEM app started')
  const endpoint = appUrl + '/api/siem'
  const forWorkspace = workspace => endpoint + '?workspace=' + workspace
  assert.equal((await fetch(forWorkspace(owner.workspace), {headers:headers(owner.session)})).status,403)
  await fixtureAuthenticator(owner.client)
  const session = data(await owner.client.auth.getSession()).session
  assert.equal((await fetch(forWorkspace(foreign.workspace), {headers:headers(session)})).status,403)
  assert.equal((await fetch(endpoint+'/drain',{method:'POST',headers:{Authorization:'Bearer incorrect'}})).status,401)
  assert.equal((await fetch(endpoint+'/drain',{method:'POST',headers:headers(session)})).status,401)

  browser = await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
  const page = await browser.newPage({acceptDownloads:true})
  await page.addInitScript(({name,value})=>localStorage.setItem(name,JSON.stringify(value)),
    {name:'sb-'+new URL(dbUrl).hostname.split('.')[0]+'-auth-token',value:session})
  await page.goto(appUrl + '/siem', {waitUntil:'domcontentloaded'})
  await page.locator('select').first().selectOption(owner.workspace)
  const downloading = page.waitForEvent('download')
  await page.getByRole('button',{name:'Download signed digest',exact:true}).click()
  const file = await downloading
  const body = await readFile(await file.path(),'utf8')
  const envelope = JSON.parse(body)
  const payload = JSON.parse(envelope.payload)
  assert.deepEqual(payload.counts,{member_suspended:1})
  assert.equal(payload.workspace,owner.workspace)
  assert(!body.includes(owner.identity.id) && !body.includes(foreign.identity.id))
  assert(verify(null,Buffer.from(envelope.payload),publicKey,Buffer.from(envelope.signature,'base64url')))

  await page.locator('select').nth(1).selectOption('webhook')
  await page.getByRole('button',{name:'Queue digest',exact:true}).click()
  await page.getByText('Digest queued for delivery.').waitFor()
  const drain = () => fetch(endpoint+'/drain',{method:'POST',headers:{Authorization:'Bearer '+secret}}).then(async response=>{
    assert.equal(response.status,200)
    return response.json()
  })
  assert.deepEqual(await drain(),{accepted:1})
  assert.deepEqual(await drain(),{accepted:0})
  await page.getByRole('button',{name:'Refresh deliveries'}).click()
  await page.getByText('· Webhook sent',{exact:false}).waitFor()
  assert.deepEqual(receipts,[{body,id:payload.id}])
  assert.equal((await fetch(forWorkspace(owner.workspace)+'&batch='+randomUUID(),{headers:headers(session)})).status,404)
  console.log('SIEM browser download, native TOTP, foreign workspace denial, and replay-safe worker passed')
} finally {
  await browser?.close()
  child?.kill()
  collector.closeAllConnections()
  await new Promise(resolve=>collector.close(resolve))
  for (const workspace of spaces) sql("delete from public.st_v2_workspaces where id='" + workspace + "';")
  for (const id of users) await admin.auth.admin.deleteUser(id)
}
