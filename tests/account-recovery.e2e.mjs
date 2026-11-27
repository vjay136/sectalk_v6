// Run against the isolated loopback application and Supabase project with TOTP enabled.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHmac, randomUUID } from 'node:crypto'
import { setTimeout } from 'node:timers/promises'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const key = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const admin = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const newClient = () => createClient(supabase.origin, key, options)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const handle = 'recoverykey_' + randomUUID().slice(0, 8)
const email = handle + '@example.org'
const password = randomUUID() + '1!Q'

function data(result) {
  if (result.error) throw result.error
  return result.data
}

let lastStep = 0
async function totp(secret, newFactor = false) {
  if (newFactor) lastStep = 0
  while (Math.floor(Date.now() / 30_000) === lastStep || Date.now() % 30_000 > 28_000) await setTimeout(200)
  lastStep = Math.floor(Date.now() / 30_000)
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bits = [...secret.toUpperCase().replace(/=+$/, '')].map(character => alphabet.indexOf(character).toString(2).padStart(5, '0')).join('')
  const key = Buffer.from(bits.match(/.{8}/g).map(part => Number.parseInt(part, 2)))
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(lastStep))
  const mac = createHmac('sha1', key).update(counter).digest()
  return String((mac.readUInt32BE(mac.at(-1) & 15) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}

const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
const button = (page, name) => page.getByRole('button', { name, exact: true })
const nav = page => page.getByRole('navigation', { name: 'SecTalk features' })

async function signIn(client) {
  return data(await client.auth.signInWithPassword({ email, password }))
}

async function signInBrowser(page) {
  await page.goto(new URL('/#account', app).href)
  await page.getByLabel('Email address', { exact: true }).fill(email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
}


const security=page=>page.getByRole('region',{name:'Account security changes',exact:true})
const keyPanel=page=>page.getByRole('region',{name:'Account recovery key',exact:true})
const registry=page=>page.getByRole('region',{name:'Device trust',exact:true})
function sql(input) {
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'],{input,encoding:'utf8'}).trim()
}
async function credentials(page,secret) {
  await page.getByLabel('Authenticator code for recovery key').fill(await totp(secret))
}
async function openSecurity(page) {
  await button(nav(page),'Profile').click()
  await button(page,'Security').click()
  await security(page).waitFor()
}
async function beginRecovery(page,method) {
  await signInBrowser(page)
  await button(page,method).click()
}
async function keyAttempt(page,value) {
  await page.getByLabel('Recovery key',{exact:true}).fill(value)
  await button(page,'Reset authenticator').click()
}
try {
  const seed=newClient()
  await signIn(seed)
  data(await seed.rpc('st_save_profile',{p_handle:handle,p_name:'Recovery fixture'}))
  const [primary,requester]=await Promise.all([browser.newPage(),browser.newPage()])
  await signInBrowser(primary)
  await openSecurity(primary)
  await button(primary,'Set up authenticator').click()
  const secret=(await primary.locator('.mfa-setup code').textContent()).trim()
  await primary.getByLabel('Authenticator code',{exact:true}).fill(await totp(secret))
  await button(primary,'Verify authenticator').click()
  await button(primary,'I saved my codes').click()
  await button(keyPanel(primary),'Create recovery key').click()
  await credentials(primary,secret)
  await button(keyPanel(primary),'Verify and save a new recovery key').click()
  const original=await keyPanel(primary).getByLabel('Your recovery key').textContent()
  assert.match(original,/^[0-9A-F]{64}$/)
  assert.equal(sql("select octet_length(key_hash) from sectalk_private.st_v7_recovery_keys where user_id='"+user.id+"';"),'32')
  await button(keyPanel(primary),'I saved my recovery key').click()
  assert.equal(await keyPanel(primary).getByLabel('Your recovery key').count(),0)
  await beginRecovery(requester,'Use a recovery key')
  await keyAttempt(requester,original.toLowerCase())
  await requester.getByText(/^Recovery can continue after/).waitFor()
  await security(primary).getByText('Authenticator recovery requested',{exact:false}).waitFor()
  await keyAttempt(requester,original)
  await requester.getByText(/^Recovery can continue after/).waitFor()
  assert.equal(await nav(requester).count(),0)
  await button(keyPanel(primary),'Replace recovery key').click()
  await credentials(primary,secret)
  await button(keyPanel(primary),'Verify and save a new recovery key').click()
  const replacement=await keyPanel(primary).getByLabel('Your recovery key').textContent()
  assert.notEqual(original,replacement)
  await button(keyPanel(primary),'I saved my recovery key').click()
  await keyAttempt(requester,original)
  await requester.getByRole('alert').filter({ hasText: 'Could not reset your authenticator' }).waitFor()
  assert.equal(sql("select state from sectalk_private.st_v7_account_security_changes where user_id='"+user.id+"';"),'cancelled')
  await button(keyPanel(primary),'Revoke recovery key').click()
  await credentials(primary,secret)
  await button(keyPanel(primary),'Verify and revoke recovery key').click()
  await keyPanel(primary).getByText('Create a key to recover access if you lose your authenticator.').waitFor()
  assert.equal(sql("select count(*) from sectalk_private.st_v7_recovery_keys where user_id='"+user.id+"';"),'0')

  await button(primary,'Devices and sessions').click()
  await button(registry(primary),'Register this device').click()
  await button(registry(primary),'Trust device').click()
  await registry(primary).getByLabel('Current authenticator code',{exact:true}).fill(await totp(secret))
  await button(registry(primary),'Confirm trust device').click()
  await registry(primary).getByText('Device trust updated.',{exact:true}).waitFor()
  await button(primary,'Security').click()
  const deviceRequester=await browser.newPage()
  await beginRecovery(deviceRequester,'Recover with a trusted device')
  const requestResponse=deviceRequester.waitForResponse(result=>result.url().includes('/rest/v1/rpc/st_v7_recovery_security_reset'))
  await button(deviceRequester,'Request or continue device recovery').click()
  assert.equal(await (await requestResponse).json(),'pending')
  await primary.route('**/api/account/devices/bundle',async route=>{
    const proof=route.request().postDataJSON()
    proof.recoverySignature=(proof.recoverySignature[0]==='A'?'B':'A')+proof.recoverySignature.slice(1)
    await route.continue({postData:JSON.stringify(proof)})
  },{times:1})
  const rejected=primary.waitForResponse(result=>result.url().endsWith('/api/account/devices/bundle'))
  await button(security(primary),'Approve recovery from this device').click()
  assert.equal((await rejected).status(),403)
  await security(primary).getByText('Approval requires the browser keys of the previously trusted, verified device.',{exact:true}).waitFor()
  const approved=primary.waitForResponse(result=>result.url().endsWith('/api/account/devices/bundle'))
  await button(security(primary),'Approve recovery from this device').click()
  assert.equal((await approved).status(),204)
  await security(primary).getByText('Recovery approved. The 24-hour cooling-off period still applies.').waitFor()
  assert.equal(await nav(deviceRequester).count(),0)
  const previousToken=await deviceRequester.evaluate(()=>{
    const saved=Object.keys(localStorage).find(name=>name.endsWith('-auth-token'))
    return JSON.parse(localStorage.getItem(saved)).access_token
  })
  sql("update sectalk_private.st_v7_account_security_changes set ready_at=now()-interval '1 minute' where user_id='"+user.id+"';")
  await button(deviceRequester,'Request or continue device recovery').click()
  await deviceRequester.getByText(/Your authenticator was reset and your sessions ended/).waitFor()
  const stale=await fetch(new URL('/rest/v1/st_profiles?select=id',supabase),{
    headers:{apikey:key,Authorization:'Bearer '+previousToken},
  })
  assert.equal(stale.status,401)
  const after=newClient()
  await signIn(after)
  assert.equal(data(await after.auth.mfa.listFactors()).all.length,0)
  assert.equal(data(await after.rpc('st_v7_recovery_security_reset',{p_code:'device-approval'})),'unavailable')
  console.log('Native sign-in, recovery key issue/replace/revoke, cooling-off, trusted device Edge signature, and session reset passed.')
} finally {
  await browser.close()
  await admin.auth.admin.deleteUser(user.id)
}
