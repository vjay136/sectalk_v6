// Run against the isolated loopback application and Supabase project with TOTP enabled and native GoTrue confirmation captured by Mailpit.
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
const handle = 'mfa_' + randomUUID().slice(0, 8)
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

const target = 'changed_' + randomUUID().slice(0, 8) + '@example.org'
const mail = new URL(process.env.SECTALK_AUTH_TEST_MAIL || 'http://127.0.0.1:55324')
assert.equal(mail.hostname, '127.0.0.1')
const {user} = data(await admin.auth.admin.createUser({email, password, email_confirm: true}))
const {user: outsider} = data(await admin.auth.admin.createUser({email: 'independent_' + email, password, email_confirm: true}))
const browser = await chromium.launch({executablePath: process.env.SECTALK_TEST_BROWSER})
const nav = page => page.getByRole('navigation', {name: 'SecTalk features'})
const area = page => page.getByRole('region', {name:'Account security changes', exact:true})
const alert = 'There is new activity in your account security settings.'

function endCoolingOff(kind) {
  execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-v', 'ON_ERROR_STOP=1',
    '-U', 'postgres', '-d', 'postgres'], {input: `
      update sectalk_private.st_v7_account_security_changes set ready_at=now()-interval '1 minute'
      where user_id='${user.id}' and kind='${kind}';`})
}

async function signInBrowser(page, address) {
  await page.goto(new URL('/#account', app).href)
  await page.getByLabel('Email address', {exact: true}).fill(address)
  await page.getByLabel('Password', {exact: true}).fill(password)
  await page.locator('button.submit-auth').click()
  await nav(page).waitFor()
}

async function security(page) {
  await nav(page).getByRole('button', {name:'Profile',exact:true}).click()
  await page.getByRole('button',{name:'Security',exact:true}).click()
  await area(page).waitFor()
}

async function emailLink(address) {
  for (let attempt = 0; attempt < 30; attempt++) {
    const response = await fetch(new URL('/api/v1/search?query=' + encodeURIComponent('to:' + address), mail))
    assert.equal(response.status, 200)
    const {messages} = await response.json()
    const entry = messages?.find(message => /change|confirm/i.test(message.Subject))
    if (entry) {
      const full = await (await fetch(new URL('/api/v1/message/' + entry.ID, mail))).json()
      const source = full.HTML.match(/href="([^"]+type=email_change[^"]*)"/i)?.[1]
      assert.ok(source, 'Expected a native email-change confirmation link')
      const link = new URL(source.replaceAll('&amp;', '&'))
      assert.equal(link.origin, supabase.origin)
      return link
    }
    await setTimeout(500)
  }
  throw new Error('Expected one confirmation at this exact local mailbox')
}

try {
  const original = newClient()
  data(await original.auth.signInWithPassword({email, password}))
  data(await original.rpc('st_save_profile', {p_handle: handle, p_name: 'Security changes tester'}))
  const otherClient = newClient()
  data(await otherClient.auth.signInWithPassword({email: outsider.email, password}))
  data(await otherClient.rpc('st_save_profile', {p_handle: 'independent_'+handle, p_name: 'Unrelated device'}))

  const [primary, second, unrelated] = await Promise.all([browser.newPage(), browser.newPage(), browser.newPage()])
  await Promise.all([signInBrowser(primary,email), signInBrowser(second,email), signInBrowser(unrelated,outsider.email)])
  await security(primary)
  await area(primary).getByRole('button',{name:'Change email address',exact:true}).click()
  await area(primary).getByLabel('New email address',{exact:true}).fill(target)
  await area(primary).getByLabel('Current password',{exact:true}).fill(password)
  await area(primary).getByRole('button',{name:'Verify and request change',exact:true}).click()
  await area(primary).getByText('Security change requested. The cooling-off period is 24 hours.').waitFor()
  await second.getByText(alert,{exact:true}).waitFor()
  assert.equal(await unrelated.getByText(alert,{exact:true}).count(),0)
  assert.equal((await original.rpc('st_v7_account_security_change', {p_action:'continue',p_kind:'email',p_value:target})).error?.code,'22023')
  assert.equal(data(await original.auth.getUser()).user.email,email)
  assert.deepEqual(data(await otherClient.rpc('st_v7_account_security_events')),[])

  endCoolingOff('email')
  await primary.reload()
  await security(primary)
  await area(primary).getByRole('button',{name:'Continue security change',exact:true}).click()
  await area(primary).getByLabel('New email address',{exact:true}).fill(target)
  await area(primary).getByLabel('Current password',{exact:true}).fill(password)
  await area(primary).getByRole('button',{name:'Verify and continue',exact:true}).click()
  await area(primary).getByText('Waiting for confirmation from both email addresses.',{exact:true}).waitFor()
  const [oldLink,newLink] = await Promise.all([emailLink(email),emailLink(target)])
  const verifyOld = await fetch(oldLink, {redirect:'manual'})
  assert.ok([302,303].includes(verifyOld.status))
  assert.equal(data(await admin.auth.admin.getUserById(user.id)).user.email,email)
  const verifyNew = await fetch(newLink, {redirect:'manual'})
  assert.ok([302,303].includes(verifyNew.status))
  assert.equal(data(await admin.auth.admin.getUserById(user.id)).user.email,target)
  await area(primary).getByText(/Email change completed/).waitFor()
  assert.ok((await newClient().auth.signInWithPassword({email,password})).error)

  await primary.getByRole('button',{name:'Set up authenticator',exact:true}).click()
  const secret = (await primary.locator('.mfa-setup code').textContent()).trim()
  await primary.getByLabel('Authenticator code',{exact:true}).fill(await totp(secret))
  await primary.getByRole('button',{name:'Verify authenticator',exact:true}).click()
  await primary.getByRole('button',{name:'I saved my codes',exact:true}).click()
  const providerProbe=newClient()
  data(await providerProbe.auth.signInWithPassword({email:target,password}))
  const factor=data(await providerProbe.auth.mfa.listFactors()).totp[0]
  data(await providerProbe.auth.mfa.challengeAndVerify({factorId:factor.id,code:await totp(secret)}))
  assert.ok((await providerProbe.auth.mfa.unenroll({factorId:factor.id})).error, 'Native provider must not bypass deliberate reset')
  await area(primary).getByRole('button',{name:'Request authenticator reset',exact:true}).click()
  await area(primary).getByLabel('Current authenticator code',{exact:true}).fill(await totp(secret))
  await area(primary).getByRole('button',{name:'Verify and request change',exact:true}).click()
  await area(primary).getByText('Security change requested. The cooling-off period is 24 hours.').waitFor()
  assert.equal((await providerProbe.rpc('st_v7_account_security_change', {p_action:'continue',p_kind:'authenticator'})).error?.code,'22023')
  await area(primary).getByRole('button',{name:'Cancel security request',exact:true}).click()
  await area(primary).getByText('Security request cancelled.',{exact:true}).waitFor()
  assert.equal(data(await providerProbe.auth.mfa.listFactors()).totp.length,1)

  await area(primary).getByRole('button',{name:'Request authenticator reset',exact:true}).click()
  await area(primary).getByLabel('Current authenticator code',{exact:true}).fill(await totp(secret))
  await area(primary).getByRole('button',{name:'Verify and request change',exact:true}).click()
  await area(primary).getByText('Security change requested. The cooling-off period is 24 hours.').waitFor()
  endCoolingOff('authenticator')
  await primary.reload()
  await security(primary)
  await area(primary).getByRole('button',{name:'Continue security change',exact:true}).click()
  await area(primary).getByLabel('Current authenticator code',{exact:true}).fill(await totp(secret))
  await area(primary).getByRole('button',{name:'Verify and continue',exact:true}).click()
  await primary.getByLabel('Email address',{exact:true}).waitFor()
  assert.ok((await providerProbe.auth.getUser()).error)
  const final = newClient()
  data(await final.auth.signInWithPassword({email:target,password}))
  assert.equal(data(await final.auth.mfa.listFactors()).all.length,0)
  assert.ok(data(await final.rpc('st_v7_account_security_events')).some(e=>e.kind==='authenticator'&&e.action==='completed'))
  assert.deepEqual(data(await otherClient.rpc('st_v7_account_security_events')),[])
  console.log('Passed genuine email and MFA cooling-off, two Mailpit confirmations, scoped device alerts, cancel, direct provider denial and revocation.')
} finally {
  await browser.close()
  await Promise.allSettled([admin.auth.admin.deleteUser(user.id),admin.auth.admin.deleteUser(outsider.id)])
}
