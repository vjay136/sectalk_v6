// Requires the local web app, Supabase Auth, Mailpit, and the Playwright browser test library.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'
import { createServer } from 'node:http'
import { setTimeout } from 'node:timers/promises'

const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const app = process.env.SECTALK_AUTH_TEST_APP || 'http://127.0.0.1:3484'
const mail = process.env.SECTALK_AUTH_TEST_MAIL || 'http://127.0.0.1:55324'
for (const address of [app, mail]) assert.equal(new URL(address).hostname, '127.0.0.1')

const qaEmail = tag => `sectalk-${tag}-${randomBytes(10).toString('hex').replace(/[0-9]/g,n=>String.fromCharCode(103+Number(n)))}@example.org`
const email = qaEmail('mail')
const displayName = 'Taylor & Lane <Verification>'
const original = randomBytes(24).toString('base64url') + '!g5'
const changed = randomBytes(24).toString('base64url') + '!h6'
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
const fixturePort = process.env.SECTALK_AUTH_TEST_RANGE_PORT
const passwordDigest = value => createHash('sha1').update(value).digest('hex').toUpperCase()
let breached
do breached = randomBytes(24).toString('base64url') + '!w7'
while (passwordDigest(breached).slice(0,5) === passwordDigest(original).slice(0,5))
const requests = []
let providerUnavailable = false
const resendPort = process.env.SECTALK_AUTH_TEST_RESEND_PORT
let resendAttempts = 0
const resendUpstream = resendPort && new URL(process.env.SECTALK_AUTH_TEST_NATIVE_ORIGIN || 'http://127.0.0.1:55321')
if (resendUpstream) assert.ok(['http://127.0.0.1:55321','http://127.0.0.1:56801'].includes(resendUpstream.origin))
const resend = resendPort && createServer(async (request, response) => {
  try {
    const url = new URL(request.url, resendUpstream)
    if (request.method !== 'POST' || url.origin !== resendUpstream.origin || url.pathname !== '/auth/v1/resend') {
      return response.writeHead(404).end()
    }
    const body = await new Response(request).text()
    const payload = JSON.parse(body)
    if (payload.email !== email || payload.type !== 'signup') return response.writeHead(400).end()
    response.setHeader('Content-Type', 'application/json')
    if (++resendAttempts === 1) return response.writeHead(503).end('{"message":"Synthetic delivery outage"}')
    const headers = new Headers()
    for (const name of ['authorization','apikey','content-type']) {
      const value = request.headers[name]
      if (typeof value === 'string') headers.set(name,value)
    }
    const forwarded = await fetch(url, {
      method: 'POST', body, redirect: 'error',
      headers,
    })
    response.writeHead(forwarded.status).end(await forwarded.text())
  } catch {
    response.writeHead(500).end()
  }
})
const range = fixturePort && createServer((request, response) => {
  requests.push({path:request.url, method:request.method, padding:request.headers['add-padding']})
  if (providerUnavailable) return response.writeHead(503).end()
  const membership = request.url === '/range/' + passwordDigest(breached).slice(0,5)
  const suffix = passwordDigest(membership ? breached : original).slice(5)
  const realSuffix = suffix === 'A'.repeat(35) ? 'B'.repeat(35) : 'A'.repeat(35)
  return response.writeHead(200, {'Content-Type':'text/plain'}).end(`${realSuffix}:5\r\n${suffix}:${membership ? 1 : 0}\r\n`)
})

async function delivered(subjectPart) {
  for (let attempt = 0; attempt < 30; attempt++) {
    const response = await fetch(mail + '/api/v1/search?query=' + encodeURIComponent('to:' + email))
    assert.equal(response.status, 200)
    const { messages } = await response.json()
    const matching = messages?.find(message => message.Subject.toLowerCase().includes(subjectPart))
    if (matching) {
      const reply = await fetch(mail + '/api/v1/message/' + matching.ID)
      assert.equal(reply.status, 200)
      return reply.json()
    }
    await setTimeout(500)
  }
  throw new Error('No matching local email was delivered')
}

async function signIn(page, password, expected) {
  await page.getByLabel('Email address', { exact: true }).fill(email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  const response = page.waitForResponse(result => result.url().endsWith('/api/auth/sign-in'))
  await page.locator('button.submit-auth').click()
  assert.equal((await response).status(), expected)
}

try {
  if (resend) {
    assert.ok(range, 'Use the local password check fixture for the retry test')
    await new Promise((resolve,reject)=>{
      resend.once('error',reject)
      resend.listen(Number(resendPort),'127.0.0.1',resolve)
    })
  }
  if (range) await new Promise((resolve,reject)=>{
    range.once('error',reject)
    range.listen(Number(fixturePort),'127.0.0.1',resolve)
  })
  const page = await browser.newPage()
  await page.goto(app + '/#account')
  const disclosure=page.getByRole('link',{name:'Security disclosures',exact:true})
  assert.equal(await disclosure.getAttribute('href'),'/security')
  await page.getByRole('button', { name: 'Create account', exact: true }).click()
  if (range) {
    const rejectedAddresses=[]
    const submit = async (password,status,notice) => {
      const rejectedAddress=qaEmail('screening')
      rejectedAddresses.push(rejectedAddress)
      await page.getByLabel('Email address',{exact:true}).fill(rejectedAddress)
      await page.getByLabel('Password', {exact:true}).fill(password)
      await page.getByLabel('Confirm password', {exact:true}).fill(password)
      const response=page.waitForResponse(result=>result.url().endsWith('/api/auth/sign-up'))
      await page.locator('button.submit-auth').click()
      assert.equal((await response).status(),status)
      await page.getByText(notice,{exact:true}).waitFor()
    }
    await submit(breached,422,'This password appeared in a data breach. Choose a different password.')
    providerUnavailable=true
    await submit(original,503,'The password check is temporarily unavailable. Try signing up again shortly.')
    providerUnavailable=false
    for(const address of rejectedAddresses){
      const result=await fetch(mail+'/api/v1/search?query='+encodeURIComponent('to:'+address))
      assert.equal((await result.json()).messages?.length??0,0,'Rejected signups must not send a confirmation email')
    }
  }
  await page.getByLabel('Email address', { exact: true }).fill(email)
  await page.getByLabel('Name for your confirmation email (optional)', { exact: true }).fill(displayName)
  await page.getByLabel('Password', { exact: true }).fill(original)
  await page.getByLabel('Confirm password', { exact: true }).fill(original)
  const submitted=page.waitForResponse(result=>result.url().endsWith('/api/auth/sign-up'))
  await page.locator('button.submit-auth').click()
  if (resend) {
    assert.equal((await submitted).status(),503)
    assert.equal(resendAttempts,1)
    await page.getByText('Your account was created, but we could not send the verification link. Use Resend verification link to try again.',{exact:true}).waitFor()
    const inbox=await fetch(mail + '/api/v1/search?query=' + encodeURIComponent('to:' + email))
    assert.equal((await inbox.json()).messages?.length??0,0)
    const retried=page.waitForResponse(result=>result.url().endsWith('/api/auth/sign-up'))
    await page.getByRole('button',{name:'Resend verification link',exact:true}).click()
    assert.equal((await retried).status(),200)
    assert.equal(resendAttempts,2)
  } else {
    assert.equal((await submitted).status(),200)
  }
  await page.getByRole('heading', { name: 'Check your email' }).waitFor()
  if (range) {
    assert.deepEqual(requests,[breached,original,original].map(password=>({
      method:'GET',path:'/range/'+passwordDigest(password).slice(0,5),padding:'true',
    })))
    console.log('Passed browser signup screening, padded prefix privacy, false padding match, and provider outage handling.')
  }

  const signup = await delivered('verify email')
  const link = signup.HTML.match(/href="([^"]*\/auth\/confirm#[^"]+)"/)?.[1]
  assert.ok(link, 'The signup email must contain the app confirmation link')
  assert.equal(new URL(link).origin, app)
  assert.equal(signup.HTML.match(/<code>([^<]+)<\/code>/)?.[1],link)
  assert.ok(signup.HTML.includes(email),'The confirmation email must identify the account address')
  assert.ok(signup.HTML.includes('Taylor &amp; Lane &lt;Verification&gt;'),
    'The signup name must appear as escaped text')

  // Loading the link in a scanner-like independent session must leave it available for the recipient.
  const scan = await browser.newPage()
  await scan.goto(link)
  await scan.getByRole('button', { name: 'Verify my email' }).waitFor()
  await scan.close()

  await page.goto(link)
  await page.getByRole('button', { name: 'Verify my email' }).click()
  await page.getByRole('heading', { name: 'Your email is verified' }).waitFor()
  await page.getByRole('link', { name: 'Go to SecTalk sign in' }).click()
  await signIn(page, original, 200)
  if (resend) console.log('Passed signup retry after the first email send failed, preserving the original password.')
  const native=process.env.SECTALK_AUTH_TEST_ARGON_DB
  if(native){
    assert.match(native,/^supabase_db_(?:v4-auth-qa|v6-c\d+-qa|v6-bundle243-qa)$/)
    const format=execFileSync('docker',['exec','-i',native,'psql','-qAXt','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres'],{
      input:`select encrypted_password like '$argon2id$%' from auth.users where email='${email}';`,encoding:'utf8',windowsHide:true,
    }).trim()
    assert.equal(format,'t','The native stored verifier stays Argon2id through confirmation and password sign-in')
  }
  await page.getByLabel('Display name', {exact:true}).fill('Auth mail QA')
  await page.getByLabel('Handle', {exact:true}).fill('authqa_' + randomBytes(6).toString('hex'))
  await page.getByRole('button', {name:'Save profile',exact:true}).click()
  await page.getByRole('button', {name:'Skip for now',exact:true}).click()
  const activeDevice = page.getByRole('navigation', {name:'SecTalk features'})
  await activeDevice.waitFor()
  for (const label of ['Group chats', 'Friends', 'Calls', 'Workspaces', 'Rooms', 'Tasks', 'Calendar', 'Meetings',
    'Files', 'Search', 'Notifications', 'Safety', 'Billing', 'Profile', 'Inbox']) {
    const tab = activeDevice.getByRole('button', {name:label, exact:true})
    await tab.click()
    await page.locator('nav.rail button[aria-current="page"]').filter({hasText: label}).waitFor()
  }
  assert.equal(await activeDevice.getByRole('button',{name:/operator|administration/i}).count(),0)
  console.log('Passed fresh-account navigation through all 15 main tabs with no operator console entry.')

  const replay = await browser.newPage()
  await replay.goto(link)
  await replay.getByRole('button', { name: 'Verify my email' }).click()
  await replay.getByRole('heading', { name: 'This link is invalid or expired' }).waitFor()
  await replay.close()

  const reset = await browser.newPage()
  await reset.goto(app + '/#account')
  await reset.getByRole('button', { name: 'Forgot password?' }).click()
  await reset.getByLabel('Email address', { exact: true }).fill(email)
  await reset.route('**/auth/v1/recover?*', route => route.fulfill({
    status: 429, headers: { 'access-control-allow-origin': '*' },
    json: { error_code: 'over_email_send_rate_limit', msg: 'Recovery cooldown' },
  }), { times: 1 })
  await reset.getByRole('button', { name: 'Send recovery code' }).click()
  await reset.getByRole('alert').filter({ hasText: 'No new code was sent' }).waitFor()
  await reset.getByRole('button', { name: 'Enter an existing code' }).click()
  await reset.getByRole('heading', { name: 'Verify your recovery code' }).waitFor()
  await reset.getByRole('button', { name: 'Change email address' }).click()
  await reset.getByRole('button', { name: 'Send recovery code' }).click()
  await reset.getByRole('heading', { name: 'Verify your recovery code' }).waitFor()
  const recovery = await delivered('reset password')
  const code = recovery.HTML.match(/>\s*(\d{6,10})\s*</)?.[1]
  assert.ok(code, 'The recovery email must contain a numeric OTP')
  await reset.getByLabel('Verification code').fill(code)
  await reset.getByRole('button', { name: 'Verify code' }).click()
  await reset.getByRole('heading', { name: 'Set a new password' }).waitFor()
  await reset.getByLabel('Password', { exact: true }).fill(changed)
  await reset.getByLabel('Confirm password', { exact: true }).fill(changed)
  await reset.route('**/auth/v1/user', route => route.fulfill({
    status: 503, headers: { 'access-control-allow-origin': '*' },
    json: { msg: 'Synthetic authentication service outage' },
  }), { times: 1 })
  await reset.getByRole('button', { name: 'Update password' }).click()
  await reset.getByRole('alert').filter({ hasText: 'Your password could not be updated' }).waitFor()
  await reset.getByRole('button', { name: 'Update password' }).click()
  await reset.getByText('Password updated. Sign in with your new password.').waitFor()
  await page.getByText('There is new activity in your account security settings.', {exact:true}).waitFor()
  await signIn(reset, original, 401)
  await signIn(reset, changed, 200)
  await reset.getByRole('navigation', {name:'SecTalk features'}).getByRole('button',{name:'Profile',exact:true}).click()
  await reset.getByRole('button',{name:'Security',exact:true}).click()
  await reset.getByText(/Password change completed/).waitFor()
  console.log('Passed local signup, passive link preview, replay rejection, immediate recovery OTP, and another device receiving the password alert.')
} finally {
  await browser.close()
  if (range?.listening) await new Promise(resolve=>range.close(resolve))
  if (resend?.listening) await new Promise(resolve=>resend.close(resolve))
}
