import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(app.protocol, 'http:')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const fixtureToken = process.env.SECTALK_URL_INSPECTION_WORKER_TOKEN
assert.match(fixtureToken, /^[A-Za-z0-9_-]{24,128}$/)
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const handle = 'url_check_' + randomUUID().slice(0,8)
const email = handle + '@example.invalid'
const password = randomUUID() + '1!Q'
let browser
let fixture
let actor

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}
async function destinationHits() {
  const response = await fetch('http://127.0.0.1:3530/hits', {
    headers: { Authorization: 'Bearer ' + fixtureToken }, signal: AbortSignal.timeout(800),
  })
  assert.equal(response.status,200)
  return response.json()
}

try {
  fixture = spawn(process.execPath, ['--permission','--allow-net','--allow-fs-read=./package.json',
    '--allow-fs-read=./apps/web','--allow-fs-read=./scripts','--allow-fs-read=./tests','tests/url-inspection-fixture.mjs'],
  { windowsHide:true, stdio:['ignore','ignore','inherit'] })
  const ended = once(fixture,'exit')
  let ready = false
  for (let attempt = 0; attempt < 30; attempt++) {
    try { await destinationHits(); ready = true; break } catch { /* Let the isolated worker start. */ }
    await new Promise(resolve => setTimeout(resolve,200))
    if (fixture.exitCode !== null) break
  }
  assert.ok(ready)
  assert.equal((await fetch(new URL('/api/safety/url-inspection',app),{ method:'POST' })).status,401)
  assert.deepEqual(await destinationHits(),[])
  actor = data(await admin.auth.admin.createUser({email,password,email_confirm:true})).user
  const session = createClient(supabase.origin,publicKey,options)
  data(await session.auth.signInWithPassword({email,password}))
  data(await session.rpc('st_save_profile',{p_handle:handle,p_name:'Synthetic URL inspector'}))

  browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
  const page = await browser.newPage({ locale:'en-US' })
  await page.goto(app.href)
  await page.getByLabel('Email address',{exact:true}).fill(email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Safety',exact:true}).click()
  await page.getByRole('button',{name:'URL inspection',exact:true}).click()
  const inspector = page.getByRole('region',{ name:'URL inspection', exact:true })
  const address = inspector.getByLabel('Web address',{exact:true})
  await address.fill('https://approved-a.example.invalid/start?opaque=never-send#unknown-fragment')
  assert.deepEqual(await destinationHits(),[])
  await inspector.getByRole('button',{name:'Check recorded risk',exact:true}).click()
  await inspector.getByText('SecTalk checked its safety records.',{exact:true}).waitFor()
  await inspector.getByText(/No active SecTalk record matched/).waitFor()
  assert.deepEqual(await destinationHits(),[])
  await inspector.getByRole('button',{name:'Inspect URL',exact:true}).click()
  await inspector.getByText(/The worker checked response headers/).waitFor()
  await inspector.getByText('The query or fragment was omitted.',{exact:true}).waitFor()
  await inspector.getByText('Verified source Verified synthetic feed',{exact:true}).first().waitFor()
  await inspector.getByText(/Recently registered/).waitFor()
  await inspector.getByText(/feed lists this domain for security review/).waitFor()
  assert.equal(await inspector.getByRole('link').count(),0)
  assert.deepEqual(await destinationHits(),[
    {url:'/start',method:'HEAD',host:'approved-a.example.invalid',credentials:false},
    {url:'/landing',method:'HEAD',host:'approved-b.example.invalid',credentials:false},
  ])

  async function inspect(url,text) {
    await address.fill(url)
    await inspector.getByRole('button',{name:'Inspect URL',exact:true}).click()
    await inspector.getByText(text).waitFor()
  }
  await inspect('https://approved-a.example.invalid/outside',/stopped at a destination outside/)
  assert.equal((await destinationHits()).length,3)
  await inspect('https://p\u0430ypal.example.invalid/','The hostname resembles PayPal branding.')
  await inspector.getByText(/hostname contains an internationalized label/).waitFor()
  assert.equal((await destinationHits()).length,3)

  fixture.kill()
  await ended
  fixture = undefined
  await inspect('https://approved-a.example.invalid/start','Network inspection is unavailable for this URL.')
  await inspector.getByText('Verified reputation and registration data are unavailable.',{exact:true}).waitFor()
  console.log('PASS: deliberate inspection, actual sandboxed local worker, metadata-only HEAD redirects, verified synthetic feed, and unavailable fallback')
} finally {
  fixture?.kill()
  await browser?.close()
  if (actor) await admin.auth.admin.deleteUser(actor.id)
}
