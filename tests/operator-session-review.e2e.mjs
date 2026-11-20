import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { fixtureAuthenticator, totpCode, verifyStaffPanel } from './workspace-admin-fixture.mjs'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const backend = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(backend.origin, 'http://127.0.0.1:55321')
const sdk = { auth: { persistSession: false, autoRefreshToken: false } }
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const service = createClient(backend.href, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, sdk)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const run = randomUUID().slice(0, 8)
const password = randomUUID() + '!1q'
const members = []
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })

function data(result) {
  if (result.error) throw result.error
  return result.data
}
function sql(statement) {
  return execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-At', '-v', 'ON_ERROR_STOP=1',
    '-U', 'postgres', '-d', 'postgres'], { input: statement, encoding: 'utf8', windowsHide: true }).trim()
}
async function account(role) {
  const handle = `os_${role}_${run}`
  const email = handle + '@example.invalid'
  const name = `Operator sessions ${role} ${run}`
  const { user } = data(await service.auth.admin.createUser({ email, password, email_confirm: true }))
  members.push(user.id)
  const client = createClient(backend.href, publicKey, sdk)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: name }))
  return { client, id: user.id, handle, name, email }
}
const nav = page => page.getByRole('navigation', { name: 'SecTalk features' })
async function signIn(actor, secret) {
  const page = await browser.newPage()
  await page.goto(app.href)
  await page.getByLabel('Email address', { exact: true }).fill(actor.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  if (secret) await verifyAuthenticator(page, secret)
  await nav(page).waitFor()
  return page
}
async function verifyAuthenticator(page, secret) {
  const code = page.getByLabel('Authenticator code', { exact: true })
  await code.waitFor()
  await code.fill(await totpCode(secret))
  await page.getByRole('button', { name: 'Verify authenticator', exact: true }).click()
}
async function token(page) {
  return page.evaluate(() => {
    const key = Object.keys(localStorage).find(name => /^sb-.+-auth-token$/.test(name))
    return JSON.parse(localStorage.getItem(key)).access_token
  })
}
const rpc = (jwt, name, params) => createClient(backend.href, publicKey, {
  ...sdk, global: { headers: { Authorization: 'Bearer ' + jwt } },
}).rpc(name, params)
const status = async jwt => data(await rpc(jwt, 'st_v7_login_risk_status'))
const claim = jwt => JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url'))
const checkRiskConsole = process.env.SECTALK_TEST_OPERATOR_RISK === '1'

try {
  const operator = await account('operator')
  const target = await account('target')
  const secret = checkRiskConsole ? (await fixtureAuthenticator(target.client)).secret : undefined
  sql(`insert into sectalk_private.st_v7_account_operators values('${operator.id}','operator');`)
  const targetOne = await signIn(target, secret)
  const targetTwo = await signIn(target, secret)
  const endedToken = await token(targetOne)
  const activeToken = await token(targetTwo)
  const endedId = claim(endedToken).session_id
  const activeId = claim(activeToken).session_id
  sql(`update auth.sessions set user_agent='Edg/123.0 fixture' where id='${endedId}';
    update auth.sessions set user_agent='Firefox/125.0 fixture' where id='${activeId}';
    insert into sectalk_private.st_v7_session_scores(session_id,user_id,score,signals,provider)
    values('${endedId}','${target.id}',65,array['impossible_travel'],'matched') on conflict(session_id) do update
      set score=excluded.score,signals=excluded.signals,provider=excluded.provider;`)
  const operatorPage = await signIn(operator)
  const beforeMfa = await token(operatorPage)
  assert.ok((await rpc(beforeMfa, 'st_v7_account_admin_sessions', { p_user: target.id })).error)
  assert.ok((await target.client.rpc('st_v7_account_admin_sessions', { p_user: operator.id })).error)
  await nav(operatorPage).getByRole('button', { name: 'Safety', exact: true }).click()
  await operatorPage.getByRole('group', { name: 'Safety center sections' })
    .getByRole('button', { name: 'Account administration', exact: true }).click()
  await verifyStaffPanel(operatorPage)
  if (checkRiskConsole) {
    const tabs = operatorPage.getByRole('group', { name: 'Account administration sections' })
    await tabs.getByRole('button', { name: 'High-risk sessions', exact: true }).click()
    const panel = operatorPage.getByRole('region', { name: 'High-risk sessions', exact: true })
    await panel.getByLabel('Unusually fast location changes only').check()
    const row = panel.getByRole('listitem').filter({ hasText: target.handle })
    await row.getByText('Unusually fast location change', { exact: true }).waitFor()
    await row.getByRole('button', { name: 'Require authenticator', exact: true }).click()
    await panel.getByLabel('Risk case reference and reason').fill('QA-R-102 suspected fast travel requires fresh proof')
    await panel.getByRole('button', { name: 'Confirm authenticator request', exact: true }).click()
    await row.getByText('Waiting for authenticator verification', { exact: true }).waitFor()
    assert.equal(await status(endedToken), 'authenticator')
    assert.equal(await status(activeToken), 'clear')
    await targetOne.getByRole('heading', { name: 'Verify your sign-in' }).waitFor()
    const challengedRead = await fetch(new URL(`/rest/v1/st_profiles?select=id&id=eq.${target.id}`, backend), {
      headers: { apikey: publicKey, Authorization: 'Bearer ' + endedToken },
    })
    assert.equal(challengedRead.status, 403)
    await new Promise(resolve => setTimeout(resolve, 1100))
    await verifyAuthenticator(targetOne, secret)
    await nav(targetOne).waitFor()
    assert.equal(await status(await token(targetOne)), 'clear')
    assert.equal(await status(endedToken), 'authenticator')
    await panel.getByRole('button', { name: 'Refresh risk sessions', exact: true }).click()
    await row.getByText('Authenticator verified', { exact: true }).waitFor()
    await row.getByRole('button', { name: 'End risk session', exact: true }).click()
    await panel.getByLabel('Risk case reference and reason').fill('QA-R-103 confirmed risky session ended')
    await panel.getByRole('button', { name: 'Confirm end risk session', exact: true }).click()
    await panel.getByText('Session ended.', { exact: true }).waitFor()
    await targetOne.getByRole('heading', { name: 'Sign in to SecTalk', exact: true }).waitFor()
    assert.equal(await status(activeToken), 'clear')
    assert.equal(sql(`select count(*) from sectalk_private.st_v7_account_admin_audit
      where target='${target.id}' and action in ('session_step_up','session_revoked');`), '2')
    console.log('Verified high-risk inventory, live targeted TOTP, stale AAL2 proof denial, successful native re-verification and audited termination.')
  } else {
  const admin = operatorPage.getByRole('region', { name: 'Account administration', exact: true })
  await admin.getByLabel('Name or handle', { exact: true }).fill(target.handle)
  await admin.getByRole('button', { name: 'Search accounts', exact: true }).click()
  await admin.getByRole('button', { name: target.name + ' (@' + target.handle + ')', exact: true }).click()
  const sessions = admin.getByRole('region', { name: 'Account sessions', exact: true })
  const flagged = sessions.getByRole('listitem').filter({ hasText: 'Unusually fast location change' })
  await flagged.getByText('High risk', { exact: false }).waitFor()
  await sessions.getByText('Firefox', { exact: true }).waitFor()
  await flagged.getByRole('button', { name: 'End session', exact: true }).click()
  await sessions.getByLabel('Session case reference and reason').fill('QA-S-10 verified individual revoked session')
  await sessions.getByRole('button', { name: 'Confirm end session', exact: true }).click()
  await admin.getByText('Individual session ended', { exact: true }).waitFor()
  await sessions.getByText('Firefox', { exact: true }).waitFor()
  assert.equal(await flagged.count(), 0)
  await targetOne.getByRole('heading', { name: 'Sign in to SecTalk', exact: true }).waitFor()
  await nav(targetTwo).waitFor()
  assert.ok((await target.client.auth.getUser(endedToken)).error)
  assert.equal(data(await target.client.auth.getUser(activeToken)).user.id, target.id)
  const stale = await fetch(new URL(`/rest/v1/st_profiles?select=id&id=eq.${target.id}`, backend), {
    headers: { apikey: publicKey, Authorization: 'Bearer ' + endedToken },
  })
  assert.ok(!stale.ok || (await stale.json()).length === 0)
  console.log('Verified fresh TOTP, risk projection, one-session termination, surviving device, native bearer denial and retained operator history.')
  }
} finally {
  await browser.close()
  if (members.length) {
    const ids = members.map(id => `'${id}'`).join(',')
    sql(`delete from sectalk_private.st_v7_account_admin_audit where actor in (${ids}) or target in (${ids});
      delete from auth.users where id in (${ids});`)
  }
}
