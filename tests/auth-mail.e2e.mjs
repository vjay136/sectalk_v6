// Requires the local web app, Supabase Auth, Mailpit, and the Playwright browser test library.
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { setTimeout } from 'node:timers/promises'

const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const app = process.env.SECTALK_AUTH_TEST_APP || 'http://127.0.0.1:3484'
const mail = process.env.SECTALK_AUTH_TEST_MAIL || 'http://127.0.0.1:55324'
for (const address of [app, mail]) assert.equal(new URL(address).hostname, '127.0.0.1')

const email = 'sectalk-qa-' + randomBytes(8).toString('hex') + '@example.org'
const original = randomBytes(24).toString('base64url') + '!g5'
const changed = randomBytes(24).toString('base64url') + '!h6'
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })

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
  const response = page.waitForResponse(result => result.url().includes('/auth/v1/token?grant_type=password'))
  await page.locator('button.submit-auth').click()
  assert.equal((await response).status(), expected)
}

try {
  const page = await browser.newPage()
  await page.goto(app + '/#account')
  const disclosure=page.getByRole('link',{name:'Security disclosures',exact:true})
  assert.equal(await disclosure.getAttribute('href'),'/security')
  await page.getByRole('button', { name: 'Create account', exact: true }).click()
  await page.getByLabel('Email address', { exact: true }).fill(email)
  await page.getByLabel('Password', { exact: true }).fill(original)
  await page.getByLabel('Confirm password', { exact: true }).fill(original)
  await page.locator('button.submit-auth').click()
  await page.getByRole('heading', { name: 'Check your email' }).waitFor()

  const signup = await delivered('verify email')
  const link = signup.HTML.match(/href="([^"]*\/auth\/confirm#[^"]+)"/)?.[1]
  assert.ok(link, 'The signup email must contain the app confirmation link')
  assert.equal(new URL(link).origin, app)

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

  const replay = await browser.newPage()
  await replay.goto(link)
  await replay.getByRole('button', { name: 'Verify my email' }).click()
  await replay.getByRole('heading', { name: 'This link is invalid or expired' }).waitFor()
  await replay.close()

  const reset = await browser.newPage()
  await reset.goto(app + '/#account')
  await reset.getByRole('button', { name: 'Forgot password?' }).click()
  await reset.getByLabel('Email address', { exact: true }).fill(email)
  await reset.getByRole('button', { name: 'Send recovery code' }).click()
  await reset.getByRole('heading', { name: 'Verify your recovery code' }).waitFor()
  const recovery = await delivered('reset password')
  const code = recovery.HTML.match(/>\s*(\d{6})\s*</)?.[1]
  assert.ok(code, 'The recovery email must contain a numeric OTP')
  await reset.getByLabel('Verification code').fill(code)
  await reset.getByRole('button', { name: 'Verify code' }).click()
  await reset.getByRole('heading', { name: 'Set a new password' }).waitFor()
  await reset.getByLabel('Password', { exact: true }).fill(changed)
  await reset.getByLabel('Confirm password', { exact: true }).fill(changed)
  await reset.getByRole('button', { name: 'Update password' }).click()
  await reset.getByText('Password updated. Sign in with your new password.').waitFor()
  await signIn(reset, original, 400)
  await signIn(reset, changed, 200)
  console.log('Passed local signup email, passive link preview, confirmation, replay rejection, recovery OTP, and password replacement.')
} finally {
  await browser.close()
}
