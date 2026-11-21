import assert from 'node:assert/strict'
import { test } from 'node:test'
import { configureAuthRelease } from '../scripts/supabase-auth-release.mjs'

const ref = 'fakesupabaseprojectx'
const siteUrl = 'https://app.sectalk.example'
const token = 'synthetic-management-token'

function project(settings = {}) {
  const config = { site_url: 'http://localhost:3000', uri_allow_list: 'https://admin.sectalk.example/auth/sso', ...settings }
  const requests = []
  const request = async (url, options) => {
    assert.equal(url, `https://api.supabase.com/v1/projects/${ref}/config/auth`)
    assert.equal(options.headers.Authorization, `Bearer ${token}`)
    assert.equal(options.redirect, 'error')
    requests.push(options.method)
    if (options.method === 'PATCH') Object.assign(config, JSON.parse(options.body))
    return Response.json(config)
  }
  return { config, requests, run: options => configureAuthRelease({ ref, token, siteUrl, request, ...options }) }
}

test('default Auth release inspection never writes and lists missing deployment settings', async () => {
  const fixture = project()
  const result = await fixture.run()
  assert.equal(result.smtpConfigured, false)
  assert.deepEqual(fixture.requests, ['GET'])
  assert.ok(result.pending.includes('site_url'))
  assert.ok(result.pending.includes('hook_before_user_created_uri'))
  assert.ok(result.pending.includes('mailer_templates_recovery_content'))
})

test('applying Auth release preserves other callbacks, uses link and OTP templates, and is idempotent', async () => {
  const fixture = project({ smtp_host: 'smtp.example', smtp_admin_email: 'auth@sectalk.example', mailer_otp_length: 8 })
  const result = await fixture.run({ apply: true })
  assert.deepEqual(result.pending, [])
  assert.deepEqual(fixture.requests, ['GET', 'PATCH', 'GET'])
  assert.equal(fixture.config.site_url, siteUrl)
  assert.equal(fixture.config.uri_allow_list, `https://admin.sectalk.example/auth/sso,${siteUrl}/auth/confirm`)
  assert.equal(fixture.config.hook_before_user_created_uri, 'pg-functions://postgres/public/st_v7_before_signup')
  assert.equal(fixture.config.hook_before_user_created_enabled, true)
  assert.equal(fixture.config.external_email_enabled, true)
  assert.equal(fixture.config.mailer_autoconfirm, false)
  assert.equal(fixture.config.mailer_allow_unverified_email_sign_ins, false)
  assert.equal(fixture.config.mailer_otp_length, 8)
  assert.match(fixture.config.mailer_templates_confirmation_content, /#token_hash=\{\{ \.TokenHash \}\}/)
  assert.match(fixture.config.mailer_templates_recovery_content, /\{\{ \.Token \}\}/)
  assert.doesNotMatch(fixture.config.mailer_templates_recovery_content, /ConfirmationURL/)
  assert.deepEqual((await fixture.run({ apply: true })).changed, [])
  assert.deepEqual(fixture.requests, ['GET', 'PATCH', 'GET', 'GET'])
  fixture.config.hook_send_email_enabled = true
  await assert.rejects(fixture.run({ apply: true }), /active Send Email hook/)
  fixture.config.hook_send_email_enabled = false
  fixture.config.smtp_host = null
  await assert.rejects(fixture.run({ apply: true }), /custom SMTP/)
  assert.deepEqual(fixture.requests.slice(-2), ['GET', 'GET'])
})

test('release rejects the v5 target, local redirects, missing SMTP and a different active hook', async () => {
  const fixture = project()
  await assert.rejects(fixture.run({ ref: 'kgcnznxkxukbijgltdsf', apply: true }), /separate v6 project/)
  await assert.rejects(fixture.run({ siteUrl: 'http://localhost:3000', apply: true }), /deployed HTTPS/)
  assert.deepEqual(fixture.requests, [])
  await assert.rejects(fixture.run({ apply: true }), /custom SMTP/)
  const conflicting = project({ smtp_host: 'smtp.example', smtp_admin_email: 'auth@sectalk.example',
    hook_before_user_created_enabled: true, hook_before_user_created_uri: 'pg-functions://postgres/public/other' })
  await assert.rejects(conflicting.run({ apply: true }), /different active signup hook/)
  assert.deepEqual(conflicting.requests, ['GET'])
  conflicting.config.hook_send_email_enabled = true
  await assert.rejects(conflicting.run({ apply: true }), /active Send Email hook/)
})
