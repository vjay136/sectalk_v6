import { readFile } from 'node:fs/promises'
import { pathToFileURL } from 'node:url'
import { confirmationRedirect } from '../apps/web/lib/auth-confirmation-origin.mjs'

const signupHook = 'pg-functions://postgres/public/st_v7_before_signup'
const liveV5 = 'kgcnznxkxukbijgltdsf'

async function authReleaseSettings(siteUrl) {
  const callback = confirmationRedirect(siteUrl, 'http://localhost', true)
  if (!callback) throw new Error('SECTALK_APP_URL must be the deployed HTTPS web origin.')
  const [confirmation, recovery] = await Promise.all(['confirmation', 'recovery'].map(name =>
    readFile(new URL(`../supabase/templates/${name}.html`, import.meta.url), 'utf8').then(html => html.replace(/\r\n/g, '\n'))))
  return {
    callback,
    settings: {
      site_url: new URL(callback).origin,
      hook_before_user_created_enabled: true,
      hook_before_user_created_uri: signupHook,
      external_email_enabled: true,
      mailer_allow_unverified_email_sign_ins: false,
      mailer_autoconfirm: false,
      mailer_otp_length: 6,
      mailer_subjects_confirmation: 'Verify email for SecTalk',
      mailer_templates_confirmation_content: confirmation,
      mailer_subjects_recovery: 'Reset password for SecTalk',
      mailer_templates_recovery_content: recovery,
    },
  }
}

function authReleaseChanges(current, { callback, settings }) {
  const redirects = current.uri_allow_list?.split(',').map(value => value.trim()).filter(Boolean) ?? []
  const desired = redirects.includes(callback) ? settings : { ...settings, uri_allow_list: [...redirects, callback].join(',') }
  return Object.fromEntries(Object.entries(desired).filter(([key, value]) => current[key] !== value))
}

export async function configureAuthRelease({ ref, token, siteUrl, apply, request = fetch }) {
  if (!/^[a-z0-9]{20}$/.test(ref ?? '') || ref === liveV5) {
    throw new Error('Provide the separate v6 project ref in SECTALK_SUPABASE_PROJECT_REF.')
  }
  if (!token) throw new Error('Supply the Supabase management access token privately in SUPABASE_ACCESS_TOKEN.')
  const release = await authReleaseSettings(siteUrl)
  const endpoint = `https://api.supabase.com/v1/projects/${ref}/config/auth`
  const api = async (method, body) => {
    const response = await request(endpoint, {
      method, redirect: 'error', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: body && JSON.stringify(body), signal: AbortSignal.timeout(15_000),
    })
    if (!response.ok) throw new Error(`Supabase Auth config ${method} failed with HTTP ${response.status}.`)
    if (method === 'GET') {
      try {
        const config = await response.json()
        if (!config || typeof config.site_url !== 'string') throw new Error()
        return config
      } catch {
        throw new Error('Supabase returned an invalid Auth configuration response.')
      }
    }
  }
  const initial = await api('GET')
  const changes = authReleaseChanges(initial, release)
  const fields = Object.keys(changes)
  const smtpConfigured = Boolean(initial.smtp_host && initial.smtp_admin_email)
  if (!apply) return { project: ref, smtpConfigured, changed: [], pending: fields }
  if (!smtpConfigured) throw new Error('Configure a custom SMTP sender on the v6 project before applying the templates.')
  if (initial.hook_send_email_enabled) throw new Error('The v6 project has an active Send Email hook. Review delivery ownership before applying SMTP templates.')
  if (initial.hook_before_user_created_enabled && initial.hook_before_user_created_uri !== signupHook) {
    throw new Error('The v6 project already has a different active signup hook. Review it before replacing it.')
  }
  if (fields.length === 0) return { project: ref, smtpConfigured, changed: [], pending: [] }
  await api('PATCH', changes)
  const pending = Object.keys(authReleaseChanges(await api('GET'), release))
  return { project: ref, smtpConfigured, changed: fields.filter(field => !pending.includes(field)), pending }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  try {
    const options = process.argv.slice(2)
    if (options.length > 1 || (options.length === 1 && options[0] !== '--apply')) {
      throw new Error('Usage: node scripts/supabase-auth-release.mjs [--apply]')
    }
    const result = await configureAuthRelease({
      ref: process.env.SECTALK_SUPABASE_PROJECT_REF,
      token: process.env.SUPABASE_ACCESS_TOKEN,
      siteUrl: process.env.SECTALK_APP_URL,
      apply: options[0] === '--apply',
    })
    console.log(JSON.stringify(result))
    if (options[0] === '--apply' && result.pending.length) process.exitCode = 1
  } catch (error) {
    console.error(error.message)
    process.exitCode = 1
  }
}
