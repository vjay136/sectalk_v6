import { createClient } from '@supabase/supabase-js'
import nodemailer from 'nodemailer'
import { logProviderFailure } from '../../../../lib/provider-log.mjs'

export const runtime = 'nodejs'
const headers = { 'Cache-Control': 'no-store' }
const uuid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i
const mailbox = /^[^\s@<>,;:"]+@[a-z0-9.-]+\.[a-z0-9-]+$/i

function fail(error: string, status: number) {
  return Response.json({ error }, { status, headers })
}

function invitationOrigin() {
  const configured = process.env.SECTALK_APP_URL
  if (!configured) return null
  try {
    const url = new URL(configured)
    const local = url.protocol === 'http:' && url.hostname === '127.0.0.1' && !process.env.VERCEL
    if ((url.protocol === 'https:' || local) && [url.origin, url.origin + '/'].includes(configured)) return url.origin
  } catch { /* An invalid origin leaves email delivery unconfigured. */ }
  return null
}

function mailTransport() {
  const { SECTALK_INVITE_SMTP_HOST: host, SECTALK_INVITE_SMTP_PORT: portValue,
    SECTALK_INVITE_SMTP_FROM: from, SECTALK_INVITE_SMTP_USER: user, SECTALK_INVITE_SMTP_PASSWORD: pass } = process.env
  const port = Number(portValue)
  const loopback = host === '127.0.0.1' && !process.env.VERCEL
  if (!host || !from || !mailbox.test(from) || !Number.isSafeInteger(port) || port < 1 || port > 65535
    || (!loopback && (!user || !pass || ![465, 587, 2525].includes(port)))) return null
  return { from, transport: nodemailer.createTransport({
    host, port, secure: port === 465, requireTLS: !loopback && port !== 465,
    auth: user && pass ? { user, pass } : undefined,
    connectionTimeout: 4000, greetingTimeout: 4000, socketTimeout: 6000,
    disableFileAccess: true, disableUrlAccess: true, maxRecipients: 1,
  }) }
}

export async function POST(request: Request) {
  const jwt = request.headers.get('Authorization')?.match(/^Bearer (\S+)$/i)?.[1]
  if (!jwt) return fail('Sign in to create an invitation.', 401)
  const {
    NEXT_PUBLIC_SUPABASE_URL: authUrl, NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: publicKey,
  } = process.env
  if (!authUrl || !publicKey) return fail('Email invitations are unavailable.', 503)
  const payload = await request.json().catch(() => null)
  const email = typeof payload?.email === 'string' ? payload.email.trim().toLowerCase() : ''
  const { workspace, hours } = payload ?? {}
  if (!mailbox.test(email) || email.length > 254 || typeof workspace !== 'string' || !uuid.test(workspace)
    || ![24, 72, 168].includes(hours)) return fail('Enter a valid email and expiry.', 400)

  const client = createClient(authUrl, publicKey, {
    auth: { persistSession: false, autoRefreshToken: false },
    global: { headers: { Authorization: 'Bearer ' + jwt } },
  })
  const auth = await client.auth.getUser(jwt)
  if (auth.error || !auth.data.user) return fail('Sign in to create an invitation.', 401)
  const origin = invitationOrigin()
  const mail = mailTransport()
  if (!origin || !mail) return fail('Email delivery is unavailable. You can create an invitation link to share.', 503)
  const issued = await client.rpc('st_v6_workspace_link_create', {
    p_workspace: workspace, p_email: email, p_hours: hours,
  })
  if (issued.error) return fail('Could not create the invitation. Check the workspace email policy and try again.',
    issued.error.code === '42501' ? 403 : 400)
  const invitation = issued.data as { token: string; expires_at: string }
  const link = new URL('/invite', origin)
  link.hash = new URLSearchParams({ link: invitation.token }).toString()
  let delivered = false
  try {
    const result = await mail.transport.sendMail({
      from: { address: mail.from, name: 'SecTalk by Eagle Security' },
      to: { address: email, name: '' }, subject: 'Your SecTalk workspace invitation',
      text: 'A SecTalk workspace administrator invited you to join. Open this link and sign in with the invited email.\n\n'
        + link.href + '\n\nThis link can be used once and expires on ' + new Date(invitation.expires_at).toUTCString() + '.',
    })
    delivered = result.accepted.length === 1
  } catch {
    logProviderFailure('workspace_invitation_email', 'unavailable')
  }
  return Response.json({ url: link.href, expires: invitation.expires_at, delivered }, { headers })
}
