import { timingSafeEqual } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import nodemailer from 'nodemailer'

export const emailHeaders = { 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff' }
const mailbox = /^[^\s@<>,;:"]+@[a-z0-9.-]+\.[a-z0-9-]+$/i

export function notificationEmailService() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL
  const key = process.env.SECTALK_NOTIFICATION_SUPABASE_KEY
  return url && key ? createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } }) : null
}

function appOrigin() {
  const configured = process.env.SECTALK_APP_URL
  if (!configured) return null
  try {
    const parsed = new URL(configured)
    const loopback = parsed.protocol === 'http:' && parsed.hostname === '127.0.0.1' && !process.env.VERCEL
    if ((parsed.protocol === 'https:' || loopback) && [parsed.origin, parsed.origin + '/'].includes(configured)) return parsed.origin
  } catch { return null }
  return null
}

export function notificationSMTPConfiguration() {
  const {
    SECTALK_NOTIFICATION_SMTP_HOST: host, SECTALK_NOTIFICATION_SMTP_PORT: portValue,
    SECTALK_NOTIFICATION_SMTP_FROM: from, SECTALK_NOTIFICATION_SMTP_USER: user,
    SECTALK_NOTIFICATION_SMTP_PASSWORD: pass,
  } = process.env
  const port = Number(portValue)
  const origin = appOrigin()
  const loopback = host === '127.0.0.1' && !process.env.VERCEL
  if (!origin || !host || !from || !mailbox.test(from)
    || !Number.isSafeInteger(port) || port < 1 || port > 65535
    || (!loopback && (!user || !pass || ![465, 587, 2525].includes(port)))) return null
  return { from, origin, transport: nodemailer.createTransport({
    host, port, secure: port === 465, requireTLS: !loopback && port !== 465,
    auth: user && pass ? { user, pass } : undefined,
    connectionTimeout: 4000, greetingTimeout: 4000, socketTimeout: 6000,
    disableFileAccess: true, disableUrlAccess: true, maxRecipients: 1,
  }) }
}

export function notificationMailConfiguration() {
  const secret = process.env.SECTALK_NOTIFICATION_DRAIN_SECRET
  if (!secret || Buffer.byteLength(secret) < 32) return null
  const mail = notificationSMTPConfiguration()
  return mail ? {...mail, secret} : null
}

export function notificationDrainAuthorized(request: Request, secret: string) {
  const provided = Buffer.from(request.headers.get('Authorization') ?? '')
  const expected = Buffer.from('Bearer ' + secret)
  return provided.length === expected.length && timingSafeEqual(provided, expected)
}

export type NotificationEmail = {
  recipient: string; lease: string; email: string; cadence: 'prompt' | 'daily' | 'weekly'
  unsubscribe_key: string; mentions: number; tasks: number; calls: number; delivery_id: string
}

export function notificationProviderFailure(error: unknown): 'retry' | 'rejected' {
  const responseCode = (error as {responseCode?: unknown} | null)?.responseCode
  return typeof responseCode === 'number' && responseCode >= 500 ? 'rejected' : 'retry'
}

export async function sendNotificationEmail(
  config: NonNullable<ReturnType<typeof notificationMailConfiguration>>, job: NotificationEmail,
) {
  if (!mailbox.test(job.email) || job.email.length > 254) return false
  const unsubscribe = new URL('/api/notification-email/unsubscribe', config.origin)
  unsubscribe.searchParams.set('key', job.unsubscribe_key)
  const inbox = new URL('/', config.origin)
  const counts = [[job.mentions, 'Room mentions'], [job.tasks, 'Task updates'], [job.calls, 'Missed calls']] as const
  const updates = counts.filter(([count]) => count > 0).map(([count, name]) => name + ': ' + count)
  const subjects = { prompt: 'Your SecTalk notification', daily: 'Your SecTalk daily digest', weekly: 'Your SecTalk weekly digest' }
  const result = await config.transport.sendMail({
    from: { address: config.from, name: 'SecTalk by Eagle Security' },
    to: { address: job.email, name: '' },
    subject: subjects[job.cadence],
    messageId: '<' + job.delivery_id + '@' + new URL(config.origin).hostname + '>',
    text: ['You have new activity in SecTalk.', '', ...updates, '', 'Open SecTalk: ' + inbox.href, '',
      'Unsubscribe from SecTalk notification emails: ' + unsubscribe.href].join('\n'),
    headers: { 'List-Unsubscribe': '<' + unsubscribe.href + '>', 'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click' },
  })
  return result.accepted.length === 1
}
