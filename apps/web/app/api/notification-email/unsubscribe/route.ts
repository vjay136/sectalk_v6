import { emailHeaders, notificationEmailService } from '../../../../lib/notification-email-server'

export const runtime = 'nodejs'
const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i
const htmlHeaders = {
  ...emailHeaders, 'Content-Type': 'text/html; charset=utf-8',
  'Content-Security-Policy': "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
}

function page(content: string, status = 200) {
  return new Response('<!doctype html><html lang="en"><meta charset="utf-8"><title>SecTalk email preferences</title>'
    + '<main><h1>SecTalk email preferences</h1>' + content + '</main></html>', { status, headers: htmlHeaders })
}

function key(request: Request) {
  const key = new URL(request.url).searchParams.get('key')
  return key && uuid.test(key) ? key : null
}

export function GET(request: Request) {
  if (!key(request)) return page('<p>This unsubscribe link is unavailable.</p>', 400)
  return page('<p>Turn off all SecTalk notification emails.</p><form method="post"><button type="submit">Unsubscribe</button></form>')
}

export async function POST(request: Request) {
  const unsubscribeKey = key(request)
  if (!unsubscribeKey) return page('<p>This unsubscribe link is unavailable.</p>', 400)
  const service = notificationEmailService()
  if (!service) return page('<p>Unsubscribe is temporarily unavailable. Try again later.</p>', 503)
  const result = await service.rpc('st_v6_unsubscribe_notification_email', { p_key: unsubscribeKey })
  return result.error ? page('<p>Unsubscribe is temporarily unavailable. Try again later.</p>', 503)
    : page('<p>You are unsubscribed from SecTalk notification emails.</p>')
}
