import { NextResponse, type NextRequest } from 'next/server'
import { browserRequestOrigin, loopbackLocaleCookie, securedLocaleCookie } from '../../../../lib/browser-request-policy'
import { locales } from '../../../../lib/locale'

const headers = { 'Cache-Control': 'no-store' }

export async function POST(request: NextRequest) {
  const requestOrigin = browserRequestOrigin(request.nextUrl.protocol, request.headers.get('host'))
  if (!requestOrigin || request.headers.get('origin') !== requestOrigin.origin || request.headers.get('sec-fetch-site') === 'cross-site') {
    return NextResponse.json({ error: 'request_origin_denied' }, { status: 403, headers })
  }
  const secure = requestOrigin.protocol === 'https:'
  if (!secure && !['localhost', '127.0.0.1', '[::1]'].includes(requestOrigin.hostname)) {
    return NextResponse.json({ error: 'secure_transport_required' }, { status: 403, headers })
  }
  const locale = (await request.json().catch(() => null))?.locale
  if (typeof locale !== 'string' || !Object.hasOwn(locales, locale)) {
    return NextResponse.json({ error: 'invalid_locale' }, { status: 400, headers })
  }
  const response = new NextResponse(null, { status: 204, headers })
  response.cookies.set(secure ? securedLocaleCookie : loopbackLocaleCookie, locale, {
    path: '/', maxAge: 31536000, secure, httpOnly: true, sameSite: 'lax',
  })
  return response
}
