import { NextResponse, type NextRequest } from 'next/server'
import { proxy as browserProxy } from '../web/proxy'

export function proxy(request: NextRequest) {
  // The admission route evaluates session risk itself so an eligible operator can reach TOTP.
  if (request.method === 'GET' && request.nextUrl.pathname === '/api/operator/access') return NextResponse.next()
  return browserProxy(request)
}

export const config = { matcher: ['/api/:path*', '/((?!api/|_next/|.*\\.).*)'] }
