import { randomBytes } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { NextResponse, type NextRequest } from 'next/server'
import { allowedIntegrationOrigin, browserRequestOrigin, documentPolicy } from './lib/browser-request-policy'

const safeMethods = new Set(['GET', 'HEAD', 'OPTIONS'])
const integrationRead = /^\/api\/v1\/[^/]+$/
const noStore = { 'Cache-Control': 'no-store' }

function carriesAccountJwt(token:string) {
  if (token.length>8192) return false
  const [header,body,signature]=token.split('.')
  if (!header||!body||!signature) return false
  try {
    const claims=JSON.parse(Buffer.from(body,'base64url').toString('utf8'))
    return claims.role==='authenticated'
  } catch {return false}
}

async function apiAccountGate(request: NextRequest) {
  const authorization=request.headers.get('authorization')
  if (!authorization?.startsWith('Bearer ')||!carriesAccountJwt(authorization.slice(7))) return NextResponse.next()
  // This only denies access. A downstream route still authenticates the actual JWT.
  const url=process.env.NEXT_PUBLIC_SUPABASE_URL
  const key=process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY
  const headers={'Cache-Control':'no-store'}
  if (!url||!key) return NextResponse.json({error:'unavailable'},{status:503,headers})
  const requester=createClient(url,key,{
    auth:{persistSession:false,autoRefreshToken:false},global:{headers:{Authorization:authorization}},
  })
  const [risk,lock]=await Promise.all([
    requester.rpc('st_v7_login_risk_status'),requester.rpc('st_v7_account_lock_status'),
  ])
  const {data,error}=risk
  if (error||lock.error||data==='inactive') return NextResponse.json({error:'unauthorized'},{status:401,headers})
  if (lock.data?.locked&&request.nextUrl.pathname!=='/api/account/devices/bundle')
    return NextResponse.json({error:'account_locked'},{status:423,headers})
  if ((data==='email'||data==='refresh')&&request.nextUrl.pathname==='/api/account/devices/bundle')
    return NextResponse.next()
  if (data!=='clear') return NextResponse.json({error:'verification_required'},{status:403,headers})
  return NextResponse.next()
}

function apiBrowserGate(request: NextRequest) {
  const { pathname, protocol } = request.nextUrl
  const appOrigin = browserRequestOrigin(protocol, request.headers.get('host'))?.origin
  const origin = request.headers.get('origin')
  const crossOrigin = origin !== null && origin !== appOrigin
  const integration = integrationRead.test(pathname)
  const cors = integration && crossOrigin && allowedIntegrationOrigin(origin)
  if (!safeMethods.has(request.method) && (crossOrigin || request.headers.get('sec-fetch-site') === 'cross-site')) {
    return NextResponse.json({ error: 'request_origin_denied' }, { status: 403, headers: noStore })
  }
  if (request.method === 'OPTIONS' && crossOrigin) {
    const requestedHeaders = (request.headers.get('access-control-request-headers') ?? '').toLowerCase().split(',')
    const allowedHeaders = requestedHeaders.every(name => ['', 'authorization', 'accept'].includes(name.trim()))
    if (!cors || request.headers.get('access-control-request-method') !== 'GET' || !allowedHeaders) {
      return new NextResponse(null, { status: 403, headers: { ...noStore, Vary: 'Origin' } })
    }
    return new NextResponse(null, { status: 204, headers: { ...noStore,
      'Access-Control-Allow-Origin': origin!, 'Access-Control-Allow-Methods': 'GET',
      'Access-Control-Allow-Headers': 'Authorization, Accept', 'Access-Control-Max-Age': '300',
      Vary: 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers',
    } })
  }
  return null
}

export async function proxy(request: NextRequest) {
  const { pathname, protocol } = request.nextUrl
  if (pathname.startsWith('/api/')) {
    const rejected = apiBrowserGate(request)
    if (rejected) return rejected
    const response = await apiAccountGate(request)
    if (integrationRead.test(pathname)) {
      response.headers.append('Vary', 'Origin')
      const origin = request.headers.get('origin')
      if (request.method === 'GET' && allowedIntegrationOrigin(origin)) {
        response.headers.set('Access-Control-Allow-Origin', origin!)
      }
    }
    return response
  }

  const policy = documentPolicy(randomBytes(18).toString('base64'), pathname === '/meeting-guest')
  const headers = new Headers(request.headers)
  headers.set('Content-Security-Policy', policy)
  const response = NextResponse.next({ request: { headers } })
  response.headers.set('Content-Security-Policy', policy)
  response.headers.set('Cache-Control', 'private, no-store')
  if (protocol === 'https:') response.headers.set('Strict-Transport-Security', 'max-age=31536000')
  return response
}

export const config = { matcher: ['/api/:path*', '/((?!api/|_next/|.*\\.).*)'] }
