import { createHash, randomBytes } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { NextRequest, NextResponse } from 'next/server'
import { readBoundedText } from '../../../../lib/request-body'

export const runtime = 'nodejs'
const noStore = { 'Cache-Control': 'private, no-store', 'Referrer-Policy': 'no-referrer' }
const cookieName = 'sectalk-workspace-sso'
const secretShape = /^[A-Za-z0-9_-]{43}$/
const domainShape = /^(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]*$/
const nativeSaml = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i
const nativeOidc = /^custom:[a-z0-9-]{1,48}$/
const bad = (status = 400) => NextResponse.json({ error: 'Workspace sign-in is unavailable. Contact your organization administrator.' },
  { status, headers: noStore })
const hash = (value: string, encoding: 'hex' | 'base64url') => createHash('sha256').update(value).digest(encoding)
const sdk = { auth: { persistSession: false, autoRefreshToken: false } }

function trustedOrigin(raw: string | undefined) {
  if (!raw) return null
  const url = URL.parse(raw)
  if (!url || (url.origin !== raw && url.origin + '/' !== raw)) return null
  return url.protocol === 'https:' || (!process.env.VERCEL && url.hostname === '127.0.0.1' && url.protocol === 'http:')
    ? url.origin : null
}
function canRedirect(url: URL | null) {
  return !!url && !url.username && !url.password && (url.protocol === 'https:' ||
    (!process.env.VERCEL && url.protocol === 'http:' && url.hostname === '127.0.0.1'))
}

export async function POST(request: NextRequest) {
  const project = trustedOrigin(process.env.NEXT_PUBLIC_SUPABASE_URL)
  const app = trustedOrigin(process.env.SECTALK_APP_URL)
  const upstream = trustedOrigin(process.env.SECTALK_SSO_AUTH_URL ?? process.env.NEXT_PUBLIC_SUPABASE_URL)
  const serviceKey = process.env.SECTALK_SSO_SERVICE_KEY
  const publicKey = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY
  if (!project || !app || !upstream || !serviceKey || !publicKey) return bad(503)
  if (request.headers.get('origin') !== app) return bad(403)
  const gateway = createClient(project, serviceKey, sdk)
  const headers = { apikey: publicKey, 'Content-Type': 'application/json' }
  const native = (path: string, body: object) => fetch(upstream + '/auth/v1/' + path, {
    method: 'POST', headers, body: JSON.stringify(body), redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(6500),
  })
  try {
    const raw = await readBoundedText(request, 1024)
    const input = JSON.parse(raw || '')
    if (input?.action === 'start') {
      const domain = typeof input.domain === 'string' ? input.domain.trim().toLowerCase() : ''
      if (domain.length > 225 || !domainShape.test(domain)) return bad()
      const attempt = randomBytes(32).toString('base64url')
      const verifier = randomBytes(32).toString('base64url')
      const challenge = hash(verifier, 'base64url')
      const started = await gateway.rpc('st_v7_workspace_sso_begin', { p_domain: domain, p_digest: hash(attempt, 'hex'), p_challenge: challenge })
      const provider = started.data?.provider
      if (started.error || typeof provider !== 'string') return bad(404)
      const redirectTo = app + '/auth/workspace-sso'
      let target: URL | null
      if (started.data.protocol === 'saml' && nativeSaml.test(provider)) {
        const response = await native('sso', { provider_id: provider, redirect_to: redirectTo, skip_http_redirect: true,
          code_challenge: challenge, code_challenge_method: 's256' })
        if (!response.ok) return bad(503)
        target = URL.parse((await response.json())?.url)
      } else if (started.data.protocol === 'oidc' && nativeOidc.test(provider)) {
        target = new URL(upstream + '/auth/v1/authorize')
        target.search = new URLSearchParams({ provider, redirect_to: redirectTo, code_challenge: challenge, code_challenge_method: 's256' }).toString()
      } else return bad(503)
      if (!canRedirect(target)) return bad(503)
      const response = NextResponse.json({ destination: target!.href }, { headers: noStore })
      response.cookies.set(cookieName, attempt + '.' + verifier, { httpOnly: true, sameSite: 'lax', secure: app.startsWith('https:'),
        maxAge: 600, path: '/api/auth/workspace-sso' })
      return response
    }
    if (input?.action !== 'complete' || typeof input.code !== 'string' || !nativeSaml.test(input.code)) return bad()
    const cookie = request.cookies.get(cookieName)?.value
    const [attempt, verifier, extra] = cookie?.split('.') ?? []
    if (extra || !secretShape.test(attempt ?? '') || !secretShape.test(verifier ?? '')) return bad(403)
    const digest = hash(attempt, 'hex')
    const claimed = await gateway.rpc('st_v7_workspace_sso_claim', {
      p_digest: digest, p_code: input.code, p_challenge: hash(verifier, 'base64url'),
    })
    if (claimed.error || !claimed.data || !nativeSaml.test(claimed.data.principal)) return bad(403)
    const issued = await native('token?grant_type=pkce', { auth_code: input.code, code_verifier: verifier })
    if (!issued.ok) return bad(403)
    const credential = await issued.json()
    if (typeof credential?.access_token !== 'string' || typeof credential?.refresh_token !== 'string' ||
        credential.user?.id !== claimed.data.principal) return bad(403)
    // The token came directly from the configured Auth endpoint. Verify its
    // signature externally as well before using the signed native claims.
    const auth = createClient(project, publicKey, sdk)
    const verified = await auth.auth.getUser(credential.access_token)
    if (verified.error || verified.data.user?.id !== claimed.data.principal) return bad(403)
    const claims = JSON.parse(Buffer.from(credential.access_token.split('.')[1] ?? '', 'base64url').toString())
    if (!nativeSaml.test(claims.session_id ?? '') || (claimed.data.protocol === 'saml' && (!Array.isArray(claims.amr) ||
      !claims.amr.some((item: { method?: string; provider?: string })=>item.method==='sso/saml'&&item.provider===claimed.data.provider)))) return bad(403)
    const complete = await gateway.rpc('st_v7_workspace_sso_finish', {
      p_digest: digest, p_actor: claimed.data.principal, p_session: claims.session_id,
    })
    if (complete.error || !nativeSaml.test(complete.data?.workspace ?? '')) {
      await gateway.auth.admin.signOut(credential.access_token, 'local').catch(()=>undefined)
      return bad(403)
    }
    const result = NextResponse.json({ access_token: credential.access_token, refresh_token: credential.refresh_token,
      workspace: complete.data.workspace }, { headers: noStore })
    result.cookies.set(cookieName, '', { httpOnly: true, sameSite: 'lax', secure: app.startsWith('https:'), maxAge: 0,
      path: '/api/auth/workspace-sso' })
    return result
  } catch { return bad() }
}
