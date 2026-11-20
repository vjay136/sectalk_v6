import { createClient } from '@supabase/supabase-js'
import { readBoundedText } from '../../../../lib/request-body'
import { inspectionDomainSignals, normalizeInspectionUrl } from '../../../../lib/url-inspection-policy.mjs'

export const runtime = 'nodejs'
const headers = { 'Cache-Control': 'private, no-store', Vary: 'Authorization' }
const reply = (status: number, body: object) => Response.json(body, { status, headers })

function worker() {
  const target = URL.parse(process.env.SECTALK_URL_INSPECTION_WORKER_URL ?? '')
  const token = process.env.SECTALK_URL_INSPECTION_WORKER_TOKEN
  if (!target || target.protocol !== 'http:' || target.hostname !== '127.0.0.1' || !target.port ||
      target.username || target.password || target.pathname !== '/inspect' || target.search || target.hash ||
      !token || !/^[A-Za-z0-9_-]{24,128}$/.test(token)) return null
  return { target, token }
}

export async function POST(request: Request) {
  const bearer = request.headers.get('Authorization')
  const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY
  const base = process.env.NEXT_PUBLIC_SUPABASE_URL
  if (!bearer?.startsWith('Bearer ')) return reply(401, { error: 'Sign in to inspect a URL.' })
  if (!key || !base) return reply(503, { error: 'URL inspection unavailable.' })

  try {
    const session = createClient(base, key, { auth: { persistSession: false, autoRefreshToken: false },
      global: { headers: { Authorization: bearer } } })
    const result = await session.rpc('st_v7_authorize_url_inspection')
    if (result.error?.code === 'PT429' || result.error?.message === 'Too many requests') {
      return reply(429, { error: 'Too many URL checks. Try again in a minute.' })
    }
    if (result.error || !result.data) return reply(403, { error: 'URL inspection unavailable for this session.' })

    const body = await readBoundedText(request, 1800)
    if (!body) return reply(400, { error: 'Enter a web URL under 1,500 characters.' })
    const input = JSON.parse(body)
    const original = normalizeInspectionUrl(input?.url)
    if (!original) return reply(400, { error: 'Enter a web URL with a domain name and no embedded credentials.' })
    const offline = { normalized: original.url.href, stripped: original.stripped, outcome: 'unavailable',
      hops: [], domains: [{ ...inspectionDomainSignals(original.url), reputation: { status: 'unavailable' } }] }
    const allowed = await session.rpc('st_v7_link_policy_allows', { p_url: original.url.href })
    if (allowed.error || typeof allowed.data !== 'boolean') return reply(503, { error: 'Link policy is unavailable.' })
    if (input?.policyOnly === true) return reply(200, { allowed: allowed.data })
    if (!allowed.data) return reply(200, { ...offline, outcome: 'blocked' })
    const service = worker()
    if (!service) return reply(200, offline)
    try {
      const response = await fetch(service.target, { method: 'POST', body: JSON.stringify({ url: original.url.href }),
        redirect: 'error', cache: 'no-store', signal: AbortSignal.any([request.signal, AbortSignal.timeout(7500)]),
        headers: { Authorization: 'Bearer ' + service.token, 'Content-Type': 'application/json' },
      })
      if (!response.ok) return reply(200, offline)
      const raw = await readBoundedText(response, 8192)
      if (!raw) return reply(200, offline)
      const inspected = JSON.parse(raw)
      if (inspected?.normalized !== original.url.href || !['checked','blocked','unavailable','redirect-limit'].includes(inspected.outcome) ||
          !Array.isArray(inspected.hops) || inspected.hops.length > 4 || !Array.isArray(inspected.domains) || inspected.domains.length > 4) {
        return reply(200, offline)
      }
      return reply(200, { ...inspected, stripped: original.stripped })
    } catch { return reply(200, offline) }
  } catch { return reply(400, { error: 'Enter a web URL with a domain name.' }) }
}
