import { Resolver } from 'node:dns/promises'
import { isIPv4 } from 'node:net'
import { createClient } from '@supabase/supabase-js'
import { readBoundedText } from '../../../../lib/request-body'

export const runtime = 'nodejs'
const auth = { autoRefreshToken: false, persistSession: false }
const headers = { 'Cache-Control': 'private, no-store', Vary: 'Authorization' }
const result = (status: number, value: object) => Response.json(value, { status, headers })
const uuid = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i
const domain = /^(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]*$/

function configuredResolver() {
  const setting = process.env.SECTALK_ORG_DNS_SERVER ?? ''
  const [host, port = '53', ...rest] = setting.split(':')
  if (rest.length || !isIPv4(host) || !/^\d{1,5}$/.test(port) || +port < 1 || +port > 65535) return null
  const resolver = new Resolver({ timeout: 1200, tries: 1 })
  resolver.setServers([host + ':' + port])
  return resolver
}

function regionAttestation() {
  const location = process.env.SECTALK_ORG_INFRA_REGION ?? ''
  const reference = process.env.SECTALK_ORG_INFRA_REGION_REFERENCE ?? ''
  if (!/^[a-z0-9][a-z0-9-]{1,31}$/.test(location) || !/^[A-Za-z0-9][A-Za-z0-9 ._/-]{3,100}$/.test(reference)) return null
  return { location, reference }
}

export async function POST(request: Request) {
  const bearer = request.headers.get('Authorization')
  const base = process.env.NEXT_PUBLIC_SUPABASE_URL
  const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY
  if (!bearer?.startsWith('Bearer ')) return result(401, { error: 'Sign in to view organization settings.' })
  if (!base || !key) return result(503, { error: 'Organization settings are unavailable.' })
  const session = createClient(base, key, { auth, global: { headers: { Authorization: bearer } } })
  let input
  try { input = JSON.parse(await readBoundedText(request, 512) ?? '') } catch {
    return result(400, { error: 'Invalid organization request.' })
  }
  if (typeof input?.workspace !== 'string' || !uuid.test(input.workspace)) return result(400, { error: 'Invalid workspace.' })
  const workspace: string = input.workspace
  if (input.action === 'region') {
    const access = await session.rpc('st_v7_org_settings', { p_workspace: workspace })
    return access.error ? result(403, { error: 'Organization settings are unavailable.' }) :
      result(200, { attestation: regionAttestation() })
  }
  if (input.action !== 'verify-domain' || typeof input.domain !== 'string' || input.domain.length > 225 || !domain.test(input.domain)) {
    return result(400, { error: 'Choose a pending domain to verify.' })
  }
  const proof = await session.rpc('st_v7_org_settings', { p_workspace: workspace, p_action: 'domain.proof', p_domain: input.domain })
  if (proof.error?.code === '22023') return result(409, { error: 'Start or renew the DNS challenge.' })
  if (proof.error?.code === 'PT429' || proof.error?.message === 'Too many requests') {
    return result(429, { error: 'Too many requests. Try again in a minute.' })
  }
  if (proof.error || !proof.data || !uuid.test(proof.data.challenge) || !uuid.test(proof.data.owner) ||
      !uuid.test(proof.data.session) || proof.data.domain !== input.domain) {
    return result(403, { error: 'Verify your current sign-in before checking the domain.' })
  }
  const service = process.env.SECTALK_ORG_DOMAIN_SERVICE_KEY
  const resolver = configuredResolver()
  if (!service || !resolver) return result(503, { error: 'The DNS verification service is unavailable.' })
  const { challenge, owner, session: sessionId } = proof.data
  const cancel = () => resolver.cancel()
  request.signal.addEventListener('abort', cancel, { once: true })
  try {
    if (request.signal.aborted) return result(503, { error: 'DNS verification was interrupted.' })
    const txt = await resolver.resolveTxt('_sectalk-verification.' + input.domain + '.')
    if (!txt.some(parts => parts.join('') === 'sectalk=' + challenge)) {
      return result(409, { error: 'The required TXT value is not published yet.' })
    }
    if (request.signal.aborted) return result(503, { error: 'DNS verification was interrupted.' })
    const finished = await createClient(base, service, { auth }).rpc('st_v7_finish_org_domain', {
      p_workspace: workspace, p_challenge: challenge, p_owner: owner, p_session: sessionId,
    })
    if (finished.error) return result(503, { error: 'Could not save the DNS verification result.' })
    return finished.data ? result(200, { verified: true }) : result(409, { error: 'The challenge changed or the domain is already verified elsewhere.' })
  } catch (cause) {
    const error = cause as NodeJS.ErrnoException
    const absent = error.code === 'ENODATA' || error.code === 'ENOTFOUND'
    return result(absent ? 409 : 503, { error: absent ? 'The required TXT value is not published yet.' : 'The DNS verification service is unavailable.' })
  } finally { request.signal.removeEventListener('abort', cancel) }
}
