import { createClient } from '@supabase/supabase-js'
import { evaluateImpersonationRules, impersonationFixtureVersion } from '../../../../lib/impersonation-rule-evaluation.mjs'

export const runtime = 'nodejs'

const headers = { 'Cache-Control': 'private, no-store', Vary: 'Authorization' }
const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i
const fail = (status: number) => Response.json({ error: 'Rule evaluation unavailable.' }, { status, headers })
const counts = (value: { tp: number; fp: number; tn: number; fn: number }) => [value.tp, value.fp, value.tn, value.fn]

export async function POST(request: Request) {
  const { NEXT_PUBLIC_SUPABASE_URL: url, NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: key, SECTALK_RULE_REGISTRY_SERVICE_KEY: service } = process.env
  if (!url || !key || !service) return fail(503)
  const token = request.headers.get('Authorization')?.match(/^Bearer (\S+)$/i)?.[1]
  if (!token) return fail(401)
  const { workspace } = await request.json().catch(() => ({})) ?? {}
  if (typeof workspace !== 'string' || !uuid.test(workspace)) return fail(400)

  try {
    const auth = { persistSession: false, autoRefreshToken: false }
    const member = createClient(url, key, { auth, global: { headers: { Authorization: 'Bearer ' + token } } })
    const user = await member.auth.getUser(token)
    if (user.error || !user.data.user) return fail(401)
    const registry = await member.rpc('st_v7_workspace_rule_registry', { p_workspace: workspace })
    if (registry.error || !registry.data?.owner) return fail(403)
    const { active, shadow, generation } = registry.data
    if (typeof active !== 'string' || typeof shadow !== 'string' || typeof generation !== 'string') return fail(409)

    // The classifier receives only the bundled synthetic cases. The caller cannot supply text, labels, or counts.
    const summary = evaluateImpersonationRules(active, shadow)
    const result = await createClient(url, service, { auth }).rpc('st_v7_record_profile_rule_evaluation', {
      p_workspace: workspace, p_actor: user.data.user.id, p_generation: generation, p_corpus: impersonationFixtureVersion,
      p_active_counts: counts(summary.active), p_shadow_counts: counts(summary.shadow), p_disagreements: summary.disagreements,
    })
    if (result.error) return fail(503)
    if (!result.data) return fail(409)
    return Response.json({ corpus: impersonationFixtureVersion, ...summary }, { headers })
  } catch {
    return fail(503)
  }
}
