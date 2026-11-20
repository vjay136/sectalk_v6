import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { saveExportResponse } from '../../../../lib/export-storage-server'

export const runtime = 'nodejs'
export const maxDuration = 30

const headers = { 'Cache-Control': 'no-store' }
const identifier = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i
const date = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/
type AuditRow = { id: number; source: 'workspace' | 'room' }

function fail(message: string, status: number) {
  return Response.json({ error: message }, { status, headers })
}

function signer() {
  const configured = process.env.SECTALK_AUDIT_SIGNING_PRIVATE_KEY
  if (!configured) return null
  try {
    const privateKey = createPrivateKey({ key: Buffer.from(configured, 'base64url'), format: 'der', type: 'pkcs8' })
    if (privateKey.asymmetricKeyType !== 'ed25519') return null
    const publicKey = createPublicKey(privateKey).export({ format: 'der', type: 'spki' })
    return { privateKey, publicKey, keyId: createHash('sha256').update(publicKey).digest('hex') }
  } catch {
    return null
  }
}

export function GET() {
  const keys = signer()
  if (!keys) return fail('Audit export signing is unavailable.', 503)
  return Response.json({
    algorithm: 'Ed25519', key_id: keys.keyId, public_key_spki: keys.publicKey.toString('base64url'),
  }, { headers })
}

export async function POST(request: Request) {
  const jwt = request.headers.get('Authorization')?.match(/^Bearer (\S+)$/i)?.[1]
  if (!jwt) return fail('Sign in to export audit entries.', 401)
  const { NEXT_PUBLIC_SUPABASE_URL: url, NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: publicKey } = process.env
  const keys = signer()
  if (!keys || !url || !publicKey) return fail('Audit export signing is unavailable.', 503)
  const input = await request.json().catch(() => null)
  const { workspace, query, source, from, before } = input ?? {}
  if (typeof workspace !== 'string' || !identifier.test(workspace) || typeof query !== 'string' || query.length > 120
    || ![null, 'workspace', 'room'].includes(source)
    || ![from, before].every(value => value === null || (typeof value === 'string' && date.test(value) && Number.isFinite(Date.parse(value))))
    || (from && before && from >= before)) return fail('Choose valid audit export filters.', 400)
  const client = createClient(url, publicKey, {
    auth: { persistSession: false, autoRefreshToken: false },
    global: { headers: { Authorization: 'Bearer ' + jwt } },
  })
  const auth = await client.auth.getUser(jwt)
  if (auth.error || !auth.data.user) return fail('Sign in to export audit entries.', 401)
  const proof=await client.rpc('st_v7_sensitive_action_status',{p_kind:'export'})
  if (proof.error||proof.data!=='verified') return fail('Enter a current authenticator code to export.',403)
  const filters = { workspace, query, source, from, before }
  const access = await client.rpc('st_v6_audit_integrity_status', { p_workspace: workspace, p_rows: [] })
  if (access.error || !access.data?.can_export) return fail('Verify workspace administrator access to export.', 403)
  const audit = await client.rpc('st_v6_audit_search', {
    p_workspace: workspace, p_query: query, p_source: source, p_from: from, p_before: before,
  })
  if (audit.error) return fail('Could not load audit entries for this workspace.', audit.error.code === '42501' ? 403 : 400)
  const refs = (audit.data as AuditRow[]).map(row => ({ source: row.source, id: row.id }))
  const integrity = await client.rpc('st_v6_audit_integrity_status', { p_workspace: workspace, p_rows: refs })
  if (integrity.error || !integrity.data?.can_export) return fail('Verify workspace administrator access to export.', 403)
  if (integrity.data.state === 'unavailable') return fail('Audit entries could not be matched to the journal.', 409)
  const recorded = await client.rpc('st_v6_record_audit_export', { p_workspace: workspace })
  if (recorded.error) return fail('Could not record audit export authorization.', recorded.error.code === '42501' ? 403 : 429)

  const payload = JSON.stringify({
    format: 'sectalk-workspace-audit-v1', exported_at: new Date().toISOString(), filters, integrity: integrity.data.state,
    last_local_checkpoint: integrity.data.last_local_checkpoint, limit: 100, entries: audit.data,
  }, null, 2)
  const envelope = JSON.stringify({
    algorithm: 'Ed25519', key_id: keys.keyId, payload,
    signature: sign(null, Buffer.from(payload, 'utf8'), keys.privateKey).toString('base64url'),
  })
  return saveExportResponse(auth.data.user.id, { kind: 'audit', scope_id: workspace },
    { filename: 'sectalk-audit.json', media_type: 'application/json' }, envelope)
}
