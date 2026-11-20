import { randomBytes } from 'node:crypto'
import { apiKeyHash, integrationFailure, integrationHeaders, integrationIdentity, uuidPattern } from '../../../../lib/integration-server'

export const runtime = 'nodejs'

export async function POST(request: Request) {
  const client = await integrationIdentity(request)
  if (!client) return integrationFailure(401, 'Sign in to manage integration keys.')
  const selection = await request.json().catch(() => null)
  if (typeof selection?.workspace !== 'string' || !uuidPattern.test(selection.workspace)) {
    return integrationFailure(400, 'Choose a valid workspace.')
  }
  const workspace = selection.workspace
  if (selection.action === 'revoke' && typeof selection.key === 'string' && uuidPattern.test(selection.key)) {
    const result = await client.rpc('st_v6_revoke_integration_key', { p_workspace: workspace, p_key: selection.key })
    if (result.error?.code === '42501') return integrationFailure(403, 'Verified integration access required.')
    return result.error ? integrationFailure(503, 'Could not revoke the key.') : new Response(null, { status: 204, headers: integrationHeaders })
  }
  if (selection.action !== 'create' || typeof selection.label !== 'string' || selection.label.length > 48
    || !Array.isArray(selection.scopes) || selection.scopes.length < 1 || selection.scopes.length > 2
    || !selection.scopes.every((scope: unknown) => scope === 'workspace:read' || scope === 'rooms:read')
    || !Number.isInteger(selection.lifetime) || selection.lifetime < 1 || selection.lifetime > 365) {
    return integrationFailure(400, 'Choose a label, API scopes and expiry.')
  }
  const raw = randomBytes(32).toString('base64url')
  const key = 'sectalk_api_' + raw
  const result = await client.rpc('st_v6_create_integration_key', {
    p_workspace: workspace, p_label: selection.label, p_prefix: raw.slice(0, 10),
    p_digest: apiKeyHash(key), p_scopes: selection.scopes, p_lifetime_days: selection.lifetime,
  })
  if (result.error?.code === '42501') return integrationFailure(403, 'Verified integration access required.')
  if (result.error?.code === '22023') return integrationFailure(400, result.error.message)
  if (result.error?.code === 'PT429') return integrationFailure(429, 'Try again in a minute.')
  if (result.error || typeof result.data !== 'string') return integrationFailure(503, 'Could not create the key.')
  return Response.json({ id: result.data, key }, { status: 201, headers: integrationHeaders })
}
