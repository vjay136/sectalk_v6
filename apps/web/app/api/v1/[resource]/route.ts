import { apiKeyHash, integrationFailure, integrationHeaders, integrationsWriter, uuidPattern } from '../../../../lib/integration-server'

export const runtime = 'nodejs'

export async function GET(request: Request, context: RouteContext<'/api/v1/[resource]'>) {
  const { resource } = await context.params
  if (resource !== 'workspace' && resource !== 'rooms') return integrationFailure(404, 'Unknown API resource.')
  if (!integrationsWriter) return integrationFailure(503, 'The workspace API is unavailable.')
  const key = request.headers.get('Authorization')?.match(/^Bearer (sectalk_api_[A-Za-z0-9_-]{43})$/i)?.[1]
  if (!key) return integrationFailure(401, 'An API key is required.')
  const query = new URL(request.url).searchParams
  const limit = query.get('limit') ?? '25'
  const after = query.get('after')
  if (!/^(?:[1-9]|[1-9][0-9]|100)$/.test(limit) || (after !== null && !uuidPattern.test(after))) {
    return integrationFailure(400, 'Choose a valid page size and cursor.')
  }
  const { data, error } = await integrationsWriter.rpc('st_v6_integration_read', {
    p_digest: apiKeyHash(key), p_resource: resource, p_after: after, p_limit: Number(limit),
  })
  if (error?.code === 'PT401') return integrationFailure(401, 'The API key is invalid or expired.')
  if (error?.code === '42501') return integrationFailure(403, 'The API key cannot access this resource.')
  if (error?.code === 'PT429') return integrationFailure(429, 'The workspace API request limit was reached.')
  if (error || !data) return integrationFailure(503, 'Could not read this workspace resource.')
  return Response.json(data, { headers: integrationHeaders })
}
