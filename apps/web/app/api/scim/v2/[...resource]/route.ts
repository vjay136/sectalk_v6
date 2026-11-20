import { createHash } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { readBoundedText } from '../../../../../lib/request-body'

export const runtime = 'nodejs'

const core = 'urn:ietf:params:scim:schemas:core:2.0:'
const messages = 'urn:ietf:params:scim:api:messages:2.0:'
const idPattern = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i
const headers = { 'Cache-Control': 'private, no-store', 'Content-Type': 'application/scim+json' }
const detail: Record<number, string> = {
  400: 'Invalid SCIM request.', 401: 'A current provisioning token is required.',
  403: 'The requested identity or change is outside the provisioning scope.',
  404: 'SCIM resource not found.', 409: 'A resource already exists or the workspace seat limit was reached.',
  413: 'The request exceeds the size limit.', 429: 'The provisioning rate limit was reached.',
  503: 'Provisioning is temporarily unavailable.',
}

function error(status: number, scimType?: string) {
  return Response.json({ schemas: [messages + 'Error'], status: String(status), detail: detail[status], scimType }, {
    status, headers: { ...headers, ...(status === 401 ? { 'WWW-Authenticate': 'Bearer' } : {}),
      ...(status === 429 ? { 'Retry-After': '60' } : {}) },
  })
}
function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value)
}
function members(value: unknown) {
  if (!Array.isArray(value) || value.length > 1000) throw new Error()
  return value.map(member => {
    if (!isObject(member) || typeof member.value !== 'string' || !idPattern.test(member.value) ||
        (member.type !== undefined && member.type !== 'User')) throw new Error()
    return { value: member.value }
  })
}
function textValue(value: unknown, max: number, nullable: boolean) {
  if (value === null && nullable) return null
  if (typeof value !== 'string' || value.length > max || /[\u0000-\u001f\u007f]/.test(value)) throw new Error()
  return value
}
function fields(value: Record<string, unknown>, user: boolean) {
  const result: Record<string, unknown> = {}
  if ('userName' in value && user) result.userName = textValue(value.userName, 254, false)
  if ('externalId' in value) result.externalId = textValue(value.externalId, 160, true)
  if ('displayName' in value) result.displayName = textValue(value.displayName, user ? 120 : 80, user)
  if ('active' in value && user) {
    if (typeof value.active !== 'boolean') throw new Error()
    result.active = value.active
  }
  if ('members' in value && !user) result.members = members(value.members)
  // Auth credentials are managed through existing SecTalk identity flows.
  if ('password' in value || 'roles' in value || 'groups' in value) throw new Error()
  return result
}
function parseBody(value: unknown, method: string, user: boolean) {
  if (!isObject(value)) throw new Error()
  const expected = method === 'PATCH' ? messages + 'PatchOp' : core + (user ? 'User' : 'Group')
  if (!Array.isArray(value.schemas) || !value.schemas.includes(expected)) throw new Error()
  if (method !== 'PATCH') {
    const result = fields(value, user)
    if (!(user ? result.userName : result.displayName)) throw new Error()
    if (method === 'PUT' && user && result.active === undefined) result.active = true
    return result
  }
  if (!Array.isArray(value.Operations) || value.Operations.length < 1 || value.Operations.length > 20) throw new Error()
  const result: Record<string, unknown> = {}
  const memberOps = []
  for (const operation of value.Operations) {
    if (!isObject(operation) || typeof operation.op !== 'string') throw new Error()
    const op = operation.op.toLowerCase()
    if (!['add', 'replace', 'remove'].includes(op)) throw new Error()
    const path = operation.path
    const field = new Map([['username','userName'],['externalid','externalId'],['displayname','displayName'],
      ['active','active'],['members','members']])
    if (path === undefined && op !== 'remove' && isObject(operation.value)) {
      const additions = fields(operation.value, user)
      if (!Object.keys(additions).length) throw new Error()
      if (additions.members) {
        memberOps.push({ op, value: additions.members })
        delete additions.members
      }
      Object.assign(result, additions)
      continue
    }
    if (typeof path !== 'string') throw new Error()
    const name = field.get(path.toLowerCase())
    const match = /^members\[value eq "([a-f0-9-]{36})"\]$/i.exec(path)
    if (!user && op === 'remove' && match && idPattern.test(match[1])) {
      memberOps.push({ op, value: [{ value: match[1] }] })
    } else if (!user && name === 'members') {
      memberOps.push({ op: op === 'remove' && operation.value === undefined ? 'replace' : op,
        value: op === 'remove' && operation.value === undefined ? [] : members(operation.value) })
    } else if (name && name !== 'members' && (op !== 'remove' || name === 'displayName' || name === 'externalId')) {
      const values = fields({ [name]: op === 'remove' ? null : operation.value }, user)
      if (!(name in values)) throw new Error()
      Object.assign(result, values)
    } else throw new Error()
  }
  if (memberOps.length) result.memberOps = memberOps
  return result
}

type ScimRow = { id: string; [name: string]: unknown }
function render(base: string, kind: string, value: ScimRow) {
  const resourceType = kind === 'Users' ? 'User' : 'Group'
  const entries = Object.entries(value).filter(([, field]) => field !== null)
  return { schemas: [core + resourceType], ...Object.fromEntries(entries), meta: { resourceType, location: base + '/' + kind + '/' + value.id } }
}

async function handle(request: Request, context: RouteContext<'/api/scim/v2/[...resource]'>) {
  const auth = /^Bearer (stscim_[0-9a-f]{64})$/.exec(request.headers.get('authorization') ?? '')
  if (!auth) return error(401)
  const project = process.env.NEXT_PUBLIC_SUPABASE_URL
  const serviceKey = process.env.SECTALK_SCIM_SERVICE_KEY
  if (!project || !serviceKey) return error(503)
  const { resource: [kind, id, ...extra] } = await context.params
  const method = request.method
  const config = kind === 'ServiceProviderConfig'
  if (extra.length || !['Users','Groups','ServiceProviderConfig'].includes(kind) ||
      (config && (id || method !== 'GET')) || (id && !idPattern.test(id)) ||
      (method === 'POST' && id) || (!id && !['GET','POST'].includes(method))) return error(404)
  const url = new URL(request.url)
  const base = '/api/scim/v2'
  let filter: RegExpExecArray | null = null
  const filterQuery = url.searchParams.get('filter')
  if (filterQuery !== null) {
    if (id || method !== 'GET' || config || filterQuery.length > 1024) return error(400, 'invalidFilter')
    filter = /^(userName|displayName|externalId)\s+eq\s+("(?:[^"\\]|\\.)*")$/i.exec(filterQuery)
    if (!filter || (kind === 'Users' && filter[1].toLowerCase() === 'displayname') ||
      (kind === 'Groups' && filter[1].toLowerCase() === 'username')) return error(400, 'invalidFilter')
  }
  const index = url.searchParams.get('startIndex') ?? '1'
  const count = url.searchParams.get('count') ?? '100'
  if (!/^\d{1,7}$/.test(index) || !/^\d{1,7}$/.test(count)) return error(400, 'invalidValue')
  let body = {}
  if (['POST','PUT','PATCH'].includes(method)) {
    try {
      const input = await readBoundedText(request, 96 * 1024)
      if (input === undefined) return error(413)
      if (input === null) return error(400, 'invalidValue')
      body = parseBody(JSON.parse(input), method, kind === 'Users')
    }
    catch { return error(400, 'invalidValue') }
  }
  let filterValue: string | null = null
  try { filterValue = filter ? textValue(JSON.parse(filter[2]), 254, false) : null }
  catch { return error(400, 'invalidFilter') }
  try {
    const client = createClient(project, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } })
    const result = await client.rpc('st_v8_scim_request', { p_digest: createHash('sha256').update(auth[1]).digest('hex'),
      p_kind: kind, p_method: method, p_id: id ?? null, p_body: body, p_filter: filter?.[1].toLowerCase() ?? null,
      p_value: filterValue, p_start: Math.max(1, Number(index)), p_count: Math.min(100, Number(count)),
    }).abortSignal(AbortSignal.timeout(8000))
    if (result.error || !result.data) return error(503)
    const data = result.data
    if (data.status >= 400) return error(data.status)
    if (data.status === 204) return new Response(null, { status: 204, headers })
    if (config) return Response.json({
      schemas: [core + 'ServiceProviderConfig'], patch: { supported: true }, bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
      filter: { supported: true, maxResults: 100 }, changePassword: { supported: false }, sort: { supported: false },
      etag: { supported: false }, authenticationSchemes: [{ type: 'oauthbearertoken', name: 'Workspace provisioning token',
        description: 'Use the bearer token issued in SecTalk workspace settings.' }],
    }, { headers })
    if (Array.isArray(data.resources)) return Response.json({ schemas: [messages + 'ListResponse'], totalResults: data.total,
      startIndex: Math.max(1, Number(index)), itemsPerPage: data.resources.length,
      Resources: data.resources.map((row: ScimRow) => render(base, kind, row)),
    }, { headers })
    const resource = render(base, kind, data.resource)
    return Response.json(resource, { status: data.status, headers: { ...headers, Location: resource.meta.location } })
  } catch { return error(503) }
}
export { handle as GET, handle as POST, handle as PATCH, handle as PUT, handle as DELETE }
