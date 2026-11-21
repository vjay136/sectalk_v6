import { timingSafeEqual } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { RoomServiceClient, TokenVerifier } from 'livekit-server-sdk'
import { readBoundedText } from '../../../../lib/request-body'
import { liveKitControlUrl } from '../../../../lib/livekit-control-url'
import { meetingBindingAttribute, parseMeetingMediaIdentity } from '../../../../lib/meeting-media-identity'

export const runtime = 'nodejs'
export const maxDuration = 30
const identifier = '[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
const roomShape = new RegExp('^sectalk-(v3|protected|group|network-check)-(' + identifier + ')(?:-([0-9]{1,9}))?$')
const meetingShape = new RegExp('^sectalk-(v3|protected)-(' + identifier + ')$')
const tokenShape = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/
const response = (status: number) => new Response(null, { status, headers: { 'Cache-Control': 'private, no-store' } })

function gatewayConfig(request: Request) {
  const { LIVEKIT_SIGNAL_AUTH_SECRET: shared, LIVEKIT_SIGNAL_SERVICE_KEY: serviceKey, LIVEKIT_API_KEY: key,
    LIVEKIT_API_SECRET: secret, NEXT_PUBLIC_SUPABASE_URL: project } = process.env
  if (!shared || shared.length < 32 || !serviceKey || !key || !secret || !project) return response(503)
  const expected = Buffer.from('Bearer ' + shared)
  const received = Buffer.from(request.headers.get('authorization') ?? '')
  if (received.length !== expected.length || !timingSafeEqual(received, expected)) return response(401)
  return { key, secret, project, serviceKey }
}

export async function POST(request: Request) {
  const config = gatewayConfig(request)
  if (config instanceof Response) return config
  const { key, secret, project, serviceKey } = config
  let token: string | null | undefined
  try { token = await readBoundedText(request, 8192) } catch { return response(400) }
  if (!token || !tokenShape.test(token)) return response(403)
  const grants = await new TokenVerifier(key, secret).verify(token, 0).catch(() => undefined)
  const match = roomShape.exec(grants?.video?.room ?? '')
  const identity = grants?.sub ? parseMeetingMediaIdentity(grants.sub) : null
  if (!identity || !match || grants?.video?.roomJoin !== true ||
      grants.video.roomAdmin || grants.video.roomCreate || grants.video.roomList || grants.video.roomRecord) return response(403)
  const kind = { v3: 'managed', protected: 'protected', group: 'group', 'network-check': 'network' }[match[1]]
  if ((kind === 'group') !== Boolean(match[3])) return response(403)
  const binding = grants.attributes?.[meetingBindingAttribute] ?? null
  if (binding !== identity.binding || (binding && grants.video.canUpdateOwnMetadata)) return response(403)
  try {
    const client = createClient(project, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } })
    const allowed = await client.rpc('st_v8_livekit_bound_admission', {
      p_kind: kind, p_room: match[2], p_actor: identity.actor, p_generation: match[3] ? Number(match[3]) : null,
      p_binding: binding ?? null,
    }).abortSignal(AbortSignal.timeout(2500))
    if (allowed.error) return response(503)
    return response(allowed.data === true ? 204 : 403)
  } catch { return response(503) }
}

export async function PUT(request: Request) {
  const config = gatewayConfig(request)
  if (config instanceof Response) return config
  const url = process.env.LIVEKIT_URL
  if (!url) return response(503)
  try {
    const rooms = new RoomServiceClient(liveKitControlUrl(url), config.key, config.secret, { requestTimeout: 5 })
    const client = createClient(config.project, config.serviceKey, { auth: { persistSession: false, autoRefreshToken: false } })
    const names = (await rooms.listRooms()).map(room => room.name).filter(name => meetingShape.test(name))
    let misses = 0
    async function reviewRoom(name: string) {
      const match = meetingShape.exec(name)!
      const kind = match[1] === 'v3' ? 'managed' : 'protected'
      const participants = await rooms.listParticipants(name)
      for (let i = 0; i < participants.length; i += 8) {
        const batch = participants.slice(i, i + 8)
        const results = await Promise.allSettled(batch.map(async person => {
          const identity = parseMeetingMediaIdentity(person.identity)
          if (!identity?.binding || person.attributes[meetingBindingAttribute] !== identity.binding) return
          const allowed = await client.rpc('st_v8_livekit_bound_admission', {
            p_kind: kind, p_room: match[2], p_actor: identity.actor, p_generation: null, p_binding: identity.binding,
          }).abortSignal(AbortSignal.timeout(2500))
          if (allowed.error) throw allowed.error
          if (allowed.data === false) await rooms.removeParticipant(name, person.identity)
        }))
        misses += results.filter(result => result.status === 'rejected').length
      }
    }
    for (let i = 0; i < names.length; i += 3) {
      const results = await Promise.allSettled(names.slice(i, i + 3).map(reviewRoom))
      misses += results.filter(result => result.status === 'rejected').length
    }
    return response(misses ? 503 : 204)
  } catch { return response(503) }
}
