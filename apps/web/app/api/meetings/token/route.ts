import { withOperationalMetrics } from '../../../../lib/operational-metrics-server'
import { AccessToken, TrackSource } from 'livekit-server-sdk'
import { createClient } from '@supabase/supabase-js'
import { logProviderFailure } from '../../../../lib/provider-log.mjs'
import { meetingBindingAttribute, meetingMediaIdentity } from '../../../../lib/meeting-media-identity'

export const runtime = 'nodejs'
const headers = { 'Cache-Control': 'no-store' }

export function GET() {
  return Response.json({ mediaConfigured: Boolean(process.env.LIVEKIT_URL && process.env.LIVEKIT_API_KEY && process.env.LIVEKIT_API_SECRET) }, { headers })
}

async function handlePost(request: Request) {
  const url = process.env.LIVEKIT_URL
  const apiKey = process.env.LIVEKIT_API_KEY
  const secret = process.env.LIVEKIT_API_SECRET
  const authUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
  const publishable = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY
  if (!url || !apiKey || !secret || !authUrl || !publishable) return Response.json({ error: 'Live meeting media needs a configured media provider.' }, { status: 503, headers })
  const jwt = request.headers.get('Authorization')?.match(/^Bearer (\S+)$/i)?.[1]
  if (!jwt) return Response.json({ error: 'Sign in before joining.' }, { status: 401, headers })
  const payload = await request.json().catch(() => null)
  const meeting = payload?.meetingId
  if (typeof meeting !== 'string' || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(meeting)) {
    return Response.json({ error: 'Choose a valid meeting.' }, { status: 400, headers })
  }
  const client = createClient(authUrl, publishable, {
    auth: { persistSession: false, autoRefreshToken: false }, global: { headers: { Authorization: 'Bearer ' + jwt } },
  })
  const { data, error } = await client.auth.getUser(jwt)
  if (error || !data.user) return Response.json({ error: 'Sign in before joining.' }, { status: 401, headers })
  const [access, session] = await Promise.all([
    client.rpc('st_v3_media_access', { p_meeting: meeting }),
    client.rpc('st_v8_workspace_member_media_allowed', { p_meeting: meeting }),
  ])
  if (access.error || session.error) {
    logProviderFailure('meeting_access','unavailable')
    return Response.json({ error: 'Meeting access could not be verified.' }, { status: 503, headers })
  }
  if (access.data !== true) return Response.json({ error: 'The host must admit you while the meeting is live.' }, { status: 403, headers })
  if (session.data !== true) return Response.json({ error: 'Sign in with workspace single sign-on before joining media.' }, { status: 403, headers })

  try {
    if (payload.networkCheck === true) {
      const token = new AccessToken(apiKey, secret, { identity: data.user.id, ttl: 30 })
      token.addGrant({ roomJoin: true, room: 'sectalk-network-check-' + data.user.id, hidden: true,
        canPublish: false, canSubscribe: false, canPublishData: false })
      return Response.json({ url, token: await token.toJwt() }, { headers })
    }
    const [{ data: profile }, binding] = await Promise.all([
      client.from('st_profiles').select('name').eq('id', data.user.id).maybeSingle(),
      client.rpc('st_v8_livekit_bind_member', { p_meeting: meeting, p_kind: 'managed' }),
    ])
    if (binding.error) return Response.json({ error: 'Meeting access could not be verified.' }, { status: 503, headers })
    if (typeof binding.data !== 'string') return Response.json({ error: 'Sign in before joining media.' }, { status: 403, headers })
    const token = new AccessToken(apiKey, secret, { identity: meetingMediaIdentity(data.user.id, binding.data),
      name: profile?.name || 'SecTalk member', ttl: 120, attributes: { [meetingBindingAttribute]: binding.data } })
    token.addGrant({ roomJoin: true, room: 'sectalk-v3-' + meeting.toLowerCase(), canPublish: true, canSubscribe: true, canPublishData: false,
      canUpdateOwnMetadata: false,
      canPublishSources: [TrackSource.CAMERA, TrackSource.MICROPHONE] })
    return Response.json({ url, token: await token.toJwt() }, { headers })
  } catch {
    logProviderFailure('meeting_signing','signing_failed')
    return Response.json({ error: 'Meeting media is temporarily unavailable.' }, { status: 503, headers })
  }
}

export async function POST(request: Request) {
  return withOperationalMetrics('meeting_token', () => handlePost(request))
}
