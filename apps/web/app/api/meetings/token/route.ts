import { AccessToken } from 'livekit-server-sdk'
import { createClient } from '@supabase/supabase-js'
import { logProviderFailure } from '../../../../lib/provider-log.mjs'

export const runtime = 'nodejs'
const headers = { 'Cache-Control': 'no-store' }

export function GET() {
  return Response.json({ mediaConfigured: Boolean(process.env.LIVEKIT_URL && process.env.LIVEKIT_API_KEY && process.env.LIVEKIT_API_SECRET) }, { headers })
}

export async function POST(request: Request) {
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
  const access = await client.rpc('st_v3_media_access', { p_meeting: meeting })
  if (access.error) {
    logProviderFailure('meeting_access','unavailable')
    return Response.json({ error: 'Meeting access could not be verified.' }, { status: 503, headers })
  }
  if (access.data !== true) return Response.json({ error: 'The host must admit you while the meeting is live.' }, { status: 403, headers })

  const { data: profile } = await client.from('st_profiles').select('name').eq('id', data.user.id).maybeSingle()
  try {
    const token = new AccessToken(apiKey, secret, { identity: data.user.id, name: profile?.name || 'SecTalk member', ttl: 120 })
    token.addGrant({ roomJoin: true, room: 'sectalk-v3-' + meeting, canPublish: true, canSubscribe: true, canPublishData: false })
    return Response.json({ url, token: await token.toJwt() }, { headers })
  } catch {
    logProviderFailure('meeting_signing','signing_failed')
    return Response.json({ error: 'Meeting media is temporarily unavailable.' }, { status: 503, headers })
  }
}
