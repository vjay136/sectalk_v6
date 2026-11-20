import { createClient } from '@supabase/supabase-js'
import { RoomServiceClient, TrackSource } from 'livekit-server-sdk'
import { logProviderFailure } from '../../../../lib/provider-log.mjs'

export const runtime = 'nodejs'
const headers = { 'Cache-Control': 'no-store' }
const identifier = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i
const actions = ['lock', 'chat', 'screen', 'mute', 'mute_all', 'remove', 'cohost', 'end']
const switches = ['lock', 'chat', 'screen', 'cohost']
const participantActions = ['mute', 'remove', 'cohost']

function fail(error: string, status: number) {
  return Response.json({ error }, { headers, status })
}

function missing(error: unknown) {
  return typeof error === 'object' && error !== null && 'status' in error && error.status === 404
}

export async function POST(request: Request) {
  const { NEXT_PUBLIC_SUPABASE_URL: authUrl, NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: publicKey,
    LIVEKIT_URL: url, LIVEKIT_API_KEY: apiKey, LIVEKIT_API_SECRET: secret } = process.env
  if (!authUrl || !publicKey) return fail('Meeting moderation is unavailable.', 503)
  const jwt = request.headers.get('Authorization')?.match(/^Bearer (\S+)$/i)?.[1]
  if (!jwt) return fail('Sign in to moderate this meeting.', 401)
  const { meetingId, action, target, enabled } = (await request.json().catch(() => null)) ?? {}
  if (typeof meetingId !== 'string' || !identifier.test(meetingId) || !actions.includes(action) ||
      (participantActions.includes(action) && (typeof target !== 'string' || !identifier.test(target))) ||
      (switches.includes(action) && typeof enabled !== 'boolean')) {
    return fail('Choose a valid meeting moderation action.', 400)
  }
  const meeting = meetingId.toLowerCase()
  const client = createClient(authUrl, publicKey, {
    auth: { persistSession: false, autoRefreshToken: false }, global: { headers: { Authorization: 'Bearer ' + jwt } },
  })
  const { data: auth, error: authError } = await client.auth.getUser(jwt)
  if (authError || !auth.user) return fail('Sign in to moderate this meeting.', 401)

  const result = await client.rpc('st_v6_moderate_meeting', {
    p_meeting: meeting, p_action: action,
    p_target: participantActions.includes(action) ? target : null, p_enabled: switches.includes(action) ? enabled : null,
  })
  if (result.error) {
    if (result.error.code === '42501') return fail('You cannot perform this action in this meeting.', 403)
    return fail('The meeting action could not be saved.', 503)
  }

  const success = (affected = 0) => Response.json({ affected }, { headers })
  if (!url || !apiKey || !secret) return success()
  const room = 'sectalk-v3-' + meeting
  const service = new RoomServiceClient(url.replace(/^ws/, 'http'), apiKey, secret, { requestTimeout: 5 })
  try {
    if (action === 'end') {
      await service.deleteRoom(room)
    } else if (action === 'remove') {
      await service.removeParticipant(room, target.toLowerCase())
    } else if (action === 'mute' || action === 'mute_all') {
      const targets = new Set<string>(result.data)
      const participants = await service.listParticipants(room)
      const microphones = participants.filter(person => targets.has(person.identity)).flatMap(person =>
        person.tracks.filter(track => track.source === TrackSource.MICROPHONE && !track.muted)
          .map(track => service.mutePublishedTrack(room, person.identity, track.sid, true).then(() => true).catch(error => {
            if (missing(error)) return false
            throw error
          })))
      return success((await Promise.all(microphones)).filter(Boolean).length)
    } else if (action === 'screen' && !enabled) {
      const { data: policy, error } = await client.from('st_v3_meetings').select('screen_share_disabled').eq('id', meeting).single()
      if (error) throw error
      if (!policy.screen_share_disabled) return success()
      const participants = await service.listParticipants(room)
      await Promise.all(participants.map(async person => {
        const permission = person.permission
        if (!permission?.canPublish) return
        const sources = permission.canPublishSources
        if (sources.length && !sources.includes(TrackSource.SCREEN_SHARE) && !sources.includes(TrackSource.SCREEN_SHARE_AUDIO)) return
        await service.updateParticipant(room, person.identity, {
          permission: { ...permission, canPublishSources: [TrackSource.CAMERA, TrackSource.MICROPHONE] },
        }).catch(error => {
          if (!missing(error)) throw error
        })
      }))
    }
    return success()
  } catch (error) {
    if (missing(error)) return success()
    logProviderFailure('meeting_moderation', 'unavailable')
    return fail(action === 'mute' || action === 'mute_all' ? 'Could not mute meeting audio. Try again.'
      : 'The meeting setting was saved. Its media update could not be confirmed.', 502)
  }
}
