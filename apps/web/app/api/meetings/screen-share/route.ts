import { createHmac } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { RoomServiceClient, TrackSource, type ParticipantInfo } from 'livekit-server-sdk'
import { logProviderFailure } from '../../../../lib/provider-log.mjs'

export const runtime = 'nodejs'
const headers = { 'Cache-Control': 'no-store' }
const identifier = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i
const meetingSources = [TrackSource.CAMERA, TrackSource.MICROPHONE]
const screenSources = [TrackSource.SCREEN_SHARE, TrackSource.SCREEN_SHARE_AUDIO]

function allowsScreen(participant: ParticipantInfo) {
  const permission = participant.permission
  return permission?.canPublish && (
    !permission.canPublishSources.length || screenSources.some(source => permission.canPublishSources.includes(source))
  )
}

function isMissingParticipant(error: unknown) {
  return typeof error === 'object' && error !== null && 'status' in error && error.status === 404
}

function fail(message: string, status: number) {
  return Response.json({ error: message }, { headers, status })
}

export async function POST(request: Request) {
  const { LIVEKIT_URL: url, LIVEKIT_API_KEY: apiKey, LIVEKIT_API_SECRET: secret,
    NEXT_PUBLIC_SUPABASE_URL: authUrl, NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: publicKey } = process.env
  if (!url || !apiKey || !secret || !authUrl || !publicKey) return fail('Screen sharing is unavailable.', 503)
  const jwt = request.headers.get('Authorization')?.match(/^Bearer (\S+)$/i)?.[1]
  if (!jwt) return fail('Sign in to share your screen.', 401)
  const payload = await request.json().catch(() => null)
  const { meetingId: input, leaseId, action } = payload ?? {}
  if (typeof input !== 'string' || !identifier.test(input)
      || typeof leaseId !== 'string' || !identifier.test(leaseId)
      || !['claim', 'renew', 'release'].includes(action)) return fail('Choose a valid screen sharing action.', 400)
  const meetingId = input.toLowerCase()

  const client = createClient(authUrl, publicKey, {
    auth: { persistSession: false, autoRefreshToken: false }, global: { headers: { Authorization: 'Bearer ' + jwt } },
  })
  const { data, error } = await client.auth.getUser(jwt)
  if (error || !data.user) return fail('Sign in to share your screen.', 401)
  const userId = data.user.id
  const digest = createHmac('sha256', secret).update('sectalk-screen-share:' + meetingId + ':' + userId + ':' + leaseId).digest('hex')
  const room = 'sectalk-v3-' + meetingId
  const service = new RoomServiceClient(url.replace(/^ws/, 'http'), apiKey, secret, { requestTimeout: 5 })

  async function lease(operation: string) {
    const result = await client.rpc('st_v6_screen_presenter', { p_meeting: meetingId, p_lease_digest: digest, p_action: operation })
    if (result.error) throw result.error
    return result.data === true
  }

  async function setScreenPermission(participant: ParticipantInfo, enabled: boolean) {
    if (!participant.permission) throw new Error('Participant permissions are unavailable')
    const canPublishSources = enabled ? [...meetingSources, ...screenSources] : meetingSources
    try {
      await service.updateParticipant(room, participant.identity, {
        permission: { ...participant.permission, canPublishSources },
      })
    } catch (error) {
      if (enabled || !isMissingParticipant(error)) throw error
    }
  }

  try {
    if (action === 'renew') return await lease(action)
      ? Response.json({ sharing: true }, { headers }) : fail('Screen sharing permission has ended.', 403)

    if (action === 'release') {
      if (!await lease('closing')) return Response.json({ sharing: false }, { headers })
      try {
        const participant = await service.getParticipant(room, userId)
        if (allowsScreen(participant)) await setScreenPermission(participant, false)
      } catch (error) {
        if (!isMissingParticipant(error)) throw error
      }
      await lease('release')
      return Response.json({ sharing: false }, { headers })
    }

    const access = await client.rpc('st_v3_media_access', { p_meeting: meetingId })
    if (access.error) throw access.error
    if (!access.data) return fail('Join the live meeting before sharing your screen.', 403)
    const participant = await service.getParticipant(room, userId).catch(error => {
      if (!isMissingParticipant(error)) throw error
      return undefined
    })
    if (!participant?.permission?.canPublish) return fail('Connect to meeting media before sharing your screen.', 403)
    if (!await lease('claim')) return fail('Someone is already presenting.', 409)

    // Remove stale source permissions before granting the new presenter access.
    const participants = await service.listParticipants(room)
    await Promise.all(participants.filter(person => person.identity !== userId && allowsScreen(person))
      .map(person => setScreenPermission(person, false)))
    if (!await lease('renew')) return fail('Screen sharing permission has ended.', 403)
    await setScreenPermission(participant, true)
    if (!await lease('renew')) {
      await setScreenPermission(participant, false)
      return fail('Screen sharing permission has ended.', 403)
    }
    return Response.json({ sharing: true }, { headers })
  } catch {
    logProviderFailure('meeting_screen_share', 'unavailable')
    return fail('Could not update screen sharing. Try again.', 503)
  }
}
