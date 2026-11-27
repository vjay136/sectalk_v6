import { liveKitControlUrl } from './livekit-control-url'
import { meetingArtifactViewer } from './meeting-artifact-viewer'
import { meetingBindingAttribute, parseMeetingMediaIdentity } from './meeting-media-identity'
import { supabaseApiFetch } from './supabase-api-fetch.mjs'
import { createClient } from '@supabase/supabase-js'
import {
  AudioCodec, EgressClient, EgressStatus, EncodedFileType, ParticipantInfo_State,
  RoomServiceClient, StartEgressRequest, TrackSource, VideoCodec, WebhookReceiver, type EgressInfo,
} from 'livekit-server-sdk'

export const recordingHeaders = { 'Cache-Control': 'private, no-store', Vary: 'Authorization' }
export const recordingId = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i
const roomPrefix = 'sectalk-v3-'
const bucket = 'recordings'
type Roster = Record<string, string>
type Capture = { owner: string; camera: string; microphones: string[] }
type RecordRow = {
  meeting_id: string; id: string; status: 'collecting'|'starting'|'recording'|'stopping'|'ready'|'discard'|'failed'
  roster: Roster; approvals: Record<string, boolean>; egress_id: string | null; attempted_at: string | null; capture: Capture | null
}
type State = { policy: boolean; owner: boolean; host: boolean; attendee: boolean; recording: RecordRow | null }
const phaseLive = new Set(['collecting','starting','recording','stopping'])
const activeEgress = new Set([EgressStatus.EGRESS_STARTING,EgressStatus.EGRESS_ACTIVE,EgressStatus.EGRESS_ENDING])
export const recordingFile = (row: RecordRow) => row.capture
  ? { name: 'meeting.mp4', type: 'video/mp4' }
  : { name: 'meeting.ogg', type: 'audio/ogg' }
const path = (row: RecordRow) => row.meeting_id + '/' + row.id + '/' + recordingFile(row).name
const roomName = (meeting: string) => roomPrefix + meeting

export function recordingServices() {
  const { NEXT_PUBLIC_SUPABASE_URL: authUrl, NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: publicKey,
    MEETING_RECORDING_SERVICE_KEY: serviceKey, MEETING_RECORDING_S3_ENDPOINT: endpoint,
    MEETING_RECORDING_S3_ACCESS_KEY: accessKey, MEETING_RECORDING_S3_SECRET: s3Secret,
    MEETING_RECORDING_WEBHOOK_URL: webhook, MEETING_RECORDING_EGRESS_URL: egressOverride,
    LIVEKIT_URL: livekit, LIVEKIT_API_KEY: apiKey, LIVEKIT_API_SECRET: secret } = process.env
  if (!authUrl || !publicKey || !serviceKey || !endpoint || !accessKey || !s3Secret || !webhook || !livekit || !apiKey || !secret) return null
  const storageHeaders = { Authorization: 'Bearer '+serviceKey, apikey: serviceKey }
  const authOptions = { persistSession: false, autoRefreshToken: false }
  const storageFetch = supabaseApiFetch(serviceKey)
  const storage = createClient(authUrl, serviceKey, { auth: authOptions, global: { fetch: storageFetch } })
  const provider = liveKitControlUrl(livekit)
  const rooms = new RoomServiceClient(provider, apiKey, secret, { requestTimeout: 5 })
  const egress = new EgressClient(egressOverride?.trim() || provider, apiKey, secret, { requestTimeout: 8 })
  const verifier = new WebhookReceiver(apiKey, secret)
  const s3 = { endpoint, accessKey, secret: s3Secret, bucket, region: process.env.MEETING_RECORDING_S3_REGION || 'us-east-1', forcePathStyle: true }

  async function command(meeting: string, actor: string|null, action: string, id?: string, roster?: Roster, egressId?: string, capture?: Capture) {
    const result = await storage.rpc('st_v6_recording_command', {
      p_meeting: meeting, p_actor: actor, p_action: action, p_recording: id ?? null, p_roster: roster ?? null,
      p_egress: egressId ?? null, p_capture: capture ?? null,
    })
    if (result.error) throw new Error('Recording state unavailable')
    return result.data as State | null
  }

  async function appCommand(meeting: string, viewer: {actor:string;session:string}, action: string, id?: string, roster?: Roster, capture?: Capture) {
    const result = await storage.rpc('st_v8_app_recording_command', {
      p_meeting: meeting, p_actor: viewer.actor, p_session: viewer.session, p_action: action,
      p_recording: id ?? null, p_roster: roster ?? null, p_capture: capture ?? null,
    })
    if (result.error) throw new Error('Recording state unavailable')
    return result.data as State | null
  }

  async function participants(meeting: string, cameraOwner?: string) {
    const members = await rooms.listParticipants(roomName(meeting))
    const roster: Roster = {}
    const microphones: string[] = []
    const cameras: string[] = []
    for (const person of members) {
      if (person.state !== ParticipantInfo_State.ACTIVE || person.kind === 2) continue
      const identity = parseMeetingMediaIdentity(person.identity)
      if (!identity || !person.sid ||
        (identity.binding && person.attributes[meetingBindingAttribute] !== identity.binding) ||
        Object.hasOwn(roster, identity.actor)) throw new Error('Unrecognized recording roster')
      roster[identity.actor] = person.sid
      for (const track of person.tracks) if (track.source === TrackSource.MICROPHONE && track.sid) microphones.push(track.sid)
      if (identity.actor === cameraOwner) {
        for (const track of person.tracks) {
          if (track.source === TrackSource.CAMERA && track.sid && !track.muted) cameras.push(track.sid)
        }
      }
    }
    return { roster, microphones, capture: cameraOwner && cameras.length === 1
      ? { owner: cameraOwner, camera: cameras[0], microphones: microphones.sort() } : undefined }
  }

  function matches(info: EgressInfo, row: RecordRow) {
    return info.roomName === roomName(row.meeting_id) && (row.egress_id ? info.egressId === row.egress_id
      : info.request.case === 'egress' && info.request.value.outputs.some(output =>
        output.config.case === 'file' && output.config.value.filepath === path(row)))
  }

  async function settle(row: RecordRow) {
    if (row.status !== 'discard' && row.status !== 'stopping' && row.status !== 'recording') return
    if (!row.egress_id && !row.attempted_at) {
      await command(row.meeting_id, null, 'cleaned', row.id)
      return
    }
    const found = await egress.listEgress(row.egress_id ? { egressId: row.egress_id } : { roomName: roomName(row.meeting_id) })
    let job = found.find(info => matches(info, row))
    if (!job) {
      if (row.status === 'discard' && !row.egress_id) await command(row.meeting_id, null, 'cleaned', row.id)
      return
    }
    if (!row.egress_id) {
      const attached = await command(row.meeting_id, null, 'attach', row.id, undefined, job.egressId)
      if (!attached?.recording) return
      row = attached.recording
    }
    if ((row.status === 'discard' || row.status === 'stopping') &&
      (job.status === EgressStatus.EGRESS_STARTING || job.status === EgressStatus.EGRESS_ACTIVE)) {
      job = await egress.stopEgress(job.egressId)
    }
    if (activeEgress.has(job.status)) return
    if (row.status === 'stopping' && job.status === EgressStatus.EGRESS_COMPLETE) {
      const file = job.fileResults.find(item => item.size > 0n &&
        (item.filename === path(row) || item.filename.endsWith('/' + path(row))))
      if (file) {
        const nanoseconds = file.duration > 0n ? file.duration : file.endedAt - file.startedAt
        const duration = (nanoseconds + 999999n) / 1000000n
        if (duration < 1n || duration > 86400000n) throw new Error('Recording duration unavailable')
        const completed = await storage.rpc('st_v7_complete_metered_recording', {p_meeting: row.meeting_id,
          p_recording: row.id, p_egress: job.egressId, p_duration_ms: Number(duration)})
        if (completed.error) throw new Error('Recording state unavailable')
        if (completed.data) return
      }
    }
    const discarded = await command(row.meeting_id, null, 'discard', row.id)
    if (discarded?.recording?.status !== 'discard' || discarded.recording.egress_id !== job.egressId) return
    const removed = await storage.storage.from(bucket).remove([path(row)])
    if (!removed.error) await command(row.meeting_id, null, 'cleaned', row.id, undefined, job.egressId)
  }

  async function reconcile(meeting: string, row: RecordRow) {
    let current = row
    if (phaseLive.has(row.status)) {
      let live: Awaited<ReturnType<typeof participants>> | undefined
      try { live = await participants(meeting, row.capture?.owner) } catch {}
      current = (await command(meeting, null, 'invalidate', row.id, live?.roster, undefined, live?.capture))?.recording ?? row
    }
    await settle(current)
  }

  async function start(row: RecordRow, tracks: string[]) {
    const routes = (row.capture?.microphones ?? tracks).map(track => ({ match: { case: 'trackId' as const, value: track } }))
    const started = await egress.startEgress(new StartEgressRequest({
      roomName: roomName(row.meeting_id),
      source: { case: 'media', value: {
        audio: routes.length ? { captureAll: false, routes } : undefined,
        video: row.capture ? { case: 'videoTrackId', value: row.capture.camera } : undefined,
      } },
      encoding: { case: 'advanced', value: row.capture
        ? { audioCodec: AudioCodec.AAC, videoCodec: VideoCodec.H264_MAIN, width: 960, height: 540, framerate: 24 }
        : { audioCodec: AudioCodec.OPUS } },
      outputs: [{ config: { case: 'file', value: { filepath: path(row), fileType: row.capture ? EncodedFileType.MP4 : EncodedFileType.OGG, disableManifest: true } } }],
      storage: { provider: { case: 's3', value: s3 } },
      webhooks: [{ url: webhook, signingKey: apiKey }],
    }))
    if (started.roomName !== roomName(row.meeting_id) || !started.egressId) throw new Error('Recording provider response unavailable')
    const attached = await command(row.meeting_id, null, 'attach', row.id, undefined, started.egressId)
    if (!attached?.recording) {
      if (activeEgress.has(started.status)) await egress.stopEgress(started.egressId)
      throw new Error('Recording could not attach')
    }
    if (attached.recording.status === 'discard' || !activeEgress.has(started.status)) await settle(attached.recording)
  }

  function download(row: RecordRow, signal: AbortSignal) {
    return storageFetch(new URL('/storage/v1/object/authenticated/'+bucket+'/'+path(row), authUrl), {
      headers: storageHeaders,
      cache: 'no-store', signal,
    })
  }
  return { viewer: (token:string) => meetingArtifactViewer(authUrl,publicKey,token),
    command, appCommand, participants, reconcile, start, settle, verifier, download }
}

export function recordingView(state: State, actor: string) {
  const rec = state.recording?.id ? state.recording : null
  return { policy: state.policy, owner: state.owner, host: state.host, attendee: state.attendee, recording: rec ? {
    mode: rec.capture ? 'single-camera' : 'audio',
    id: rec.id, status: rec.status, eligible: Object.hasOwn(rec.roster, actor), accepted: rec.approvals[actor] === true,
    count: Object.keys(rec.roster).length, approved: Object.keys(rec.approvals).length,
  } : null }
}

export function recordingMeeting(room: string | undefined) {
  const id = room?.startsWith(roomPrefix) && room.slice(roomPrefix.length)
  return typeof id === 'string' && recordingId.test(id) ? id.toLowerCase() : null
}
