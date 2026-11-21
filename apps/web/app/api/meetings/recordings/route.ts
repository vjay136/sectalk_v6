import { randomUUID } from 'node:crypto'
import { recordingFile, recordingHeaders, recordingId, recordingServices, recordingView } from '../../../../lib/meeting-recording-server'

export const runtime = 'nodejs'
const actions = new Set(['view','request','request-video','accept','withdraw','start','stop'])
const updateError = 'The recording action could not be completed.'

function fail(error: string, status: number) {
  return Response.json({ error }, { status, headers: recordingHeaders })
}

export async function GET(request: Request) {
  const services = recordingServices()
  const url = new URL(request.url)
  const meeting = url.searchParams.get('meeting')?.toLowerCase()
  const recording = url.searchParams.get('recording')?.toLowerCase()
  if (!meeting && !recording) return Response.json({ configured: services !== null }, { headers: recordingHeaders })
  if (!services || !meeting || !recording || !recordingId.test(meeting) || !recordingId.test(recording)) return fail('Recording unavailable.',404)
  const jwt = request.headers.get('Authorization')?.match(/^Bearer (\S+)$/i)?.[1]
  if (!jwt) return fail('Sign in to download the recording.',401)
  try {
    const viewer = await services.viewer(jwt)
    if (!viewer) return fail('Sign in to download the recording.',401)
    const allowed = await services.appCommand(meeting,viewer,'download')
    if (!allowed?.recording || allowed.recording.id !== recording) return fail('Recording unavailable.',404)
    const object = await services.download(allowed.recording,request.signal)
    if (!object.ok || !object.body) return fail('Recording unavailable.',404)
    const current = await services.appCommand(meeting,viewer,'download')
    if (current?.recording?.id !== recording) {
      await object.body.cancel().catch(() => {})
      return fail('Recording unavailable.',404)
    }
    const file = recordingFile(allowed.recording)
    const headers = { ...recordingHeaders, 'Content-Type':file.type, 'Content-Disposition':'attachment; filename="'+file.name+'"',
      'X-Content-Type-Options':'nosniff' }
    return new Response(object.body, { headers })
  } catch {
    return fail('Recording unavailable.',503)
  }
}

export async function POST(request: Request) {
  const services = recordingServices()
  if (!services) return fail('Recording is unavailable.',503)
  const jwt = request.headers.get('Authorization')?.match(/^Bearer (\S+)$/i)?.[1]
  if (!jwt) return fail('Sign in to manage meeting recording.',401)
  const { action, meeting: input, id } = await request.json().catch(() => null) ?? {}
  if (typeof input !== 'string' || !recordingId.test(input) || !actions.has(action) ||
      (['accept','withdraw','start','stop'].includes(action) && (typeof id !== 'string' || !recordingId.test(id)))) {
    return fail('Choose a valid recording action.',400)
  }
  const meeting = input.toLowerCase()
  try {
    const viewer = await services.viewer(jwt)
    if (!viewer) return fail('Sign in to manage meeting recording.',401)
    if (action === 'stop' || action === 'withdraw') {
      const result = await services.appCommand(meeting,viewer,action,id)
      if (!result?.recording?.id) return fail('Recording unavailable.',403)
      if (action === 'stop') await services.reconcile(meeting,result.recording)
      else await services.settle(result.recording)
      const visible = await services.appCommand(meeting,viewer,'view')
      return Response.json(visible ? recordingView(visible,viewer.actor) :
        {policy:false,owner:false,host:false,attendee:false,recording:null}, { headers: recordingHeaders })
    }
    const state = await services.appCommand(meeting,viewer,'view')
    if (!state) return fail('Recording unavailable.',403)
    if (action === 'view' && state.recording?.id) {
      await services.reconcile(meeting,state.recording).catch(() => {})
    } else if (action === 'request' || action === 'request-video' || action === 'accept' || action === 'start') {
      if (!state.attendee || !state.policy || (action !== 'accept' && !state.host)) return fail('Recording unavailable.',403)
      const requesting = action === 'request' || action === 'request-video'
      const owner = requesting ? (action === 'request-video' ? viewer.actor : undefined) : state.recording?.capture?.owner
      const { roster, microphones, capture } = await services.participants(meeting,owner)
      const recId = requesting ? randomUUID() : id
      if (action === 'request-video' && !capture) return fail('Turn on your camera before requesting single-camera recording.',409)
      if (action === 'start' && !microphones.length) return fail('At least one microphone must be published to start audio recording.',409)
      const result = await services.appCommand(meeting,viewer,requesting ? 'request' : action,recId,roster,capture)
      if (!result?.recording?.id) return fail('The recording roster or consent changed. Request consent again if needed.',409)
      if (action === 'start') {
        try { await services.start(result.recording,microphones) }
        catch {
          const rejected = await services.command(meeting,null,'discard',recId)
          if (rejected?.recording) await services.settle(rejected.recording).catch(() => {})
          return fail('The recording could not start. No recording is available.',502)
        }
      }
    }
    const current = await services.appCommand(meeting,viewer,'view')
    return current ? Response.json(recordingView(current,viewer.actor), { headers: recordingHeaders }) :
      fail('Recording unavailable.',403)
  } catch {
    return fail(updateError,503)
  }
}
