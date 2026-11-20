import { recordingMeeting, recordingServices } from '../../../../../lib/meeting-recording-server'
import { readBoundedText } from '../../../../../lib/request-body'

export const runtime = 'nodejs'
const subscriptions = new Set(['participant_joined','participant_left','participant_connection_aborted','room_finished',
  'track_published','track_unpublished','egress_started','egress_ended'])

export async function POST(request: Request) {
  const services = recordingServices()
  if (!services) return new Response(null,{status:503})
  let event
  try {
    const body = await readBoundedText(request, 1024 * 1024)
    if (body === undefined) return new Response(null, { status: 413 })
    if (!body) return new Response(null, { status: 401 })
    event = await services.verifier.receive(body, request.headers.get('Authorization') ?? undefined)
  } catch {
    return new Response(null,{status:401})
  }
  const meeting = recordingMeeting(event.room?.name ?? event.egressInfo?.roomName)
  if (!meeting || !subscriptions.has(event.event)) return new Response(null,{status:204})
  try {
    const state = await services.command(meeting,null,'internal')
    if (state?.recording?.id) await services.reconcile(meeting,state.recording)
    return new Response(null,{status:204})
  } catch {
    return new Response(null,{status:503})
  }
}
