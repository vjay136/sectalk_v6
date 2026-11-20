import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { ParticipantInfo_State, RoomServiceClient, TrackSource } from 'livekit-server-sdk'

export const runtime = 'nodejs'
const headers = { 'Cache-Control':'private, no-store', Vary:'Authorization' }
const uuid = /^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/i
const maxAudioBytes = 192000
const actions = new Set(['view','start','join','withdraw','stop'])

const fail = (status: number) => Response.json({ error:status===401 ? 'Sign in required.' : 'Captions unavailable.' },{status,headers})

function config() {
  const { NEXT_PUBLIC_SUPABASE_URL:url, NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:key, MEETING_CAPTIONS_SERVICE_KEY:service,
    MEETING_CAPTIONS_WORKER_URL:worker, MEETING_CAPTIONS_WORKER_TOKEN:secret,
    LIVEKIT_URL:livekit, LIVEKIT_API_KEY:roomKey, LIVEKIT_API_SECRET:roomSecret } = process.env
  if (!url || !key || !service || !worker || !secret || secret.length<24 || !livekit || !roomKey || !roomSecret) return null
  const endpoint = URL.parse(worker)
  if (!endpoint || endpoint.protocol!=='http:' || endpoint.hostname!=='127.0.0.1' || !endpoint.port ||
      endpoint.username || endpoint.password || endpoint.pathname!=='/transcribe' || endpoint.search || endpoint.hash) return null
  return { url,key,service,endpoint,secret,rooms:new RoomServiceClient(livekit.replace(/^ws/,'http'),roomKey,roomSecret,{requestTimeout:5}) }
}

async function session(request: Request) {
  const services = config()
  if (!services) return fail(503)
  const token = request.headers.get('Authorization')?.match(/^Bearer (\S+)$/i)?.[1]
  if (!token) return fail(401)
  const auth = { persistSession:false, autoRefreshToken:false }
  const { data,error } = await createClient(services.url,services.key,{auth}).auth.getUser(token)
  if (error || !data.user) return fail(401)
  const actor = data.user.id
  const db = createClient(services.url,services.service,{auth})
  async function participant(meeting: string) {
    const member = await services!.rooms.getParticipant('sectalk-v3-'+meeting,actor).catch(()=>null)
    return member?.state===ParticipantInfo_State.ACTIVE ? member : null
  }
  async function command(meeting: string, action: string, values: Record<string, unknown> = {}) {
    const result = await db.rpc('st_v6_meeting_caption_command',{p_meeting:meeting,p_actor:actor,p_action:action,...values})
    if (result.error) throw new Error('Caption state unavailable')
    return result.data
  }
  async function publish(meeting: string, sid: string, lease: string, text: string, samples: number) {
    const result = await db.rpc('st_v7_publish_metered_caption', {p_meeting: meeting, p_actor: actor,
      p_sid: sid, p_lease: lease, p_text: text, p_samples: samples})
    if (result.error) throw new Error('Caption state unavailable')
    return result.data
  }
  return { services, participant, command, publish }
}

export async function GET() {
  return Response.json({configured:config()!==null},{headers})
}

export async function POST(request: Request) {
  try {
    const context = await session(request)
    if (context instanceof Response) return context
    const { action, meeting, language, after } = await request.json().catch(()=>null) ?? {}
    if (typeof meeting!=='string' || !uuid.test(meeting) || !actions.has(action) ||
        (after!==undefined && (!Number.isInteger(after) || after<0 || after>2400))) return fail(400)
    const member = action==='withdraw' ? null : await context.participant(meeting)
    if (action==='start' || action==='stop' || action==='join') {
      const changed = await context.command(meeting,action,{p_sid:member?.sid ?? null,p_language:typeof language==='string'?language:null})
      if (!changed) return fail(403)
    } else if (action==='withdraw') {
      if (!await context.command(meeting,'withdraw')) return fail(403)
    }
    const state = await context.command(meeting,'view',{p_sid:member?.sid ?? null,p_after:after ?? 0})
      ?? (action==='withdraw' ? {active:false,host:false,admitted:false,language:null,consented:false,sending:false,lines:[]} : null)
    return state ? Response.json(state,{headers}) : fail(403)
  } catch { return fail(503) }
}

async function audioBody(request: Request, size: number) {
  const reader = request.body?.getReader()
  if (!reader) throw new Error('Audio required')
  const body = new Uint8Array(size)
  let offset = 0
  try {
    while (true) {
      const {done,value} = await reader.read()
      if (done) break
      if (offset+value.length>size) throw new Error('Audio size exceeded')
      body.set(value,offset)
      offset+=value.length
    }
    if (offset!==size) throw new Error('Audio incomplete')
    return body
  } finally { await reader.cancel().catch(()=>{}); reader.releaseLock() }
}

export async function PUT(request: Request) {
  const meeting = new URL(request.url).searchParams.get('meeting')
  const track = request.headers.get('X-Microphone-Track')
  const size = Number(request.headers.get('Content-Length'))
  if (!meeting || !uuid.test(meeting) || !track || track.length>80 || !Number.isInteger(size) ||
      size<1000 || size>maxAudioBytes || size%2 || request.headers.get('Content-Type')!=='application/octet-stream') return fail(400)
  try {
    const context = await session(request)
    if (context instanceof Response) return context
    const { participant } = context
    async function currentMicrophone(meetingId: string) {
      const member = await participant(meetingId)
      return member?.tracks.some(item=>item.sid===track && item.source===TrackSource.MICROPHONE && !item.muted) ? member.sid : null
    }
    const sid = await currentMicrophone(meeting)
    if (!sid) return fail(403)
    const lease = randomUUID()
    const allowed = await context.command(meeting,'reserve',{p_sid:sid,p_lease:lease})
    if (!allowed) return fail(403)
    const body = await audioBody(request,size)
    const current = await context.command(meeting,'process',{p_sid:sid,p_lease:lease})
    if (!current) return fail(403)
    const provider = await fetch(context.services.endpoint,{ method:'POST',redirect:'error',body,
      signal:AbortSignal.any([request.signal,AbortSignal.timeout(12000)]),
      headers:{Authorization:'Bearer '+context.services.secret,'X-Source-Language':current.language} })
    if (!provider.ok) return fail(503)
    const result = await provider.json()
    if (typeof result?.text!=='string' || result.text.length>500) return fail(503)
    if (await currentMicrophone(meeting)!==sid) return fail(403)
    const stored = await context.publish(meeting,sid,lease,result.text,body.byteLength / 2)
    return stored ? new Response(null,{status:204,headers}) : fail(403)
  } catch { return fail(503) }
}
