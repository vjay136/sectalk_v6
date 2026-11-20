import { createClient } from '@supabase/supabase-js'
import { draftMeetingSummary } from '../../../../lib/meeting-summary'

export const runtime = 'nodejs'
const headers = { 'Cache-Control':'private, no-store', Vary:'Authorization' }
const uuid = /^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/i
const actions = new Set(['view','policy','opt-in','withdraw','generate'])
const config = () => {
  const { NEXT_PUBLIC_SUPABASE_URL:url, NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:key, MEETING_CAPTIONS_SERVICE_KEY:service }=process.env
  return url && key && service ? {url,key,service} : null
}
const fail = (status:number) => Response.json({error:'Meeting summary unavailable.'},{status,headers})

export function GET() {
  return Response.json({configured:config()!==null},{headers})
}

export async function POST(request:Request) {
  const services=config()
  if (!services) return fail(503)
  const token=request.headers.get('Authorization')?.match(/^Bearer (\S+)$/i)?.[1]
  if (!token) return fail(401)
  const {meeting,action,enabled}=await request.json().catch(()=>null) ?? {}
  if (typeof meeting!=='string' || !uuid.test(meeting) || !actions.has(action) ||
    (action==='policy' && typeof enabled!=='boolean')) return fail(400)
  try {
    const auth={persistSession:false,autoRefreshToken:false}
    const {data,error}=await createClient(services.url,services.key,{auth}).auth.getUser(token)
    if (error || !data.user) return fail(401)
    const actor=data.user.id
    const db=createClient(services.url,services.service,{auth})
    async function command(commandAction:string) {
      const result=await db.rpc('st_v6_meeting_summary_command',{p_meeting:meeting,p_actor:actor,
        p_action:commandAction,p_enabled:action==='policy'?enabled:null})
      if (result.error) throw new Error('Meeting summary unavailable')
      return result.data
    }
    const raw=await command(action==='generate'?'source':action)
    if (!raw) return fail(403)
    const {source,language,...state}=raw
    if (action!=='generate') return Response.json(state,{headers})
    if (typeof language!=='string' || typeof state.revision!=='string' || !source?.length) return fail(409)
    const draft=draftMeetingSummary(source,language)
    const current=await command('view')
    if (!current?.revision || current.revision!==state.revision) return fail(409)
    return Response.json({...state,draft},{headers})
  } catch { return fail(503) }
}
