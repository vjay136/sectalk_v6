import { liveKitControlUrl } from '../../../../lib/livekit-control-url'
import { meetingBindingAttribute, meetingMediaIdentity } from '../../../../lib/meeting-media-identity'
import { createClient } from '@supabase/supabase-js'
import { AccessToken, RoomServiceClient, TrackSource } from 'livekit-server-sdk'

const headers={'Cache-Control':'private, no-store',Vary:'Authorization'}
const uuid=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i
const fail=(status:number)=>Response.json({error:'Protected meeting unavailable.'},{status,headers})
const auth={persistSession:false,autoRefreshToken:false}
function config() {
  const {NEXT_PUBLIC_SUPABASE_URL:url,NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:key,
    PROTECTED_MEETING_SERVICE_KEY:service,LIVEKIT_URL:livekit,LIVEKIT_API_KEY:apiKey,LIVEKIT_API_SECRET:secret}=process.env
  return url&&key&&service&&livekit&&apiKey&&secret ? {url,key,service,livekit,apiKey,secret} : null
}
export function GET() {
  return Response.json({configured:config()!==null},{headers})
}
export async function POST(request:Request) {
  const settings=config()
  if (!settings) return fail(503)
  const jwt=request.headers.get('Authorization')?.match(/^Bearer (\S+)$/i)?.[1]
  if (!jwt) return fail(401)
  const {meeting,action,device}=await request.json().catch(()=>null) ?? {}
  if (typeof meeting!=='string' || !uuid.test(meeting) || !['start','token'].includes(action) ||
    (action==='token' && (typeof device!=='string' || !uuid.test(device)))) return fail(400)
  try {
    const client=createClient(settings.url,settings.key,{auth,global:{headers:{Authorization:'Bearer '+jwt}}})
    const {data,error}=await client.auth.getUser(jwt)
    if (error || !data.user) return fail(401)
    const mediaSession=()=>client.rpc('st_v8_workspace_member_media_allowed',{p_meeting:meeting})
    const session=await mediaSession()
    if (session.error) return fail(503)
    if (session.data!==true) return fail(403)
    if (action==='start') {
      const managed='sectalk-v3-'+meeting.toLowerCase()
      const rooms=new RoomServiceClient(liveKitControlUrl(settings.livekit),settings.apiKey,settings.secret,{requestTimeout:5})
      let active:Awaited<ReturnType<typeof rooms.listParticipants>>=[]
      try { active=await rooms.listParticipants(managed) }
      catch(error) { if (!(error instanceof Error && 'status' in error && error.status===404)) throw error }
      if (active?.length) return fail(409)
      const current=await mediaSession()
      if (current.error) return fail(503)
      if (current.data!==true) return fail(403)
      const db=createClient(settings.url,settings.service,{auth})
      const result=await db.rpc('st_v6_create_protected_meeting',{p_meeting:meeting,p_actor:data.user.id})
      if (result.error) return fail(503)
      return result.data===true ? Response.json({ok:true},{headers}) : fail(403)
    }
    const result=await client.rpc('st_v6_protected_meeting_exchange',{p_meeting:meeting,p_device:device,p_action:'token'})
    if (result.error || !result.data?.ready) return fail(403)
    const [profile,binding]=await Promise.all([
      client.from('st_profiles').select('name').eq('id',data.user.id).maybeSingle(),
      client.rpc('st_v8_livekit_bind_member',{p_meeting:meeting,p_kind:'protected'}),
    ])
    if (binding.error) return fail(503)
    if (typeof binding.data!=='string') return fail(403)
    const token=new AccessToken(settings.apiKey,settings.secret,{identity:meetingMediaIdentity(data.user.id,binding.data),
      name:profile.data?.name || 'SecTalk member',ttl:30,attributes:{[meetingBindingAttribute]:binding.data}})
    token.addGrant({roomJoin:true,room:'sectalk-protected-'+meeting.toLowerCase(),canPublish:true,canSubscribe:true,canPublishData:false,
      canUpdateOwnMetadata:false,
      canPublishSources:[TrackSource.CAMERA,TrackSource.MICROPHONE]})
    return Response.json({url:settings.livekit,token:await token.toJwt()},{headers})
  } catch { return fail(503) }
}
