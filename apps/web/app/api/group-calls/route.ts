import { createClient } from '@supabase/supabase-js'
import { AccessToken, TrackSource } from 'livekit-server-sdk'
import { callIceServers } from '../../../lib/turn-ice-servers'

const headers={'Cache-Control':'private, no-store',Vary:'Authorization'}
const valid=/^[a-f\d]{8}(?:-[a-f\d]{4}){3}-[a-f\d]{12}$/i
const unavailable=(status:number)=>Response.json({error:'Group media unavailable.'},{status,headers})

export function GET() {
  return Response.json({sfu:Boolean(process.env.LIVEKIT_URL && process.env.LIVEKIT_API_KEY && process.env.LIVEKIT_API_SECRET)},{headers})
}

export async function POST(request:Request) {
  const {NEXT_PUBLIC_SUPABASE_URL:url,NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:key}=process.env
  if (!url || !key) return unavailable(503)
  const token=request.headers.get('Authorization')?.match(/^Bearer (\S+)$/i)?.[1]
  if (!token) return unavailable(401)
  const {call,device,action}=await request.json().catch(()=>null) ?? {}
  if (typeof call!=='string' || !valid.test(call) || typeof device!=='string' || !valid.test(device) ||
    (action!=='sfu' && action!=='ice')) return unavailable(400)
  try {
    const client=createClient(url,key,{auth:{persistSession:false,autoRefreshToken:false},global:{headers:{Authorization:'Bearer '+token}}})
    const {data,error}=await client.auth.getUser(token)
    if (error || !data.user) return unavailable(401)
    if (action==='ice') {
      const scope=await client.rpc('st_v6_group_call_ice',{p_call:call,p_device:device})
      if (scope.error?.code==='PT429') return Response.json({error:'Try again in a minute.'},{status:429,headers:{...headers,'Retry-After':'60'}})
      if (scope.error) return unavailable(503)
      if (!scope.data) return unavailable(403)
      const expiresAt=Date.parse(scope.data.expires_at)
      const config=await callIceServers(expiresAt,'group-call:'+call.toLowerCase()+':'+data.user.id)
      return Response.json(config,{headers})
    }
    const scope=await client.rpc('st_v6_group_call',{p_action:action,p_call:call,p_device:device})
    if (scope.error || !scope.data) return unavailable(403)
    const {LIVEKIT_URL:livekit,LIVEKIT_API_KEY:apiKey,LIVEKIT_API_SECRET:secret}=process.env
    if (!livekit || !apiKey || !secret || !Number.isInteger(scope.data.generation)) return unavailable(503)
    const lease=new AccessToken(apiKey,secret,{identity:data.user.id,ttl:30})
    lease.addGrant({roomJoin:true,room:'sectalk-group-'+call.toLowerCase()+'-'+scope.data.generation,
      canSubscribe:true,canPublish:true,canPublishData:false,canPublishSources:scope.data.video
        ? [TrackSource.MICROPHONE,TrackSource.CAMERA] : [TrackSource.MICROPHONE]})
    return Response.json({url:livekit,token:await lease.toJwt(),generation:scope.data.generation},{headers})
  } catch { return unavailable(503) }
}
