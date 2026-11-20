import { createHmac } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { AccessToken, TrackSource } from 'livekit-server-sdk'

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
    const scope=await client.rpc('st_v6_group_call',{p_action:action,p_call:call,p_device:device})
    if (scope.error || !scope.data) return unavailable(403)
    if (action==='ice') {
      const turnSecret=process.env.TURN_SHARED_SECRET
      const urls=process.env.TURN_URLS?.split(',').map(item=>item.trim()).filter(Boolean)
      const iceServers:RTCIceServer[]=[{urls:process.env.STUN_URL || 'stun:stun.l.google.com:19302'}]
      if (turnSecret && urls?.length && urls.every(url=>/^turns?:[\w.:[\]-]+(?:\?transport=(?:udp|tcp))?$/i.test(url))) {
        const expires=Math.min(Math.floor(Date.now()/1000)+300,Math.floor(Date.parse(scope.data.expires_at)/1000))
        const principal=createHmac('sha256',turnSecret).update('group-call:'+call+':'+data.user.id).digest('hex').slice(0,32)
        const username=expires+':'+principal
        iceServers.push({urls,username,credential:createHmac('sha1',turnSecret).update(username).digest('base64')})
      } else if (turnSecret || urls?.length) return unavailable(503)
      return Response.json({iceServers,iceTransportPolicy:iceServers.length>1?'relay':'all'},{headers})
    }
    const {LIVEKIT_URL:livekit,LIVEKIT_API_KEY:apiKey,LIVEKIT_API_SECRET:secret}=process.env
    if (!livekit || !apiKey || !secret || !Number.isInteger(scope.data.generation)) return unavailable(503)
    const lease=new AccessToken(apiKey,secret,{identity:data.user.id,ttl:30})
    lease.addGrant({roomJoin:true,room:'sectalk-group-'+call.toLowerCase()+'-'+scope.data.generation,
      canSubscribe:true,canPublish:true,canPublishData:false,canPublishSources:scope.data.video
        ? [TrackSource.MICROPHONE,TrackSource.CAMERA] : [TrackSource.MICROPHONE]})
    return Response.json({url:livekit,token:await lease.toJwt(),generation:scope.data.generation},{headers})
  } catch { return unavailable(503) }
}
