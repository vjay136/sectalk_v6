import { liveKitControlUrl } from '../../../../lib/livekit-control-url'
import { createHash, randomBytes } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { AccessToken, RoomServiceClient, TrackSource } from 'livekit-server-sdk'

export const runtime='nodejs'
const headers={'Cache-Control':'private, no-store',Vary:'Authorization'}
const uuid=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i
const opaque=/^[\w-]{43}$/
const hostActions=new Set(['view','policy','create','revoke','approve','deny'])
const siteverify='https://challenges.cloudflare.com/turnstile/v0/siteverify'
const authOptions={persistSession:false,autoRefreshToken:false}
const digest=(value:string)=>createHash('sha256').update(value).digest('hex')
const generate=()=>randomBytes(32).toString('base64url')
const unavailable=(status:number)=>Response.json({error:'Guest access unavailable.'},{status,headers})

function config() {
  const { NEXT_PUBLIC_SUPABASE_URL:url, NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:key, MEETING_GUEST_SERVICE_KEY:service,
    MEETING_GUEST_TURNSTILE_SITE_KEY:siteKey, MEETING_GUEST_TURNSTILE_SECRET:captchaSecret, MEETING_GUEST_CAPTCHA_HOSTNAME:hostname,
    MEETING_GUEST_CAPTCHA_TEST_URL:fixture, LIVEKIT_URL:livekit,LIVEKIT_API_KEY:apiKey,LIVEKIT_API_SECRET:apiSecret }=process.env
  if (!url || !key || !service || !siteKey || !captchaSecret || !hostname || !livekit || !apiKey || !apiSecret) return null
  let endpoint=siteverify
  if (fixture) {
    const parsed=URL.parse(fixture)
    if (URL.parse(url)?.hostname!=='127.0.0.1' || URL.parse(livekit)?.hostname!=='127.0.0.1' || hostname!=='127.0.0.1' ||
      !parsed || parsed.protocol!=='http:' || parsed.hostname!=='127.0.0.1' || !parsed.port ||
      parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname!=='/siteverify') return null
    endpoint=parsed.href
  }
  return {url,key,service,siteKey,captchaSecret,hostname,endpoint,livekit,apiKey,apiSecret}
}

async function readBody(request:Request) {
  if (!request.headers.get('Content-Type')?.startsWith('application/json')) return null
  const reader=request.body?.getReader()
  if (!reader) return null
  const text=new TextDecoder('utf-8',{fatal:true})
  let body=''
  let size=0
  try {
    while (true) {
      const {done,value}=await reader.read()
      if (done) break
      size+=value.length
      if (size>4096) return null
      body+=text.decode(value,{stream:true})
    }
    return JSON.parse(body+text.decode())
  } catch { return null }
  finally { await reader.cancel().catch(()=>{}); reader.releaseLock() }
}

async function verifyCaptcha(settings:NonNullable<ReturnType<typeof config>>,response:string) {
  const verification=await fetch(settings.endpoint,{method:'POST',redirect:'error',signal:AbortSignal.timeout(4500),
    body:new URLSearchParams({response,secret:settings.captchaSecret})})
  if (!verification.ok) return false
  const result=await verification.json()
  const age=Date.now()-Date.parse(result?.challenge_ts)
  return result?.success===true && result.action==='meeting_guest' && result.hostname===settings.hostname && age>=-30000 && age<=300000
}

export function GET() {
  const settings=config()
  return Response.json({configured:Boolean(settings),siteKey:settings?.siteKey},{headers})
}

export async function POST(request:Request) {
  const settings=config()
  if (!settings) return unavailable(503)
  const input=await readBody(request)
  const action=input?.action
  const authorization=request.headers.get('Authorization') ?? ''
  const db=createClient(settings.url,settings.service,{auth:authOptions})
  async function command(p_action:string,values:Record<string,unknown>) {
    const result=await db.rpc('st_v6_meeting_guest_command',{p_action,...values})
    if (result.error) throw new Error('Guest state failed')
    return result.data
  }
  try {
    if (action==='request') {
      const {ticket,captcha}=input
      const name=typeof input.name==='string' ? input.name.normalize('NFKC').replace(/[\p{Cc}\p{Cf}]/gu,'').trim() : ''
      if (typeof ticket!=='string' || !opaque.test(ticket) || typeof captcha!=='string' || !captcha || captcha.length>2048 ||
        !name || [...name].length>60) return unavailable(400)
      const invite=digest(ticket)
      if (!await command('probe',{p_digest:invite}) || !await verifyCaptcha(settings,captcha)) return unavailable(403)
      const access=generate()
      const result=await command('request',{p_digest:invite,p_name:name,p_visit_digest:digest(access),p_challenge_digest:digest(captcha)})
      return result ? Response.json({...result,access},{status:201,headers}) : unavailable(403)
    }
    if (action==='status' || action==='token') {
      const guest=authorization.match(/^Guest ([\w-]{43})$/)?.[1]
      if (!guest) return unavailable(401)
      const result=await command(action,{p_visit_digest:digest(guest)})
      if (!result) return unavailable(403)
      if (action==='status') return Response.json(result,{headers})
      const ttl=Math.min(30,Math.floor((Date.parse(result.expiresAt)-Date.now())/1000))
      if (!Number.isInteger(ttl) || ttl<2) return unavailable(403)
      const token=new AccessToken(settings.apiKey,settings.apiSecret,{identity:result.visitor, name:'Guest · '+result.name,
        metadata:JSON.stringify({guest:true}),ttl})
      token.addGrant({roomJoin:true,room:'sectalk-v3-'+result.meeting,canSubscribe:true,canPublish:true,
        canPublishSources:[TrackSource.CAMERA,TrackSource.MICROPHONE],canPublishData:false})
      return Response.json({url:settings.livekit,token:await token.toJwt()},{headers})
    }
    if (!hostActions.has(action)) return unavailable(400)
    const jwt=authorization.match(/^Bearer (\S+)$/i)?.[1]
    if (!jwt) return unavailable(401)
    if (typeof input.meeting!=='string' || !uuid.test(input.meeting) ||
      (action==='policy' && typeof input.enabled!=='boolean') ||
      (action==='revoke' && (typeof input.link!=='string' || !uuid.test(input.link))) ||
      (['approve','deny'].includes(action) && (typeof input.visitor!=='string' || !uuid.test(input.visitor)))) return unavailable(400)
    const {data,error}=await createClient(settings.url,settings.key,{auth:authOptions}).auth.getUser(jwt)
    if (error || !data.user) return unavailable(401)
    const ticket=action==='create' ? generate() : undefined
    const meeting=input.meeting.toLowerCase()
    const result=await command(action,{p_meeting:meeting,p_actor:data.user.id,p_enabled:input.enabled ?? null,
      p_link:input.link ?? null,p_visitor:input.visitor ?? null,p_digest:ticket ? digest(ticket) : null})
    if (!result) return unavailable(403)
    const {detach,...state}=result
    let cleanupPending=false
    if (Array.isArray(detach) && detach.length) {
      const room='sectalk-v3-'+meeting
      const rooms=new RoomServiceClient(liveKitControlUrl(settings.livekit),settings.apiKey,settings.apiSecret,{requestTimeout:4})
      try {
        const present=(await rooms.listParticipants(room)).filter(person=>detach.includes(person.identity))
        const removed=await Promise.allSettled(present.map(person=>rooms.removeParticipant(room,person.identity)))
        cleanupPending=removed.some(item=>item.status==='rejected')
      } catch(error) {
        cleanupPending=!(error instanceof Error && 'status' in error && error.status===404)
      }
    }
    return Response.json({...state,ticket,cleanupPending},{headers})
  } catch { return unavailable(503) }
}
