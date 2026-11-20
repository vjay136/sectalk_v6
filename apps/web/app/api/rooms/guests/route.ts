import { createHash, randomBytes } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

export const runtime='nodejs'
const uuid=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i
const opaque=/^[\w-]{43}$/
const headers={'Cache-Control':'private, no-store',Vary:'Authorization'}
const auth={persistSession:false,autoRefreshToken:false}
const hash=(value:string)=>createHash('sha256').update(value).digest('hex')
const mint=()=>randomBytes(32).toString('base64url')
const fail=(status:number)=>Response.json({error:'Guest room access unavailable.'},{status,headers})
const hostActions=new Set(['view','create','revoke'])

function config() {
  const {NEXT_PUBLIC_SUPABASE_URL:url,NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:key,ROOM_GUEST_SERVICE_KEY:service}=process.env
  return url && key && service ? {url,key,service} : null
}

export function GET() {
  return Response.json({configured:config()!==null},{headers})
}

export async function POST(request:Request) {
  const settings=config()
  if (!settings) return fail(503)
  const size=Number(request.headers.get('Content-Length'))
  if (!Number.isInteger(size) || size<1 || size>2048 || !request.headers.get('Content-Type')?.startsWith('application/json')) return fail(400)
  const input=await request.json().catch(()=>null)
  const action=input?.action
  const room=typeof input?.room==='string' && uuid.test(input.room) ? input.room.toLowerCase() : null
  if (input?.room!==undefined && !room) return fail(400)
  const header=request.headers.get('Authorization') ?? ''
  const db=createClient(settings.url,settings.service,{auth})
  async function command(values:Record<string,unknown>) {
    const result=await db.rpc('st_v6_room_guest_command',{p_action:action,p_room:room,...values})
    if (result.error) throw new Error('Room guest command failed')
    return result.data
  }
  try {
    if (action==='redeem') {
      if (typeof input.ticket!=='string' || !opaque.test(input.ticket)) return fail(400)
      const access=mint()
      const result=await command({p_digest:hash(input.ticket),p_capability:hash(access)})
      return result ? Response.json({...result,access},{headers}) : fail(403)
    }
    if (action==='read') {
      const access=header.match(/^Guest ([\w-]{43})$/)?.[1]
      if (!access) return fail(401)
      const result=await command({p_capability:hash(access)})
      return result ? Response.json(result,{headers}) : fail(403)
    }
    if (!hostActions.has(action) || !room) return fail(400)
    const jwt=header.match(/^Bearer (\S+)$/i)?.[1]
    if (!jwt) return fail(401)
    const {data,error}=await createClient(settings.url,settings.key,{auth}).auth.getUser(jwt)
    if (error || !data.user) return fail(401)
    const posts=input.posts
    if (action==='create' && (!Array.isArray(posts) || posts.length<1 || posts.length>10 ||
      posts.some(id=>typeof id!=='string' || !uuid.test(id)))) return fail(400)
    if (action==='revoke' && (typeof input.link!=='string' || !uuid.test(input.link))) return fail(400)
    const ticket=action==='create'?mint():undefined
    const result=await command({p_actor:data.user.id,p_digest:ticket?hash(ticket):null,
      p_posts:action==='create'?posts:null,p_link:action==='revoke'?input.link:null})
    return result ? Response.json({...result,ticket},{headers}) : fail(403)
  } catch { return fail(503) }
}
