import { isIP } from 'node:net'
import { createClient } from '@supabase/supabase-js'
import { sessionRiskGateway } from '../../../../lib/session-risk-server'
import { readBoundedText } from '../../../../lib/request-body'
import { supabaseApiFetch } from '../../../../lib/supabase-api-fetch.mjs'

export const runtime='nodejs'
const headers={'Cache-Control':'no-store'}
export async function POST(request:Request) {
  const started=performance.now()
  async function unavailable() {
    const remaining=500-(performance.now()-started)
    if (remaining>0) await new Promise(resolve=>setTimeout(resolve,remaining))
    return Response.json({error:'invalid_credentials'},{status:401,headers})
  }
  const url=process.env.SECTALK_AUTH_PASSWORD_UPSTREAM||process.env.NEXT_PUBLIC_SUPABASE_URL
  const key=process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY
  const temporary=()=>Response.json({error:'sign_in_unavailable'},{status:503,headers})
  if (!url||!key) return temporary()
  try {
    const raw=await readBoundedText(request,2048)
    if (!raw) return unavailable()
    const values=JSON.parse(raw)
    if (!values||typeof values.email!=='string'||typeof values.password!=='string') return unavailable()
    const email=values.email.trim()
    if (email.length<1||email.length>254||values.password.length<1||values.password.length>256)
      return unavailable()

    const forwarded:Record<string,string>={}
    const browser=request.headers.get('user-agent')
    if (browser) forwarded['User-Agent']=browser.slice(0,512)
    // Vercel supplies this header at its ingress. A self-hosted proxy must
    // configure its upstream Auth server to trust only its ingress network.
    const ip=process.env.VERCEL==='1'?request.headers.get('x-vercel-forwarded-for'):null
    if (ip&&isIP(ip)) forwarded['X-Forwarded-For']=ip
    const auth=createClient(url,key,{
      auth:{persistSession:false,autoRefreshToken:false},global:{headers:forwarded,fetch:
        supabaseApiFetch(key,(input: RequestInfo|URL, options?: RequestInit)=>
          fetch(input,{...options,signal:AbortSignal.any([request.signal,AbortSignal.timeout(7000)])}))},
    })
    const risk=sessionRiskGateway(url,email)
    const retryAfter=await risk?.admit(ip&&isIP(ip)?ip:null)
    if (retryAfter) {
      return Response.json({error:'try_again_later'},{status:429,headers:{...headers,'Retry-After':String(retryAfter)}})
    }
    const signed=await auth.auth.signInWithPassword({email,password:values.password})
    if (signed.error||!signed.data.session||!signed.data.user) {
      if (signed.error?.status===429) {
        return Response.json({error:'try_again_later'},{status:429,headers})
      }
      if (signed.error && (!signed.error.status || signed.error.status>=500)) return temporary()
      if (signed.error?.code==='invalid_credentials') await risk?.failure()
      return unavailable()
    }
    const {access_token,refresh_token}=signed.data.session
    await risk?.assess(signed.data.user.id,access_token)
    return Response.json({access_token,refresh_token},{headers})
  } catch (error) {return error instanceof SyntaxError ? unavailable() : temporary()}
}
