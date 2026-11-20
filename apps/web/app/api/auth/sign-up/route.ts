import {isIP} from 'node:net'
import {createClient} from '@supabase/supabase-js'
import {confirmationRedirect} from '../../../../lib/auth-confirmation-origin.mjs'
import {readBoundedText} from '../../../../lib/request-body'

export const runtime='nodejs'
const headers={'Cache-Control':'no-store'}
const auth={persistSession:false,autoRefreshToken:false}
const challengePattern=/^[a-f0-9]{64}$/
const invitePattern=/^[a-f0-9]{48}$/
const failure=(status=400)=>Response.json({error:'signup_unavailable'},{status,headers})

export async function POST(request:Request) {
  const project=process.env.NEXT_PUBLIC_SUPABASE_URL
  const upstream=process.env.SECTALK_AUTH_SIGNUP_UPSTREAM||project
  const key=process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY
  const redirect=confirmationRedirect(process.env.SECTALK_APP_URL,request.url,
    process.env.VERCEL==='1'&&process.env.VERCEL_ENV!=='development')
  if (!project||!upstream||!key||!redirect) return failure(503)
  try {
    const raw=await readBoundedText(request,4096)
    if (!raw) return failure()
    const input=JSON.parse(raw)
    if (!input||typeof input.email!=='string'||input.email.length>254) return failure()
    const email=input.email.trim()
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return failure()
    const resend=input.action==='resend'
    if (!resend&&(input.action!=='signup'||typeof input.password!=='string'||input.password.length<12
      ||new TextEncoder().encode(input.password).length>72)) return failure()
    if (input.invite!=null&&(typeof input.invite!=='string'||!invitePattern.test(input.invite))) return failure()
    if (input.challenge!=null&&(typeof input.challenge!=='string'||!challengePattern.test(input.challenge)
      ||!Number.isInteger(input.solution)||input.solution<0||input.solution>=250000)) return failure()
    if (input.challenge==null&&input.solution!=null) return failure()

    const ip=process.env.VERCEL==='1'?request.headers.get('x-vercel-forwarded-for'):null
    const nativeHeaders:Record<string,string>={}
    if (ip&&isIP(ip)) nativeHeaders['X-Forwarded-For']=ip
    const serviceKey=process.env.SECTALK_SIGNUP_ADMISSION_SERVICE_KEY||process.env.SECTALK_AUTH_RISK_SERVICE_KEY
    let permit:string|undefined
    if (serviceKey) {
      const admission=createClient(project,serviceKey,{auth})
      const result=await admission.rpc('st_v7_signup_admission',{
        p_email:email,p_ip:ip&&isIP(ip)?ip:null,p_invite:input.invite??null,
        p_challenge:input.challenge??null,p_solution:input.solution??null,p_resend:resend,
      }).abortSignal(AbortSignal.timeout(2000))
      if (result.error) return failure(503)
      if (result.data?.status==='limited') return Response.json({error:'try_again_later'},{
        status:429,headers:{...headers,'Retry-After':String(result.data.retry)},
      })
      if (result.data?.status==='challenge'&&challengePattern.test(result.data.challenge)) {
        return Response.json({challenge:result.data.challenge},{status:428,headers})
      }
      if (result.data?.status!=='allow') return failure()
      if (!resend) {
        permit=result.data.permit
        if (!permit||!challengePattern.test(permit)) return failure(503)
      }
    }
    const client=createClient(upstream,key,{auth,global:{headers:nativeHeaders}})
    const result=resend
      ? await client.auth.resend({type:'signup',email,options:{emailRedirectTo:redirect}})
      : await client.auth.signUp({email,password:input.password,options:{emailRedirectTo:redirect,
        ...(permit?{data:{sectalk_signup_gate:permit}}:{})}})
    if (result.error) return failure(result.error.status===429?429:400)
    return Response.json({status:'sent'},{headers})
  } catch {return failure()}
}
