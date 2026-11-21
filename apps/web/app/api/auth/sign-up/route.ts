import {isIP} from 'node:net'
import {createClient} from '@supabase/supabase-js'
import {readBoundedText} from '../../../../lib/request-body'
import {isBreachedPassword} from '../../../../lib/breached-password'
import {signupConfiguration} from '../../../../lib/signup-configuration.mjs'
import {signupPasswordHash} from '../../../../lib/signup-password.mjs'
import {signupFetch} from '../../../../lib/signup-transport.mjs'

export const runtime='nodejs'
const headers={'Cache-Control':'no-store'}
const auth={persistSession:false,autoRefreshToken:false}
const challengePattern=/^[a-f0-9]{64}$/
const invitePattern=/^[a-f0-9]{48}$/
const duplicateAccountCodes=new Set(['email_exists','user_already_exists'])
const failure=(status=400)=>Response.json({error:'signup_unavailable'},{status,headers})
const sent=()=>Response.json({status:'sent'},{headers})

export async function POST(request:Request) {
  const configuration=signupConfiguration(request.url)
  if (!configuration) return failure(503)
  const {project,upstream,key,serviceKey,redirect}=configuration
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
    const admission=createClient(project,serviceKey,{auth,global:{fetch:signupFetch(serviceKey)}})
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
      const permit=result.data.permit
      if (typeof permit!=='string'||!challengePattern.test(permit)) return failure(503)
      try {
        if (await isBreachedPassword(input.password)) {
          return Response.json({error:'breached_password'},{status:422,headers})
        }
      } catch {
        return Response.json({error:'password_check_unavailable'}, {status:503,headers:{...headers,'Retry-After':'30'}})
      }
      const consumed=await admission.rpc('st_v8_consume_password_signup_permit',{
        p_email:email,p_token:permit,
      }).abortSignal(AbortSignal.timeout(2000))
      if (consumed.error || consumed.data!==true) return failure(503)

      const created=await admission.auth.admin.createUser({email,email_confirm:false,
        password_hash:await signupPasswordHash(input.password)})
      if (created.error) {
        if (created.error.code&&duplicateAccountCodes.has(created.error.code)) return sent()
        return failure(created.error.status===429?429:503)
      }
    }
    const client=createClient(upstream,key,{auth,global:{headers:nativeHeaders,fetch:signupFetch(key)}})
    const delivery=await client.auth.resend({type:'signup',email,options:{emailRedirectTo:redirect}})
    if (delivery.error) {
      const status=delivery.error.status===429?429:503
      return resend ? failure(status) : Response.json({error:'confirmation_delivery_failed'},{status,headers})
    }
    return sent()
  } catch {return failure()}
}
