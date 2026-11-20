import {createClient} from '@supabase/supabase-js'
import {readBoundedText} from '../../../lib/request-body'
import {base64urlToBinary,deviceBundleContract} from '../../../lib/device-bundle'
import {groupHistoryTranscript,type GroupHistoryEnvelope,type GroupHistoryProof} from '../../../lib/group-history-proof'

export const runtime='nodejs'
const headers={'Cache-Control':'private, no-store',Vary:'Authorization'}
const response=(status:number)=>new Response(null,{status,headers})
const auth={persistSession:false,autoRefreshToken:false}

type VerifiedProof=GroupHistoryProof&{actor:string;session:string;signing:string;epochs:number[]}

function validEnvelope(row:unknown):row is GroupHistoryEnvelope{
  if(!row||typeof row!=='object')return false
  const value=row as Partial<GroupHistoryEnvelope>
  return Number.isInteger(value.epoch)&&Number(value.epoch)>0&&typeof value.ephemeral==='string'&&
    /^[A-Za-z0-9_-]{87}$/.test(value.ephemeral)&&typeof value.sealed==='string'&&/^[A-Za-z0-9_-]{80}$/.test(value.sealed)
}

export async function POST(request:Request){
  const {NEXT_PUBLIC_SUPABASE_URL:url,NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:key,SECTALK_DEVICE_BUNDLE_SERVICE_KEY:service}=process.env
  if(!url||!key||!service)return response(503)
  const token=request.headers.get('Authorization')?.match(/^Bearer (\S+)$/i)?.[1]
  if(!token)return response(401)
  const client=createClient(url,key,{auth,global:{headers:{Authorization:'Bearer '+token}}})
  const user=await client.auth.getUser(token)
  if(user.error||!user.data.user)return response(401)
  try{
    const raw=await readBoundedText(request,8192)
    const value=raw?JSON.parse(raw):null
    if(!value||typeof value.nonce!=='string'||!deviceBundleContract.uuid.test(value.nonce)||
      typeof value.signature!=='string'||!deviceBundleContract.signature.test(value.signature)||
      !Array.isArray(value.envelopes)||value.envelopes.length<1||value.envelopes.length>16||!value.envelopes.every(validEnvelope)){
      return response(400)
    }
    const scope=await client.rpc('st_v7_group_history_proof',{p_nonce:value.nonce})
    const proof=scope.data as VerifiedProof|null
    if(scope.error||!proof||proof.actor!==user.data.user.id)return response(403)
    const envelopes=(value.envelopes as GroupHistoryEnvelope[]).map(({epoch,ephemeral,sealed})=>({epoch,ephemeral,sealed}))
    if(proof.epochs.length!==envelopes.length||proof.epochs.some((epoch,index)=>epoch!==envelopes[index].epoch))return response(400)
    const signing=await crypto.subtle.importKey('raw',base64urlToBinary(proof.signing),{name:'ECDSA',namedCurve:'P-256'},false,['verify'])
    if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},signing,base64urlToBinary(value.signature),
      groupHistoryTranscript(proof,envelopes)))return response(403)
    const finished=await createClient(url,service,{auth}).rpc('st_v7_finish_group_history',{
      p_nonce:value.nonce,p_actor:proof.actor,p_session:proof.session,p_envelopes:envelopes,
    })
    if(finished.error)return response(503)
    if(!Number.isInteger(finished.data)||finished.data<0)return response(409)
    return Response.json({restored:finished.data},{headers})
  }catch{return response(400)}
}
