import { createClient } from '@supabase/supabase-js'
import { base64urlToBinary, deviceBundleContract, deviceCommandTranscript } from '../../../../../lib/device-bundle'
import { readBoundedText } from '../../../../../lib/request-body'

export const runtime='nodejs'
const headers={'Cache-Control':'no-store'}
const uuid=(value:unknown):value is string=>typeof value==='string'&&deviceBundleContract.uuid.test(value)

export async function POST(request: Request) {
  const url=process.env.NEXT_PUBLIC_SUPABASE_URL
  const key=process.env.SECTALK_DEVICE_BUNDLE_SERVICE_KEY
  if (!url||!key) return new Response(null,{status:503,headers})
  let value:Record<string,unknown>
  try {
    const body=await readBoundedText(request,1024)
    if (body===undefined) return new Response(null,{status:413,headers})
    if (body===null) return new Response(null,{status:400,headers})
    value=JSON.parse(body)
    if (!value||Array.isArray(value)||typeof value!=='object') throw new Error()
  } catch {return new Response(null,{status:400,headers})}
  if (!uuid(value.device)) return new Response(null,{status:400,headers})
  const service=createClient(url,key,{auth:{persistSession:false,autoRefreshToken:false}})
  if (value.mode==='ack') {
    if (!uuid(value.command)||typeof value.receipt!=='string'||!/^[a-f0-9]{64}$/.test(value.receipt))
      return new Response(null,{status:400,headers})
    const ack=await service.rpc('st_v7_ack_device_command',{
      p_device:value.device,p_command:value.command,p_receipt:value.receipt,
    })
    return new Response(null,{status:ack.error?503:ack.data?204:403,headers})
  }
  if (value.mode!=='poll'||!uuid(value.owner)||!uuid(value.nonce)||typeof value.at!=='string'
    ||value.at.length!==24||!Number.isFinite(Date.parse(value.at))||Math.abs(Date.now()-Date.parse(value.at))>90_000
    ||typeof value.proof!=='string'||!deviceBundleContract.signature.test(value.proof))
    return new Response(null,{status:400,headers})
  const signing=await service.rpc('st_v7_device_command_key',{p_owner:value.owner,p_device:value.device})
  if (signing.error) return new Response(null,{status:503,headers})
  if (!signing.data) return new Response(null,{status:404,headers})
  try {
    const verifier=await crypto.subtle.importKey('raw',base64urlToBinary(signing.data),
      {name:'ECDSA',namedCurve:'P-256'},false,['verify'])
    if (!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},verifier,base64urlToBinary(value.proof),
      deviceCommandTranscript(value.owner,value.device,value.nonce,value.at)))
      return new Response(null,{status:403,headers})
  } catch {return new Response(null,{status:403,headers})}
  const claim=await service.rpc('st_v7_claim_device_command',{
    p_owner:value.owner,p_device:value.device,p_nonce:value.nonce,p_at:value.at,
  })
  if (claim.error) return new Response(null,{status:503,headers})
  if (!claim.data) return new Response(null,{status:409,headers})
  return Response.json(claim.data,{headers})
}
