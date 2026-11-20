import { createClient } from '@supabase/supabase-js'
import { base64urlToBinary, binaryToBase64url, deviceBindingTranscript,
  deviceBundleContract, deviceBundleTranscript, deviceRecoveryTranscript, type DeviceChallenge } from '../../../../../lib/device-bundle'
import { readBoundedText } from '../../../../../lib/request-body'

export const runtime = 'nodejs'
const headers = {'Cache-Control':'no-store'}
const auth = {persistSession:false,autoRefreshToken:false}

export async function POST(request: Request) {
  const supabase=process.env.NEXT_PUBLIC_SUPABASE_URL
  const key=process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY
  const serviceKey=process.env.SECTALK_DEVICE_BUNDLE_SERVICE_KEY
  if (!supabase || !key || !serviceKey) return new Response(null,{status:503,headers})

  const bearer=request.headers.get('authorization')
  if (!bearer?.startsWith('Bearer ')) return new Response(null,{status:401,headers})
  const scoped=createClient(supabase,key,{auth,global:{headers:{Authorization:bearer}}})
  const identity=await scoped.auth.getUser(bearer.slice(7))
  if (identity.error || !identity.data.user) return new Response(null,{status:401,headers})

  let proof: {challenge?: unknown; signature?: unknown; binding?: unknown; recoveryRequest?: unknown; recoverySignature?: unknown}
  try {
    const raw=await readBoundedText(request,1024)
    if (raw===undefined) return new Response(null,{status:413,headers})
    if (raw===null) return new Response(null,{status:400,headers})
    proof=JSON.parse(raw)
    if (!proof || typeof proof!=='object') throw new Error()
  } catch {return new Response(null,{status:400,headers})}
  if (typeof proof.challenge!=='string' || !deviceBundleContract.uuid.test(proof.challenge)
    || typeof proof.signature!=='string' || !deviceBundleContract.signature.test(proof.signature)
    || typeof proof.binding!=='string' || !deviceBundleContract.signature.test(proof.binding))
    return new Response(null,{status:400,headers})
  const {recoveryRequest,recoverySignature}=proof
  const recovery=recoveryRequest!==undefined || recoverySignature!==undefined
  if (recovery && (typeof recoveryRequest!=='string' || !deviceBundleContract.uuid.test(recoveryRequest)
    || typeof recoverySignature!=='string' || !deviceBundleContract.signature.test(recoverySignature)))
    return new Response(null,{status:400,headers})

  const result=await scoped.rpc('st_v7_pending_device_bundle',{p_challenge:proof.challenge})
  const challenge=result.data as DeviceChallenge|null
  if (result.error || !challenge || challenge.owner!==identity.data.user.id)
    return new Response(null,{status:403,headers})

  try {
    const signing=base64urlToBinary(challenge.signing)
    const agreement=base64urlToBinary(challenge.agreement)
    if (signing.byteLength!==65 || agreement.byteLength!==65
      || binaryToBase64url(signing.buffer)!==challenge.signing || binaryToBase64url(agreement.buffer)!==challenge.agreement)
      return new Response(null,{status:400,headers})
    const [verifier]=await Promise.all([
      crypto.subtle.importKey('raw',signing,{name:'ECDSA',namedCurve:'P-256'},false,['verify']),
      crypto.subtle.importKey('raw',agreement,{name:'ECDH',namedCurve:'P-256'},false,[]),
    ])
    const params={name:'ECDSA',hash:'SHA-256'}
    const [validBundle,validBinding]=await Promise.all([
      crypto.subtle.verify(params,verifier,base64urlToBinary(proof.signature),deviceBundleTranscript(challenge)),
      crypto.subtle.verify(params,verifier,base64urlToBinary(proof.binding),deviceBindingTranscript(challenge)),
    ])
    if (!validBundle || !validBinding) return new Response(null,{status:403,headers})
    if (typeof recoveryRequest==='string' && typeof recoverySignature==='string' &&
      !await crypto.subtle.verify(params,verifier,base64urlToBinary(recoverySignature),deviceRecoveryTranscript(challenge,recoveryRequest)))
      return new Response(null,{status:403,headers})
  } catch {return new Response(null,{status:400,headers})}

  const service=createClient(supabase,serviceKey,{auth})
  const args={
    p_owner:challenge.owner,p_session:challenge.session,p_challenge:challenge.challenge,p_signature:proof.signature,
  }
  const finished=typeof recoveryRequest==='string'
    ? await service.rpc('st_v7_finish_device_recovery_approval',{...args,p_recovery:recoveryRequest})
    : await service.rpc('st_v7_finish_device_bundle',args)
  return new Response(null,{status:finished.error?503:finished.data?204:409,headers})
}
