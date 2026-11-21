import {createClient} from '@supabase/supabase-js'
import {base64urlToBinary,deviceBundleContract} from '../../../../lib/device-bundle'
import {matrixObject,olmDirectoryTranscript,olmPrekeysTranscript,verifyOlmPublish} from '../../../../lib/olm-directory-proof'
import {readBoundedText} from '../../../../lib/request-body'

export const runtime='nodejs'
const headers={'Cache-Control':'no-store'}
const auth={persistSession:false,autoRefreshToken:false}
type Context={owner:string;device:string;signing:string;session:string}

export async function POST(request:Request) {
  const project=process.env.NEXT_PUBLIC_SUPABASE_URL
  const publishable=process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY
  const serviceKey=process.env.SECTALK_DEVICE_BUNDLE_SERVICE_KEY
  if (!project||!publishable||!serviceKey) return new Response(null,{status:503,headers})
  const token=request.headers.get('Authorization')?.match(/^Bearer (\S+)$/i)?.[1]
  if (!token) return new Response(null,{status:401,headers})

  const scoped=createClient(project,publishable,{auth,global:{headers:{Authorization:`Bearer ${token}`}}})
  const [identity,approval]=await Promise.all([scoped.auth.getUser(token),
    scoped.rpc('st_v8_olm_device_proof').abortSignal(AbortSignal.timeout(3000))])
  if (identity.error||!identity.data.user) return new Response(null,{status:401,headers})
  const current=approval.data as Context|null
  if (approval.error||!current||current.owner!==identity.data.user.id) return new Response(null,{status:403,headers})

  try {
    const raw=await readBoundedText(request,68000)
    if (raw===undefined) return new Response(null,{status:413,headers})
    if (!raw) return new Response(null,{status:400,headers})
    const payload:unknown=JSON.parse(raw)
    if (!matrixObject(payload) || !matrixObject(payload.bundle)||!matrixObject(payload.prekeys)||
      typeof payload.bundleProof!=='string'||!deviceBundleContract.signature.test(payload.bundleProof)||
      typeof payload.uploadProof!=='string'||!deviceBundleContract.signature.test(payload.uploadProof)) {
      return new Response(null,{status:400,headers})
    }
    const {bundle,prekeys,bundleProof,uploadProof}=payload
    const {owner,device,session}=current
    const verifier=await crypto.subtle.importKey('raw',base64urlToBinary(current.signing),{name:'ECDSA',namedCurve:'P-256'},false,['verify'])
    const signature={name:'ECDSA',hash:'SHA-256'}
    const [validBundle,validUpload]=await Promise.all([
      crypto.subtle.verify(signature,verifier,base64urlToBinary(bundleProof),olmDirectoryTranscript(owner,device,bundle)),
      crypto.subtle.verify(signature,verifier,base64urlToBinary(uploadProof),olmPrekeysTranscript(owner,device,session,bundle,prekeys)),
    ])
    if (!validBundle||!validUpload||!await verifyOlmPublish(owner,device,bundle,prekeys)) {
      return new Response(null,{status:403,headers})
    }

    const admin=createClient(project,serviceKey,{auth})
    const saved=await admin.rpc('st_v8_olm_register_device',{
      p_owner:owner,p_device:device,p_session:session,p_bundle:bundle,p_proof:bundleProof,p_prekeys:prekeys,
    }).abortSignal(AbortSignal.timeout(3000))
    if (saved.error) return new Response(null,{status:saved.error.code==='42501'?403:saved.error.code==='23505'?409:
      saved.error.code==='22023'?400:503,headers})
    return Response.json({one_time_key_counts:saved.data},{headers})
  } catch {
    return new Response(null,{status:400,headers})
  }
}
