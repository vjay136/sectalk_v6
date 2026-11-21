import { readBoundedText } from './request-body'
import { pinnedExternalTenantKey } from './tenant-artifact-keys'
import { providerErasureArn, providerErasureObservation, type ProviderErasureReport } from './provider-key-erasure-observation'

export { providerErasureObservation } from './provider-key-erasure-observation'

export async function observeProviderErasure(workspace:string,version:number,reference:string,marker:string,stagedAt:string):Promise<ProviderErasureReport> {
  const endpoint=URL.parse(process.env.SECTALK_PROVIDER_ERASURE_URL??'')
  const backend=URL.parse(process.env.NEXT_PUBLIC_SUPABASE_URL??'')
  const token=process.env.SECTALK_PROVIDER_ERASURE_TOKEN??''
  const local=!process.env.VERCEL && backend?.origin==='http://127.0.0.1:55321' && endpoint?.protocol==='http:' &&
    endpoint.hostname==='127.0.0.1' && !!endpoint.port
  if (!endpoint || (endpoint.protocol!=='https:' && !local) || endpoint.pathname!=='/v1/provider-key-erasure' ||
    endpoint.username || endpoint.password || endpoint.search || endpoint.hash || !/^[A-Za-z0-9_-]{32,128}$/.test(token)) {
    return {state:'unavailable'}
  }
  try {
    const keyId=pinnedExternalTenantKey(workspace,version,reference,marker)
    if (!providerErasureArn.test(keyId)) return {state:'unavailable'}
    const response=await fetch(endpoint,{method:'POST',redirect:'error',cache:'no-store',signal:AbortSignal.timeout(6500),
      headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},
      body:JSON.stringify({workspace,version,reference,keyId,stagedAt}),
    })
    if (!response.ok) {
      void response.body?.cancel().catch(()=>undefined)
      return {state:'unavailable'}
    }
    const raw=await readBoundedText(response,8192)
    return raw ? providerErasureObservation(JSON.parse(raw),keyId,stagedAt) : {state:'unavailable'}
  } catch { return {state:'unavailable'} }
}
