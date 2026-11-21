import { keyDeletionEvidence, kmsKeyArn } from '../../../services/tenant-dek-aws/cloudtrail-key-deletion.mjs'

export const providerErasureArn=kmsKeyArn
export type ProviderErasureReport = { state:'active'|'disabled'|'pending_deletion'|'pending_replica_deletion'|'unavailable' } |
  { state:'deleted_event'; event:string; eventTime:string; sha256:string }

export function providerErasureObservation(report:unknown,keyId:string,stagedAt:string,now=Date.now()):ProviderErasureReport {
  const since=Date.parse(stagedAt)
  if (!providerErasureArn.test(keyId) || !Number.isFinite(since) || !report || typeof report!=='object') return {state:'unavailable'}
  const value=report as {keyId?:unknown;state?:unknown;event?:Record<string,unknown>}
  if (value.keyId!==keyId) return {state:'unavailable'}
  if (value.state==='active' || value.state==='disabled' || value.state==='pending_deletion' || value.state==='pending_replica_deletion') {
    return {state:value.state}
  }
  const proof=value.state==='not_found' ? keyDeletionEvidence(value.event,keyId,stagedAt,now) : null
  return proof ? {state:'deleted_event',...proof} : {state:'unavailable'}
}
