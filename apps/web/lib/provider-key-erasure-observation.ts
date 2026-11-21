import { createHash } from 'node:crypto'
import { cloudTrailKeyMaterialEvidence } from '../../../services/tenant-dek-aws/cloudtrail-key-material.mjs'

export const providerErasureArn=/^arn:aws:kms:([a-z]{2}-[a-z]+-[1-9][0-9]?):([0-9]{12}):key\/([a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}|mrk-[a-f0-9]{32})$/
const uuid=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/
export type ProviderErasureReport = { state:'active'|'disabled'|'pending_deletion'|'pending_replica_deletion'|'unavailable' } |
  { state:'deleted_event'; event:string; eventTime:string; sha256:string }

export function providerErasureObservation(report:unknown,keyId:string,stagedAt:string,now=Date.now()):ProviderErasureReport {
  const match=providerErasureArn.exec(keyId)
  const since=Date.parse(stagedAt)
  if (!match || !Number.isFinite(since) || !report || typeof report!=='object') return {state:'unavailable'}
  const value=report as {keyId?:unknown;state?:unknown;event?:Record<string,unknown>}
  if (value.keyId!==keyId) return {state:'unavailable'}
  if (value.state==='active' || value.state==='disabled' || value.state==='pending_deletion' || value.state==='pending_replica_deletion') {
    return {state:value.state}
  }
  if (match[3].startsWith('mrk-')) return {state:'unavailable'}
  const event=value.event
  if (value.state!=='not_found' || !event || typeof event.eventID!=='string' || !uuid.test(event.eventID) ||
    event.eventName!=='DeleteKey' || event.eventSource!=='kms.amazonaws.com' || event.eventType!=='AwsServiceEvent' ||
    event.awsRegion!==match[1] || event.recipientAccountId!==match[2] || event.readOnly!==false || event.errorCode!==undefined ||
    typeof event.eventTime!=='string' || !Array.isArray(event.resources) || !event.resources.some(resource=>
      resource?.ARN===keyId && resource?.type==='AWS::KMS::Key' && resource?.accountId===match[2])) return {state:'unavailable'}
  const result=event.responseElements as {keyId?:unknown}|null|undefined
  if (result!==null && result!==undefined && (typeof result!=='object'||Array.isArray(result)||
    ('keyId' in result&&result.keyId!==keyId))) return {state:'unavailable'}
  const eventTime=Date.parse(event.eventTime)
  if (!Number.isFinite(eventTime) || eventTime<since || eventTime>now+30_000) return {state:'unavailable'}
  const keyMaterial=cloudTrailKeyMaterialEvidence(event.additionalEventData)
  if (keyMaterial===null) return {state:'unavailable'}
  const timestamp=new Date(eventTime).toISOString()
  const canonical=JSON.stringify([keyMaterial.length?'sectalk/aws-kms-delete-event/v2':'sectalk/aws-kms-delete-event/v1',
    keyId,event.eventID,timestamp,event.eventSource,event.eventName,event.eventType,event.awsRegion,event.recipientAccountId,
    ...keyMaterial])
  return {state:'deleted_event',event:event.eventID,eventTime:timestamp,sha256:createHash('sha256').update(canonical).digest('hex')}
}
