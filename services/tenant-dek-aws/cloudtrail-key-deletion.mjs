import {createHash} from 'node:crypto'
import {cloudTrailKeyMaterialEvidence} from './cloudtrail-key-material.mjs'

export const kmsKeyArn=/^arn:aws:kms:([a-z]{2}-[a-z]+-[1-9][0-9]?):([0-9]{12}):key\/([a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}|mrk-[a-f0-9]{32})$/
const eventId=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/
const responseArnIntroduced=Date.UTC(2022,11,1)

export function keyDeletionEvidence(event,keyId,stagedAt,now=Date.now()){
  const match=kmsKeyArn.exec(keyId)
  const since=Date.parse(stagedAt)
  if(!match||match[3].startsWith('mrk-')||!Number.isFinite(since)||!Number.isFinite(now)||!event||
    typeof event.eventID!=='string'||!eventId.test(event.eventID)||typeof event.eventTime!=='string'||
    event.eventName!=='DeleteKey'||event.eventSource!=='kms.amazonaws.com'||event.eventType!=='AwsServiceEvent'||
    event.awsRegion!==match[1]||event.recipientAccountId!==match[2]||event.readOnly!==false||
    event.managementEvent!==true||event.eventCategory!=='Management'||event.errorCode!==undefined||event.errorMessage!==undefined||
    event.userIdentity?.accountId!==match[2]||event.userIdentity?.invokedBy!=='AWS Internal'||
    !Array.isArray(event.resources)||!event.resources.some(resource=>
      resource?.ARN===keyId&&resource.type==='AWS::KMS::Key'&&resource.accountId===match[2])) return null

  const timestamp=Date.parse(event.eventTime)
  if(!Number.isFinite(timestamp)||timestamp<since||timestamp>now+30_000) return null
  const result=event.responseElements
  const modern=timestamp>=responseArnIntroduced
  if(result==null ? modern : typeof result!=='object'||Array.isArray(result)||result.keyId!==keyId) return null
  const material=cloudTrailKeyMaterialEvidence(event.additionalEventData)
  if(material===null) return null
  const time=new Date(timestamp).toISOString()
  const fields=[keyId,event.eventID,time,event.eventSource,event.eventName,event.eventType,event.awsRegion,event.recipientAccountId]
  const payload=modern
    ? ['sectalk/aws-kms-delete-event/v3',...fields,result.keyId,event.eventCategory,event.userIdentity.invokedBy,...material]
    : [material.length?'sectalk/aws-kms-delete-event/v2':'sectalk/aws-kms-delete-event/v1',...fields,...material]
  return {event:event.eventID,eventTime:time,sha256:createHash('sha256').update(JSON.stringify(payload)).digest('hex')}
}
