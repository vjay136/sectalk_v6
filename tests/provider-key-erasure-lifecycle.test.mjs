import assert from 'node:assert/strict'
import {test} from 'node:test'
import {providerErasureObservation} from '../apps/web/lib/provider-key-erasure-observation.ts'
import {awsErasureObserver} from '../services/tenant-dek-aws/erasure-attestor.mjs'

const region='us-east-1'
const account='111122223333'
const root='arn:aws:kms:'+region+':'+account+':key/'
const single=root+'11111111-aaaa-bbbb-cccc-111111111111'
const wrong=root+'22222222-aaaa-bbbb-cccc-222222222222'
const regional=root+'mrk-'+'a'.repeat(32)
const stagedAt='2026-11-16T12:00:00Z'
const after='2026-11-17T12:00:00Z'
const now=Date.parse('2026-11-18T12:00:00Z')
const uuid='aaaaaaaa-bbbb-cccc-dddd-aaaaaaaaaaaa'

function event(keyId,responseElements){
  return {eventID:uuid,eventTime:after,eventSource:'kms.amazonaws.com',eventName:'DeleteKey',eventType:'AwsServiceEvent',
    awsRegion:region,recipientAccountId:account,readOnly:false,
    resources:[{ARN:keyId,type:'AWS::KMS::Key',accountId:account}],responseElements}
}

function awsNotFound(){
  return Object.assign(new Error('Synthetic provider exception'),{
    stderr:'An error occurred (NotFoundException) when calling the DescribeKey operation',
  })
}

test('one deleted multi-Region replica never produces an erasure receipt while pending state remains visible',async()=>{
  let deleted=false
  const calls=[]
  const observe=awsErasureObserver({},async(_binary,args)=>{
    calls.push(args.slice(0,2))
    assert.equal(args[1],'describe-key','Multi-Region replica observations must avoid completed event lookup')
    if(deleted)throw awsNotFound()
    return {stdout:JSON.stringify({KeyMetadata:{Arn:regional,AWSAccountId:account,KeyState:'PendingReplicaDeletion'}})}
  })
  const address={keyId:regional,region,stagedAt}
  assert.deepEqual(await observe(address),{state:'pending_replica_deletion'})
  deleted=true
  assert.deepEqual(await observe(address),{state:'unavailable'})
  assert.deepEqual(calls,[['kms','describe-key'],['kms','describe-key']])
  assert.deepEqual(providerErasureObservation({keyId:regional,state:'pending_replica_deletion'},regional,stagedAt,now),
    {state:'pending_replica_deletion'})
  assert.deepEqual(providerErasureObservation({keyId:regional,state:'not_found',event:event(regional,{keyId:regional})},
    regional,stagedAt,now),{state:'unavailable'})
})

test('single-Region evidence requires agreement for the modern response ARN and keeps the exact legacy digest',async()=>{
  const legacy=event(single,null),modern=event(single,{keyId:single}),mismatch=event(single,{keyId:wrong})
  let matches=[mismatch]
  const observe=awsErasureObserver({},async(_binary,args)=>{
    if(args[1]==='describe-key')throw awsNotFound()
    return {stdout:JSON.stringify({Events:matches.map(value=>JSON.stringify(value))})}
  })
  const address={keyId:single,region,stagedAt}
  assert.deepEqual(await observe(address),{state:'not_found'})
  matches=[mismatch,modern]
  assert.deepEqual(await observe(address),{state:'not_found',event:modern})
  const check=value=>providerErasureObservation({keyId:single,state:'not_found',event:value},single,stagedAt,now)
  assert.deepEqual(check(mismatch),{state:'unavailable'})
  const legacyResult=check(legacy)
  assert.equal(legacyResult.state,'deleted_event')
  assert.match(legacyResult.sha256,/^[a-f0-9]{64}$/)
  assert.deepEqual(check(modern),legacyResult)
  assert.deepEqual(check(event(single,[])),{state:'unavailable'})
})
