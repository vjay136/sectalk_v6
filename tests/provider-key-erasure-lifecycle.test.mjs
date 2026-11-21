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
    managementEvent:true,eventCategory:'Management',userIdentity:{accountId:account,invokedBy:'AWS Internal'},
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

test('both reviewers reject malformed modern records and look past them to a valid service event',async()=>{
  const modern=event(single,{keyId:single})
  const invalid=[event(single,{keyId:wrong}),event(single,null),event(single,{}),event(single,[]),
    {...modern,managementEvent:false},
    {...modern,eventCategory:'Data'},
    {...modern,userIdentity:{accountId:account,invokedBy:'unrelated.amazonaws.com'}},
    {...modern,userIdentity:{...modern.userIdentity,accountId:'000000000000'}},
    {...modern,eventTime:new Date(now+60_000).toISOString()},
    {...modern,eventID:'invalid'},
    {...modern,errorMessage:'unexpected provider failure'},
  ]
  let matches=invalid
  const observe=awsErasureObserver({},async(_binary,args)=>{
    if(args[1]==='describe-key')throw awsNotFound()
    return {stdout:JSON.stringify({Events:matches.map(value=>JSON.stringify(value))})}
  },()=>now)
  const address={keyId:single,region,stagedAt}
  assert.deepEqual(await observe(address),{state:'not_found'})
  matches=[...invalid,modern]
  assert.deepEqual(await observe(address),{state:'not_found',event:modern})
  const check=value=>providerErasureObservation({keyId:single,state:'not_found',event:value},single,stagedAt,now)
  for(const entry of invalid) assert.deepEqual(check(entry),{state:'unavailable'})
  const completion=check(modern)
  assert.equal(completion.state,'deleted_event')
  assert.match(completion.sha256,/^[a-f0-9]{64}$/)
  assert.deepEqual(check(modern),completion)
  const historical={...event(single,null),eventTime:'2022-11-22T00:00:00Z'}
  assert.equal(providerErasureObservation({keyId:single,state:'not_found',event:historical},
    single,'2022-11-21T00:00:00Z',now).state,'deleted_event')
})

test('custom key store deletion requires successful evidence for every listed backing key',async()=>{
  const cloudHsm={customKeyStoreId:'cks-1234567890abcdef0',clusterId:'cluster-abc123',
    backingKeys:JSON.stringify([{backingKeyId:'one'},{backingKeyId:'two'}])}
  const success=[{backingKeyId:'one',deletionStatus:'SUCCESS'},{backingKeyId:'two',deletionStatus:'SUCCESS'}]
  const withDetails=additionalEventData=>({...event(single,{keyId:single}),additionalEventData})
  const complete=withDetails({...cloudHsm,backingKeysDeletionStatus:JSON.stringify(success)})
  const rejected=[
    withDetails(cloudHsm),
    withDetails({...cloudHsm,backingKeysDeletionStatus:'invalid'}),
    withDetails({...cloudHsm,backingKeysDeletionStatus:JSON.stringify([success[0]])}),
    withDetails({...cloudHsm,backingKeysDeletionStatus:JSON.stringify([success[0],success[0]])}),
    withDetails({...cloudHsm,backingKeysDeletionStatus:JSON.stringify([success[0],{...success[1],deletionStatus:'FAILURE'}])}),
    withDetails({...cloudHsm,backingKeysDeletionStatus:JSON.stringify([success[0],{...success[1],backingKeyId:'unrelated'}])}),
    withDetails({customKeyStoreId:cloudHsm.customKeyStoreId,xksKeyId:'external-key'}),
    withDetails({customKeyStoreType:'AWS_CLOUDHSM'}),
    withDetails({customKeyStoreType:'EXTERNAL_KEY_STORE'}),
  ]
  const address={keyId:single,region,stagedAt}
  let entries=rejected
  const observe=awsErasureObserver({},async(_binary,args)=>{
    if(args[1]==='describe-key')throw awsNotFound()
    return {stdout:JSON.stringify({Events:entries.map(value=>JSON.stringify(value))})}
  })
  const check=value=>providerErasureObservation({keyId:single,state:'not_found',event:value},single,stagedAt,now)
  assert.deepEqual(await observe(address),{state:'not_found'})
  for(const entry of rejected) assert.deepEqual(check(entry),{state:'unavailable'})

  entries=[...rejected,complete]
  assert.deepEqual(await observe(address),{state:'not_found',event:complete})
  const receipt=check(complete)
  assert.equal(receipt.state,'deleted_event')
  assert.notEqual(receipt.sha256,check(event(single,{keyId:single})).sha256)
  assert.notEqual(receipt.sha256,check(withDetails({...complete.additionalEventData,clusterId:'cluster-other'})).sha256)
  assert.deepEqual(receipt,check(withDetails({...complete.additionalEventData,
    backingKeys:JSON.stringify([{backingKeyId:'two'},{backingKeyId:'one'}]),
    backingKeysDeletionStatus:JSON.stringify([...success].reverse()),
  })))
})
