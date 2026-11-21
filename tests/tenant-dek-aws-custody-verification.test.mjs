import assert from 'node:assert/strict'
import {createCipheriv,createDecipheriv,randomBytes} from 'node:crypto'
import {once} from 'node:events'
import {test} from 'node:test'
import {createAdapter,readAllowlist} from '../services/tenant-dek-aws/adapter.mjs'
import {approvedBinding,exerciseAwsAdapter,inspectAwsCustody} from '../services/tenant-dek-aws/verify-custody.mjs'

const workspace='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
const reference='sandbox_v1'
const keyId='arn:aws:kms:ap-southeast-2:111111111111:key/11111111-aaaa-bbbb-cccc-111111111111'
const expectedRole='arn:aws:iam::222222222222:role/team/sectalk-audit'
const roleId='AROASYNTHETIC0123456789'
const row={workspace,version:1,reference,keyId}
const token='synthetic-custody-verifier-bearer'
const endpoint='https://adapter.example.invalid/v1/tenant-dek'
const adapterMap=JSON.stringify([row])
const config={
  SECTALK_TENANT_DEK_AWS_KEYS:adapterMap,
  SECTALK_EXTERNAL_KMS_KEYS:JSON.stringify({[workspace]:{active:reference,keys:{[reference]:keyId}}}),
  SECTALK_CUSTODY_EXPECTED_KEY_ARN:keyId,
  SECTALK_CUSTODY_EXPECTED_ROLE_ARN:expectedRole,
  SECTALK_CUSTODY_EXPECTED_ROLE_ID:roleId,
  AWS_CONTAINER_CREDENTIALS_RELATIVE_URI:'/v2/credentials/synthetic',
  AWS_ACCESS_KEY_ID:'injected-value-to-reject',
  AWS_ENDPOINT_URL:'https://override.example.invalid',
}
const binding=approvedBinding(config,workspace,1,reference)
const keyMetadata={
  Arn:keyId,KeyId:keyId.split('/').at(-1),AWSAccountId:'111111111111',Enabled:true,KeyState:'Enabled',
  KeyManager:'CUSTOMER',KeySpec:'SYMMETRIC_DEFAULT',KeyUsage:'ENCRYPT_DECRYPT',
  EncryptionAlgorithms:['SYMMETRIC_DEFAULT'],Origin:'AWS_KMS',MultiRegion:false,
}
const caller={
  Arn:'arn:aws:sts::222222222222:assumed-role/sectalk-audit/synthetic-session',Account:'222222222222',
  UserId:roleId+':synthetic-session',
}

test('custody binding requires exact independent ARN and agreement across app and adapter configuration',()=>{
  assert.deepEqual(binding,{...row,region:'ap-southeast-2'})
  assert.throws(()=>approvedBinding({...config,SECTALK_CUSTODY_EXPECTED_KEY_ARN:keyId+'1'},workspace,1,reference),/must agree/)
  assert.throws(()=>approvedBinding({...config,SECTALK_EXTERNAL_KMS_KEYS:'{}'},workspace,1,reference),/must agree/)
  assert.throws(()=>approvedBinding({...config,SECTALK_TENANT_DEK_AWS_KEYS:'private accidentally supplied'},
    workspace,1,reference),/^Error: The adapter custody mapping is invalid\.$/)
  assert.throws(()=>approvedBinding(config,workspace,2,reference),/bindings are required/)
})

test('AWS custody inspection is read-only, pins the effective role ID and rejects metadata drift',async()=>{
  const commands=[]
  let identity=caller
  let metadata=keyMetadata
  let expectedRequestKey=keyId
  const run=async(binary,args,options)=>{
    assert.equal(binary,'/usr/local/aws-cli/v2/current/bin/aws')
    assert.equal(options.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI,config.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI)
    assert.equal(options.env.AWS_ACCESS_KEY_ID,undefined)
    assert.equal(options.env.AWS_ENDPOINT_URL,undefined)
    commands.push(args.slice(0,2).join(' '))
    assert.equal(args[args.indexOf('--region')+1],binding.region)
    if(args[0]==='sts')return {stdout:JSON.stringify(identity)}
    assert.equal(args[args.indexOf('--key-id')+1],expectedRequestKey)
    return {stdout:JSON.stringify({KeyMetadata:metadata})}
  }
  const inspect=()=>inspectAwsCustody({binding,settings:config,expectedOrigin:'AWS_KMS',run})
  const report=await inspect()
  assert.deepEqual(commands,['sts get-caller-identity','kms describe-key'])
  assert.equal(report.scope,'single_region_key')
  assert.equal(report.erasure,'unverified')
  assert.equal(report.backupErasure,'unverified')
  for(const raw of [keyId,workspace,reference,expectedRole,roleId,caller.Arn])assert.ok(!JSON.stringify(report).includes(raw))
  identity={...caller,UserId:'AROAOTHER012345678912:synthetic-session'}
  await assert.rejects(inspect,/expected workload role/)
  assert.equal(commands.at(-1),'sts get-caller-identity')
  identity=caller
  for(const mismatch of [
    {Arn:keyId+'1'},{AWSAccountId:'222222222222'},{MultiRegion:true},{KeyManager:'AWS'},{Origin:'EXTERNAL'},
    {KeyState:'PendingDeletion'},{KeySpec:'RSA_2048'},{KeyUsage:'SIGN_VERIFY'},{EncryptionAlgorithms:[]},
  ]){
    metadata={...keyMetadata,...mismatch}
    await assert.rejects(inspect,/exact approved enabled symmetric customer key/)
  }
  const regionalKey=keyId.replace(/\/[^/]+$/,'/mrk-'+'d'.repeat(32))
  expectedRequestKey=regionalKey
  metadata={...keyMetadata,Arn:regionalKey,KeyId:regionalKey.split('/').at(-1),MultiRegion:true,Origin:'EXTERNAL'}
  const regional=await inspectAwsCustody({binding:{...binding,keyId:regionalKey},settings:config,expectedOrigin:'EXTERNAL',run})
  assert.equal(regional.scope,'regional_key_in_multi_region_set')
  assert.equal(regional.keyOrigin,'EXTERNAL')
  assert.equal(regional.erasure,'unverified')
})

test('non-production drill runs through the real adapter contract and fails if scope isolation is bypassed',async()=>{
  const key=randomBytes(32)
  let ignoreContext=false
  const server=createAdapter({token,bindings:readAllowlist(adapterMap),runKms:input=>{
    const fixed={KeyId:keyId,EncryptionAlgorithm:'SYMMETRIC_DEFAULT'}
    const aad=Buffer.from(ignoreContext?'':JSON.stringify(input.encryptionContext))
    if(input.operation==='wrap'){
      const iv=randomBytes(12)
      const cipher=createCipheriv('aes-256-gcm',key,iv).setAAD(aad)
      const encrypted=Buffer.concat([cipher.update(input.bytes),cipher.final()])
      return {...fixed,CiphertextBlob:Buffer.concat([iv,cipher.getAuthTag(),encrypted]).toString('base64')}
    }
    const decipher=createDecipheriv('aes-256-gcm',key,input.bytes.subarray(0,12)).setAAD(aad)
    decipher.setAuthTag(input.bytes.subarray(12,28))
    return {...fixed,Plaintext:Buffer.concat([decipher.update(input.bytes.subarray(28)),decipher.final()]).toString('base64')}
  }})
  server.listen(0,'127.0.0.1')
  await once(server,'listening')
  let calls=0
  const fetcher=(url,options)=>{
    calls++
    assert.equal(url.href,endpoint)
    assert.equal(options.redirect,'error')
    assert.equal(options.cache,'no-store')
    return fetch('http://127.0.0.1:'+server.address().port+url.pathname,options)
  }
  try{
    const request={binding,endpoint,approvedOrigin:new URL(endpoint).origin,token,approvedTestKey:true,fetcher}
    await assert.rejects(exerciseAwsAdapter({...request,approvedTestKey:false}),/explicit non-production/)
    await assert.rejects(exerciseAwsAdapter({...request,endpoint:endpoint.replace('https:','http:')}),/authenticated HTTPS/)
    await assert.rejects(exerciseAwsAdapter({...request,endpoint:endpoint.replace('adapter.','unapproved.')}),/authenticated HTTPS/)
    assert.equal(calls,0)
    const report=await exerciseAwsAdapter(request)
    assert.equal(calls,6)
    assert.equal(report.exactRoundTrip,true)
    assert.equal(report.contextIsolation,true)
    assert.equal(report.ciphertextIntegrity,true)
    assert.equal(report.mismatchedKeyRefused,true)
    assert.equal(report.erasure,'unverified')
    for(const raw of [workspace,reference,keyId,token,endpoint])assert.ok(!JSON.stringify(report).includes(raw))
    ignoreContext=true
    await assert.rejects(exerciseAwsAdapter(request),/unexpected custody status/)
  }finally{
    key.fill(0)
    server.closeAllConnections()
    await new Promise(resolve=>server.close(resolve))
  }
})
