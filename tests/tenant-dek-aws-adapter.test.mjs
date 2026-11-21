import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'
import { once } from 'node:events'
import { test } from 'node:test'
import { openTenantRecord, sealTenantRecord, wrapFreshTenantKey } from '../apps/web/lib/tenant-artifact-keys.ts'
import { awsRunner, createAdapter, readAllowlist, workloadEnvironment } from '../services/tenant-dek-aws/adapter.mjs'

const token='synthetic-service-bearer-long-enough'
const keyId='arn:aws:kms:ap-southeast-2:111111111111:key/11111111-aaaa-bbbb-cccc-111111111111'
const otherKey='arn:aws:kms:us-east-1:111111111111:key/22222222-aaaa-bbbb-cccc-222222222222'
const workspace='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
const otherWorkspace='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
const binding={workspace,version:1,reference:'rotation_1',keyId}
const otherBinding={workspace:otherWorkspace,version:1,reference:'rotation_1',keyId:otherKey}
const scope=createHash('sha256').update('synthetic protected record').digest('base64url')
const contextFor=({workspace,version,reference,keyId},digest=scope)=>
  Buffer.from(JSON.stringify(['sectalk/external-dek/v2',workspace,version,reference,keyId,digest])).toString('base64url')

async function listen(runKms) {
  const server=createAdapter({token,bindings:readAllowlist(JSON.stringify([binding,otherBinding])),runKms})
  server.listen(0,'127.0.0.1')
  await once(server,'listening')
  const root='http://127.0.0.1:'+server.address().port
  return {
    root,
    async post(input,options={}) {
      return fetch(root+'/v1/tenant-dek',{
        method:'POST',body:JSON.stringify(input),
        headers:{'content-type':'application/json',authorization:'Bearer '+token,...options},
      })
    },
    async close() { server.closeAllConnections(); await new Promise(resolve=>server.close(resolve)) },
  }
}

test('exact allowlist rejects aliases and repeats and workload credentials omit override channels',()=>{
  const allowlist=readAllowlist(JSON.stringify([binding,otherBinding]))
  assert.equal(allowlist.size,2)
  assert.throws(()=>readAllowlist(JSON.stringify([{...binding,keyId:keyId.replace(':key/',':alias/')}])) )
  assert.throws(()=>readAllowlist(JSON.stringify([binding,{...binding,version:2}])))
  assert.throws(()=>readAllowlist(JSON.stringify([binding,{...binding,keyId:otherKey}])))
  assert.throws(()=>readAllowlist(JSON.stringify([{...binding,version:0}])))
  const role={AWS_WEB_IDENTITY_TOKEN_FILE:'/var/run/token',AWS_ROLE_ARN:'arn:aws:iam::111111111111:role/sectalk-tenant-dek'}
  const env=workloadEnvironment({...role,AWS_ACCESS_KEY_ID:'ignored',AWS_SECRET_ACCESS_KEY:'ignored',
    AWS_PROFILE:'ignored',AWS_ENDPOINT_URL:'ignored',HTTP_PROXY:'ignored'})
  assert.equal(env.AWS_ROLE_ARN,role.AWS_ROLE_ARN)
  for(const variable of ['AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_PROFILE','AWS_ENDPOINT_URL','HTTP_PROXY']) {
    assert.equal(env[variable],undefined)
  }
  assert.equal(env.AWS_IGNORE_CONFIGURED_ENDPOINT_URLS,'true')
  assert.equal(env.AWS_SHARED_CREDENTIALS_FILE,'/dev/null')
  const task={AWS_CONTAINER_CREDENTIALS_RELATIVE_URI:'/v2/credentials/abc-123'}
  assert.equal(workloadEnvironment(task).AWS_CONTAINER_CREDENTIALS_RELATIVE_URI,task.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI)
  assert.throws(()=>workloadEnvironment({...role,...task}))
  assert.throws(()=>workloadEnvironment({AWS_CONTAINER_CREDENTIALS_FULL_URI:'https://example.invalid/credentials'}))
})

test('AWS runner pins the binary, operation, region and context and sends DEK bytes only on stdin',async()=>{
  const raw=randomBytes(32)
  const encryptionContext={purpose:'sectalk-tenant-dek-v2',binding:'a'.repeat(64)}
  const env={PATH:'/usr/local/bin:/usr/bin:/bin'}
  const run=awsRunner(env,(command,args,options)=>{
    assert.equal(command,'/bin/sh')
    assert.deepEqual(args.slice(0,6),['-c','/bin/cat | exec "$@"','sectalk-kms',
      '/usr/local/aws-cli/v2/current/bin/aws','kms','encrypt'])
    assert.equal(args[args.indexOf('--region')+1],'ap-southeast-2')
    assert.equal(args[args.indexOf('--key-id')+1],keyId)
    assert.equal(args[args.indexOf('--plaintext')+1],'fileb:///dev/stdin')
    assert.deepEqual(JSON.parse(args[args.indexOf('--encryption-context')+1]),encryptionContext)
    assert.ok(!args.join(' ').includes(raw.toString('base64')))
    assert.equal(options.env,env)
    assert.equal(options.detached,true)
    assert.deepEqual(options.stdio,['pipe','pipe','ignore'])
    return spawn(process.execPath,['-e',`const chunks=[]; process.stdin.on('data',chunk=>chunks.push(chunk));
      process.stdin.on('end',()=>console.log(JSON.stringify({ received:Buffer.concat(chunks).toString('hex') })))`],
    {stdio:options.stdio,windowsHide:true})
  })
  const result=await run({operation:'wrap',bytes:raw,keyId,region:'ap-southeast-2',encryptionContext})
  assert.equal(result.received,raw.toString('hex'))
})

test('Linux subprocess can reopen the runner pipe as a binary file',{skip:process.platform!=='linux'},async()=>{
  const raw=randomBytes(32)
  const run=awsRunner(workloadEnvironment({AWS_CONTAINER_CREDENTIALS_RELATIVE_URI:'/v2/credentials/synthetic'}),
    (command,args,options)=>spawn(command,[...args.slice(0,3),process.execPath,'-e',
      `const fs=require('node:fs');
      const path=process.argv.at(-1).slice('fileb://'.length);
      console.log(JSON.stringify({ received:fs.readFileSync(path).toString('hex') }))`,
      '--',args[args.indexOf('--plaintext')+1]],options))
  const result=await run({operation:'wrap',bytes:raw,keyId,region:'ap-southeast-2',encryptionContext:{purpose:'fixture'}})
  assert.equal(result.received,raw.toString('hex'))
})

test('adapter and app bind capsules to the exact record and tenant and deny changed custody and bad responses',async()=>{
  const keys=new Map([[keyId,randomBytes(32)],[otherKey,randomBytes(32)]])
  let calls=0,wrongKey=false
  const api=await listen(input=>{
    calls++
    const key=keys.get(input.keyId)
    if(!key)throw new Error('key unavailable')
    const fixed={KeyId:wrongKey?otherKey:input.keyId,EncryptionAlgorithm:'SYMMETRIC_DEFAULT'}
    const aad=Buffer.from(JSON.stringify(input.encryptionContext))
    if(input.operation==='wrap') {
      const iv=randomBytes(12)
      const cipher=createCipheriv('aes-256-gcm',key,iv).setAAD(aad)
      const ciphertext=Buffer.concat([cipher.update(input.bytes),cipher.final()])
      return {...fixed,CiphertextBlob:Buffer.concat([iv,cipher.getAuthTag(),ciphertext]).toString('base64')}
    }
    const decipher=createDecipheriv('aes-256-gcm',key,input.bytes.subarray(0,12)).setAAD(aad)
    decipher.setAuthTag(input.bytes.subarray(12,28))
    return {...fixed,Plaintext:Buffer.concat([decipher.update(input.bytes.subarray(28)),decipher.final()]).toString('base64')}
  })
  const settings={NEXT_PUBLIC_SUPABASE_URL:'http://127.0.0.1:55321',
    SECTALK_EXTERNAL_KMS_URL:api.root+'/v1/tenant-dek',SECTALK_EXTERNAL_KMS_TOKEN:token,
    SECTALK_EXTERNAL_KMS_KEYS:JSON.stringify({[workspace]:{active:binding.reference,keys:{[binding.reference]:keyId}}}),
  }
  const previous=Object.fromEntries(Object.keys(settings).map(key=>[key,process.env[key]]))
  try {
    Object.assign(process.env,settings)
    const wrap={...binding,context:contextFor(binding),operation:'wrap',value:randomBytes(32).toString('base64url')}
    let response=await api.post(wrap,{authorization:'Bearer other'})
    assert.equal(response.status,401)
    response=await api.post(wrap,{'content-type':'text/plain'})
    assert.equal(response.status,415)
    for(const changed of [{keyId:otherKey},{version:2},{reference:'rotation_2'},{workspace:otherWorkspace},
      {value:wrap.value+'='},{context:contextFor(otherBinding)},{operation:'export'},{extra:true}]) {
      response=await api.post({...wrap,...changed})
      assert.equal(response.status,403)
      await response.text()
    }
    assert.equal(calls,0)

    response=await api.post(wrap)
    assert.equal(response.status,200)
    assert.equal(response.headers.get('cache-control'),'no-store')
    const wrapped=await response.json()
    assert.equal(wrapped.keyId,keyId)
    assert.equal(wrapped.context,wrap.context)
    assert.notEqual(wrapped.value,wrap.value)
    const unwrap={...wrap,operation:'unwrap',value:wrapped.value}
    response=await api.post(unwrap)
    assert.deepEqual(await response.json(),{keyId,context:wrap.context,value:wrap.value})

    const changedScope=createHash('sha256').update('another record').digest('base64url')
    const tampered=Buffer.from(wrapped.value,'base64url')
    tampered[35]^=1
    for(const changed of [{context:contextFor(binding,changedScope)},
      {...otherBinding,context:contextFor(otherBinding)},{value:tampered.toString('base64url')}]) {
      response=await api.post({...unwrap,...changed})
      assert.equal(response.status,503)
      assert.deepEqual(await response.json(),{error:'Key operation unavailable'})
    }
    wrongKey=true
    assert.equal((await api.post(unwrap)).status,503)
    wrongKey=false
    const fresh=await wrapFreshTenantKey(workspace,1,'byok')
    assert.match(fresh.wrapped,/^external_v2_/)
    const appKey={workspace,version:1,custody:'byok',...fresh}
    const plaintext=Buffer.from('Synthetic managed post')
    const envelope=await sealTenantRecord(appKey,'room-example','message-example','author-example',plaintext)
    assert.notEqual(envelope.body,plaintext.toString('base64url'))
    assert.deepEqual(await openTenantRecord(appKey,'room-example','message-example','author-example',envelope),plaintext)
    await assert.rejects(openTenantRecord(appKey,'room-example','wrong-record','author-example',envelope))
    keys.delete(keyId)
    assert.equal((await api.post(unwrap)).status,503)
    await assert.rejects(openTenantRecord(appKey,'room-example','message-example','author-example',envelope))
  } finally {
    for(const [key,value] of Object.entries(previous)) {
      if(value===undefined)delete process.env[key]
      else process.env[key]=value
    }
    await api.close()
  }
})
