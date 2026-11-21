import assert from 'node:assert/strict'
import { createCipheriv,createDecipheriv,createHash,randomBytes,randomUUID } from 'node:crypto'
import { createServer } from 'node:http'
import { test } from 'node:test'
import { encryptManagedArtifact,decryptManagedArtifact,openTenantRecord,rewrapManagedTenantRecord,sealTenantRecord,wrapFreshTenantKey } from '../apps/web/lib/tenant-artifact-keys.ts'

test('managed DEK rewrap preserves the original authenticated bytes across successive KEKs',async()=>{
  const setting='SECTALK_KMS_WRAPPING_KEY'
  const previous=process.env[setting]
  process.env[setting]=randomBytes(32).toString('base64url')
  try {
    const workspace=randomUUID(), channel=randomUUID(), message=randomUUID(), sender=randomUUID()
    const key=async (tenant,version)=>({workspace:tenant,version,custody:'managed',...await wrapFreshTenantKey(tenant,version,'managed')})
    const [first,second,third,foreign]=await Promise.all([
      key(workspace,1),key(workspace,2),key(workspace,3),key(randomUUID(),2),
    ])
    const plaintext=Buffer.from('Synthetic managed message\nExact content, emoji 🔐 and UTF-8 bytes')
    const original=await sealTenantRecord(first,channel,message,sender,plaintext)
    const before={...original}
    const secondWrap=await rewrapManagedTenantRecord(first,second,channel,message,sender,original)
    const envelope={...original,data_version:1,wrapped_dek:secondWrap}
    assert.notEqual(secondWrap,original.wrapped_dek)
    assert.deepEqual(original,before)
    assert.deepEqual(await openTenantRecord(first,channel,message,sender,original),plaintext)
    assert.deepEqual(await openTenantRecord(second,channel,message,sender,envelope),plaintext)
    await assert.rejects(openTenantRecord(second,channel,message,sender,{...envelope,data_version:2}))
    await assert.rejects(rewrapManagedTenantRecord(first,foreign,channel,message,sender,original))
    await assert.rejects(rewrapManagedTenantRecord(first,second,channel,randomUUID(),sender,original))
    await assert.rejects(rewrapManagedTenantRecord(first,second,channel,message,randomUUID(),original))
    await assert.rejects(rewrapManagedTenantRecord(first,second,channel,message,sender,
      {...original,tag:(original.tag[0]==='A'?'B':'A')+original.tag.slice(1)}))
    const thirdWrap=await rewrapManagedTenantRecord(second,third,channel,message,sender,envelope)
    assert.deepEqual(await openTenantRecord(third,channel,message,sender,{...envelope,wrapped_dek:thirdWrap}),plaintext)
  } finally {
    if (previous===undefined) delete process.env[setting]
    else process.env[setting]=previous
  }
})

test('managed export and evidence download rewrap preserves exact protected bytes and leaves legacy objects alone',async()=>{
  const previous=process.env.SECTALK_KMS_WRAPPING_KEY
  process.env.SECTALK_KMS_WRAPPING_KEY=randomBytes(32).toString('base64url')
  try {
    const workspace=randomUUID()
    const [source,target]=await Promise.all([wrapFreshTenantKey(workspace,1,'managed'),wrapFreshTenantKey(workspace,2,'managed')])
    for(const kind of ['compliance','evidence']) {
      const artifact=randomUUID(), ticket=randomUUID(), policy=randomUUID(), revision='b'.repeat(64)
      const plaintext=Buffer.from(JSON.stringify({fixture:kind,proof:'Exact approved UTF-8 content 🔐'}))
      const state={workspace,kind,sha256:createHash('sha256').update(plaintext).digest('hex'),bytes:plaintext.length,
        version:1,custody:'managed',...source}
      let attempts=0, legacy=false, reject=false
      const storage={async rpc(name,args) {
        assert.equal(args.p_ticket,ticket)
        assert.equal(args.p_artifact,artifact)
        if(name==='st_v7_export_key_context')return {data:legacy?{legacy:true}:{...state}}
        if(name==='st_v7_bind_export_envelope') {
          Object.assign(state,{wrapped_dek:args.p_key,nonce:args.p_nonce,tag:args.p_tag}); return {data:true}
        }
        assert.equal(name,'st_v8_commit_protected_artifact_rewrap')
        assert.deepEqual(args,{p_ticket:ticket,p_artifact:artifact,p_policy_revision:policy,p_source_revision:revision,
          p_previous:1,p_target:2,p_wrapped_dek:args.p_wrapped_dek})
        assert.notEqual(args.p_wrapped_dek,state.wrapped_dek)
        attempts++
        if(reject)throw new Error('Synthetic compare-and-swap failure')
        Object.assign(state,{...target,wrapped_dek:args.p_wrapped_dek,data_version:1,version:2,rewrap:null})
        return {data:true}
      }}
      const ciphertext=await encryptManagedArtifact(storage,ticket,artifact,plaintext)
      const stored=Buffer.from(ciphertext)
      state.rewrap={source_revision:revision,policy_revision:policy,version:2,wrapped:target.wrapped}
      const damaged=Buffer.from(ciphertext)
      damaged[0]^=1
      await assert.rejects(decryptManagedArtifact(storage,ticket,artifact,damaged))
      assert.equal(attempts,0)
      reject=true
      assert.deepEqual(await decryptManagedArtifact(storage,ticket,artifact,ciphertext),plaintext)
      assert.equal(state.version,1)
      reject=false
      assert.deepEqual(await decryptManagedArtifact(storage,ticket,artifact,ciphertext),plaintext)
      assert.equal(state.version,2)
      assert.deepEqual(await decryptManagedArtifact(storage,ticket,artifact,ciphertext),plaintext)
      assert.deepEqual(ciphertext,stored)
      legacy=true
      assert.deepEqual(await decryptManagedArtifact(storage,ticket,artifact,plaintext),plaintext)
      assert.equal(attempts,2)
    }
  } finally {
    if(previous===undefined)delete process.env.SECTALK_KMS_WRAPPING_KEY
    else process.env.SECTALK_KMS_WRAPPING_KEY=previous
  }
})

test('loopback Enterprise custody contract binds the KEK while the artifact envelope binds exact tenant and bytes',async () => {
  const tenant=randomUUID()
  const foreign=randomUUID()
  const artifact=randomUUID()
  const token=randomBytes(32).toString('base64url')
  const reference='fixture-root'
  const inputs=[]
  const roots=new Map([[tenant,randomBytes(32)],[foreign,randomBytes(32)]])
  const server=createServer(async (request,response)=>{
    try {
      if (request.method!=='POST' || request.url!=='/tenant-key' || request.headers.authorization!=='Bearer '+token) {
        response.writeHead(403).end(); return
      }
      let raw=''
      for await (const piece of request) {
        raw+=piece.toString()
        if (raw.length>3200) { response.writeHead(413).end(); return }
      }
      const { operation,workspace,version,reference:ref,value }=JSON.parse(raw)
      const key=roots.get(workspace)
      if (!key || ref!==reference || version!==1 || !['wrap','unwrap'].includes(operation)) {
        response.writeHead(403).end(); return
      }
      const aad=Buffer.from(JSON.stringify([workspace,ref,version]))
      const bytes=Buffer.from(value,'base64url')
      inputs.push({operation,workspace})
      let result
      if (operation==='wrap' && bytes.length===32) {
        const nonce=randomBytes(12)
        const cipher=createCipheriv('aes-256-gcm',key,nonce).setAAD(aad)
        const encrypted=Buffer.concat([cipher.update(bytes),cipher.final()])
        result=Buffer.concat([nonce,cipher.getAuthTag(),encrypted])
      } else if (operation==='unwrap' && bytes.length===60) {
        const decipher=createDecipheriv('aes-256-gcm',key,bytes.subarray(0,12))
          .setAAD(aad).setAuthTag(bytes.subarray(12,28))
        result=Buffer.concat([decipher.update(bytes.subarray(28)),decipher.final()])
      } else {
        response.writeHead(400).end(); return
      }
      response.writeHead(200,{'Content-Type':'application/json'}).end(JSON.stringify({value:result.toString('base64url')}))
    } catch { response.writeHead(403).end() }
  })
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve))
  const port=server.address().port
  const variables={
    NEXT_PUBLIC_SUPABASE_URL:'http://127.0.0.1:55321',
    SECTALK_KMS_BYOK_FIXTURE_URL:'http://127.0.0.1:'+port+'/tenant-key',
    SECTALK_KMS_BYOK_FIXTURE_TOKEN:token,
    SECTALK_KMS_BYOK_FIXTURE_REFS:JSON.stringify({[tenant]:reference,[foreign]:reference}),
    SECTALK_KMS_WRAPPING_KEY:randomBytes(32).toString('base64url'),
  }
  const previous=Object.fromEntries(Object.keys(variables).map(key=>[key,process.env[key]]))
  Object.assign(process.env,variables)
  try {
    const external=await wrapFreshTenantKey(tenant,1,'byok')
    assert.equal(external.ref,reference)
    const plaintext=Buffer.from('Benign synthetic tenant export bytes')
    const state={workspace:tenant,kind:'compliance',sha256:'1'.repeat(64),bytes:plaintext.length,
      version:1,custody:'byok',ref:external.ref,wrapped:external.wrapped,wrapped_dek:null,nonce:null,tag:null}
    const mock={async rpc(name,args){
      if (name==='st_v7_export_key_context') return {data:state}
      if (name==='st_v7_bind_export_envelope') {
        Object.assign(state,{wrapped_dek:args.p_key,nonce:args.p_nonce,tag:args.p_tag})
        return {data:true}
      }
      throw new Error('Unexpected RPC')
    }}
    const ciphertext=await encryptManagedArtifact(mock,'fixture-ticket',artifact,plaintext)
    assert.notDeepEqual(ciphertext,plaintext)
    assert.equal(ciphertext.length,plaintext.length)
    assert.deepEqual(await decryptManagedArtifact(mock,'fixture-ticket',artifact,ciphertext),plaintext)
    await assert.rejects(decryptManagedArtifact(mock,'fixture-ticket',randomUUID(),ciphertext))
    const changed=Buffer.from(ciphertext)
    changed[0]^=1
    await assert.rejects(decryptManagedArtifact(mock,'fixture-ticket',artifact,changed))
    state.workspace=foreign
    await assert.rejects(decryptManagedArtifact(mock,'fixture-ticket',artifact,ciphertext))
    process.env.SECTALK_KMS_BYOK_FIXTURE_TOKEN=randomBytes(32).toString('base64url')
    await assert.rejects(wrapFreshTenantKey(tenant,1,'byok'))
    assert.ok(!JSON.stringify(inputs).includes(plaintext.toString()))
    assert.ok(inputs.some(call=>call.operation==='wrap' && call.workspace===tenant))
    assert.ok(inputs.some(call=>call.operation==='unwrap' && call.workspace===tenant))
  } finally {
    for (const [key,value] of Object.entries(previous)) {
      if (value===undefined) delete process.env[key]
      else process.env[key]=value
    }
    await new Promise(resolve=>server.close(resolve))
  }
})

test('external v2 custody wraps only per-object DEKs and keeps historical provider pins live across rotation',async()=>{
  const tenant=randomUUID()
  const outside=randomUUID()
  const post=randomUUID()
  const actor=randomUUID()
  const channel=randomUUID()
  const token=randomBytes(32).toString('base64url')
  const configurations={
    [tenant]:{active:'first',keys:{first:'keys/immutable-1',second:'keys/immutable-2'}},
    [outside]:{active:'outside',keys:{outside:'keys/immutable-outside'}},
  }
  const roots=new Map([
    ['keys/immutable-1',{workspace:tenant,root:randomBytes(32)}],
    ['keys/immutable-2',{workspace:tenant,root:randomBytes(32)}],
    ['keys/immutable-outside',{workspace:outside,root:randomBytes(32)}],
  ])
  const requests=[]
  let wrongContext=false
  const server=createServer(async(request,response)=>{
    try {
      assert.equal(request.url,'/v1/tenant-dek')
      assert.equal(request.headers.authorization,'Bearer '+token)
      const chunks=[]
      for await(const chunk of request)chunks.push(Buffer.from(chunk))
      const {operation,workspace,version,reference,keyId,context,value}=JSON.parse(Buffer.concat(chunks).toString())
      const current=roots.get(keyId)
      if (!current || current.workspace!==workspace) return response.writeHead(403).end()
      assert.ok(['wrap','unwrap'].includes(operation))
      const contextTuple=JSON.parse(Buffer.from(context,'base64url').toString())
      assert.deepEqual(contextTuple.slice(0,5),['sectalk/external-dek/v2',workspace,version,reference,keyId])
      assert.match(contextTuple[5],/^[A-Za-z0-9_-]{43}$/)
      const aad=Buffer.from(context)
      const input=Buffer.from(value,'base64url')
      requests.push({operation,workspace,ref:keyId,bytes:input.length})
      let result
      if(operation==='wrap'){
        assert.equal(input.length,32)
        const nonce=randomBytes(12)
        const cipher=createCipheriv('aes-256-gcm',current.root,nonce).setAAD(aad)
        const body=Buffer.concat([cipher.update(input),cipher.final()])
        result=Buffer.concat([Buffer.from('mock-kms'),nonce,cipher.getAuthTag(),body])
      }else{
        assert.equal(input.subarray(0,8).toString(),'mock-kms')
        const decipher=createDecipheriv('aes-256-gcm',current.root,input.subarray(8,20))
          .setAAD(aad).setAuthTag(input.subarray(20,36))
        result=Buffer.concat([decipher.update(input.subarray(36)),decipher.final()])
      }
      response.writeHead(200,{'Content-Type':'application/json'}).end(JSON.stringify({
        keyId,context:wrongContext?'mismatched':context,value:result.toString('base64url'),
      }))
    }catch{response.writeHead(403).end()}
  })
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve))
  const variables={
    NEXT_PUBLIC_SUPABASE_URL:'http://127.0.0.1:55321',
    SECTALK_EXTERNAL_KMS_URL:'http://127.0.0.1:'+server.address().port+'/v1/tenant-dek',
    SECTALK_EXTERNAL_KMS_TOKEN:token,
    SECTALK_EXTERNAL_KMS_KEYS:JSON.stringify(configurations),
  }
  const previous=Object.fromEntries(Object.keys(variables).map(key=>[key,process.env[key]]))
  Object.assign(process.env,variables)
  const provision=async(workspace,version)=>({workspace,version,custody:'byok',...await wrapFreshTenantKey(workspace,version,'byok')})
  try{
    const one=await provision(tenant,1)
    assert.match(one.wrapped,/^external_v2_[A-Za-z0-9_-]{43}_[A-Za-z0-9_-]{43}$/)
    const plaintext=Buffer.from('Synthetic bytes never supplied to the custodian')
    const first=await sealTenantRecord(one,channel,post,actor,plaintext)
    assert.equal(Buffer.from(first.wrapped_dek,'base64url').subarray(0,8).toString(),'mock-kms')
    assert.deepEqual(await openTenantRecord(one,channel,post,actor,first),plaintext)
    await assert.rejects(openTenantRecord(one,randomUUID(),post,actor,first))
    await assert.rejects(openTenantRecord({...one,workspace:outside},channel,post,actor,first))
    wrongContext=true
    await assert.rejects(openTenantRecord(one,channel,post,actor,first),/Invalid key provider response/)
    wrongContext=false

    configurations[tenant].active='second'
    process.env.SECTALK_EXTERNAL_KMS_KEYS=JSON.stringify(configurations)
    const two=await provision(tenant,2)
    assert.notEqual(one.wrapped.slice(0,55),two.wrapped.slice(0,55))
    const second=await sealTenantRecord(two,channel,post,actor,plaintext)
    assert.deepEqual(await openTenantRecord(one,channel,post,actor,first),plaintext)
    assert.deepEqual(await openTenantRecord(two,channel,post,actor,second),plaintext)
    await assert.rejects(openTenantRecord(two,channel,post,actor,first))

    const artifact=randomUUID()
    const state={...one,kind:'evidence',sha256:'2'.repeat(64),bytes:plaintext.length,
      wrapped_dek:null,nonce:null,tag:null}
    const storage={async rpc(name,args){
      if(name==='st_v7_export_key_context') return {data:state}
      assert.equal(name,'st_v7_bind_export_envelope')
      Object.assign(state,{wrapped_dek:args.p_key,nonce:args.p_nonce,tag:args.p_tag})
      return {data:true}
    }}
    const bytes=await encryptManagedArtifact(storage,'fixture',artifact,plaintext)
    assert.deepEqual(await decryptManagedArtifact(storage,'fixture',artifact,bytes),plaintext)

    const other=await provision(outside,1)
    const otherPayload=await sealTenantRecord(other,channel,post,actor,plaintext)
    const originalRef=configurations[tenant].keys.first
    configurations[tenant].keys.first=configurations[tenant].keys.second
    process.env.SECTALK_EXTERNAL_KMS_KEYS=JSON.stringify(configurations)
    const count=requests.length
    await assert.rejects(openTenantRecord(one,channel,post,actor,first),/reference has changed/)
    assert.equal(requests.length,count)
    configurations[tenant].keys.first=originalRef
    process.env.SECTALK_EXTERNAL_KMS_KEYS=JSON.stringify(configurations)

    // Only the disposable fixture relinquishes a synthetic key, with no app delete operation.
    roots.get(originalRef).root.fill(0)
    roots.delete(originalRef)
    await assert.rejects(openTenantRecord(one,channel,post,actor,first))
    await assert.rejects(decryptManagedArtifact(storage,'fixture',artifact,bytes))
    assert.deepEqual(await openTenantRecord(two,channel,post,actor,second),plaintext)
    assert.deepEqual(await openTenantRecord(other,channel,post,actor,otherPayload),plaintext)
    assert.ok(requests.every(request=>request.operation!=='wrap'||request.bytes===32))
  }finally{
    for(const [key,value] of Object.entries(previous)){
      if(value===undefined)delete process.env[key]
      else process.env[key]=value
    }
    await new Promise(resolve=>server.close(resolve))
  }
})
