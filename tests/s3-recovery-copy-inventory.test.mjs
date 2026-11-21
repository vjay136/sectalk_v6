import assert from 'node:assert/strict'
import {spawnSync} from 'node:child_process'
import {createHash} from 'node:crypto'
import {mkdtemp,rmdir,unlink,writeFile} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import {test} from 'node:test'
import {fileURLToPath} from 'node:url'
import {captureS3RecoveryCopies,recoveryScopeDigest,verifyS3RecoveryInventory}
  from '../services/tenant-dek-aws/s3-recovery-copy-inventory.mjs'

const scope={workspace:'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',version:4,bucket:'protected-archive-test',
  owner:'111111111111',region:'ap-southeast-2',prefix:'recovery/project-a/'}
const approvedScope=recoveryScopeDigest(scope)
const key=scope.prefix+'historical résumé %25'
const otherKey=scope.prefix+'other.pgdump'
const markerVersion='marker+/%valid'
const timestamp='2026-10-01T02:49:00+00:00'
const encode=value=>encodeURIComponent(value)
const settings={AWS_CONTAINER_CREDENTIALS_RELATIVE_URI:'/v2/credentials/fixture-only',
  AWS_ENDPOINT_URL:'https://untrusted.example.invalid',AWS_ACCESS_KEY_ID:'fake-access'}
const time=()=>new Date('2026-10-02T03:10:00Z')
const sha=value=>createHash('sha256').update(value).digest('hex')

function version(Key,VersionId,IsLatest){
  return {Key:encode(Key),VersionId,IsLatest,LastModified:timestamp,Size:56,ETag:'"provider-etag"',
    StorageClass:'GLACIER_IR'}
}

function fixture(change=page=>page,versioning=()=>({Status:'Enabled'}),location=scope.region){
  const calls=[]
  let pass=0
  const run=async(binary,args,options)=>{
    assert.equal(binary,'/usr/local/aws-cli/v2/current/bin/aws')
    assert.equal(options.env.AWS_ENDPOINT_URL,undefined)
    assert.equal(options.env.AWS_ACCESS_KEY_ID,undefined)
    assert.equal(options.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI,settings.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI)
    assert.equal(args[0],'s3api')
    assert.equal(args[args.indexOf('--bucket')+1],scope.bucket)
    assert.equal(args[args.indexOf('--expected-bucket-owner')+1],scope.owner)
    assert.equal(args[args.indexOf('--region')+1],scope.region)
    const action=args[1]
    calls.push(action)
    if(action==='get-bucket-location')return {stdout:JSON.stringify({LocationConstraint:location})}
    if(action==='get-bucket-versioning')return {stdout:JSON.stringify(versioning(calls.length))}
    assert.equal(action,'list-object-versions')
    assert.ok(args.includes('--no-paginate'))
    assert.equal(args[args.indexOf('--encoding-type')+1],'url')
    assert.equal(args[args.indexOf('--prefix')+1],scope.prefix)
    const page={Name:scope.bucket,Prefix:encode(scope.prefix),EncodingType:'url',MaxKeys:1000}
    const following=args.includes('--key-marker='+key)
    if(following){
      assert.ok(args.includes('--version-id-marker='+markerVersion))
      Object.assign(page,{KeyMarker:encode(key),VersionIdMarker:markerVersion,IsTruncated:false,
        Versions:[version(key,'older-version',false),version(otherKey,'live-version',true)]})
    }else{
      pass++
      assert.ok(!args.some(value=>value.startsWith('--key-marker=')))
      Object.assign(page,{IsTruncated:true,NextKeyMarker:encode(key),NextVersionIdMarker:markerVersion,
        DeleteMarkers:[{Key:encode(key),VersionId:markerVersion,IsLatest:true,LastModified:timestamp}]})
    }
    return {stdout:JSON.stringify(change(page,pass,following))}
  }
  return {run,calls}
}

const capture=fixture=>captureS3RecoveryCopies({input:scope,approvedScope,settings,run:fixture.run,now:time})

test('observes a full repeatable version set and binds the protected manifest to independently recorded digests',async()=>{
  const provider=fixture()
  const captured=await capture(provider)
  assert.deepEqual(provider.calls,['get-bucket-location','get-bucket-versioning','list-object-versions','list-object-versions',
    'list-object-versions','list-object-versions','get-bucket-versioning'])
  assert.equal(captured.copies.length,3)
  assert.deepEqual(captured.copies.filter(copy=>copy.key===key).map(copy=>copy.kind),['delete_marker','object_version'])
  const raw=Buffer.from(JSON.stringify(captured)+'\n')
  const approvedInventory=sha(raw)
  const check=verifyS3RecoveryInventory(raw,{input:scope,approvedScope,approvedInventory})
  assert.equal(check.objectVersions,2)
  assert.equal(check.noncurrentVersions,1)
  assert.equal(check.deleteMarkers,1)
  assert.equal(check.backupErasure,'unverified')
  for(const privateValue of [scope.workspace,scope.bucket,scope.owner,scope.prefix,markerVersion,key,otherKey]) {
    assert.ok(!JSON.stringify(check).includes(privateValue))
  }
  const altered=Buffer.from(JSON.stringify({...captured,capturedAt:'2026-10-02T03:11:00.000Z'}))
  assert.throws(()=>verifyS3RecoveryInventory(altered,{input:scope,approvedScope,approvedInventory}),/independently recorded digest/)
  const malformed=Buffer.from(JSON.stringify({...captured,listingSha256:'0'.repeat(64)}))
  assert.throws(()=>verifyS3RecoveryInventory(malformed,{input:scope,approvedScope,approvedInventory:sha(malformed)}),/provenance/)
  assert.throws(()=>verifyS3RecoveryInventory(raw,{input:{...scope,version:5},approvedScope,approvedInventory}),/approved|independently/)
})

test('fails closed on ambiguous, incomplete or changing provider pages',async()=>{
  for(const [change,expected] of [
    [(page,pass,following)=>following&&pass===2?{...page,Versions:[version(otherKey,'live-version',true)]}:page,/changed between/],
    [(page,pass,following)=>following?{...page,IsTruncated:true,NextKeyMarker:encode(key),NextVersionIdMarker:markerVersion}:page,/repeated/],
    [(page,pass,following)=>following?{...page,Versions:[version(key,markerVersion,false)]}:page,/repeated/],
    [(page,pass,following)=>following?{...page,Versions:[version(key,'null',false)]}:page,/immutable version ID/],
    [(page,pass,following)=>following?{...page,Versions:[version('outside/object','other',true)]}:page,/outside its approved/],
    [(page,pass,following)=>following?{...page,KeyMarker:encode(otherKey)}:page,/different scope/],
    [(page,pass,following)=>following?{...page,Versions:[version(key,'duplicate-latest',true)]}:page,/single current/],
    [page=>({...page,CommonPrefixes:[{Prefix:'nested-directory/'}]}),/different scope/],
  ])await assert.rejects(capture(fixture(change)),expected)
  await assert.rejects(capture(fixture(undefined,()=>({Status:'Suspended'}))),/active versioning/)
  await assert.rejects(capture(fixture(undefined,call=>({Status:call===2?'Enabled':'Suspended'}))),/active versioning/)
  const wrongRegion=fixture(undefined,undefined,'us-east-2')
  await assert.rejects(capture(wrongRegion),/bucket region/)
  assert.deepEqual(wrongRegion.calls,['get-bucket-location'])
  await assert.rejects(captureS3RecoveryCopies({input:{...scope,owner:'222222222222'},approvedScope,settings,
    run:()=>assert.fail('Digest mismatch must prevent provider calls.')}),/scope digest/)
  await assert.rejects(capture({run:()=>{throw new Error('private provider error')}}),/denied or could not be completed/)
})

test('a separate CLI reviewer verifies the protected inventory offline with both trusted digests',async()=>{
  const directory=await mkdtemp(join(tmpdir(),'sectalk-s3-inventory-'))
  const inventory=join(directory,'inventory.json')
  const raw=Buffer.from(JSON.stringify(await capture(fixture()))+'\n')
  const command=fileURLToPath(new URL('../services/tenant-dek-aws/s3-recovery-copy-inventory.mjs',import.meta.url))
  const flags=Object.entries(scope).flatMap(([flag,value])=>['--'+flag,String(value)])
  const run=(mode,...args)=>spawnSync(process.execPath,[command,'--mode='+mode,...flags,...args],{
    encoding:'utf8',windowsHide:true,timeout:4000,
  })
  try{
    await writeFile(inventory,raw,{mode:0o600,flag:'wx'})
    const scoped=run('scope')
    assert.equal(scoped.status,0,scoped.stderr)
    assert.deepEqual(JSON.parse(scoped.stdout),{scopeSha256:approvedScope})
    const review=(inventoryDigest)=>run('verify','--scope-sha256',approvedScope,'--inventory',inventory,
      '--inventory-sha256',inventoryDigest)
    const receipt=review(sha(raw))
    assert.equal(receipt.status,0,receipt.stderr)
    assert.equal(JSON.parse(receipt.stdout).noncurrentVersions,1)
    const failure=review('0'.repeat(64))
    assert.equal(failure.status,1)
    assert.match(failure.stderr,/independently recorded digest/)
    assert.equal(failure.stdout,'')
  }finally{
    await unlink(inventory)
    await rmdir(directory)
  }
})
