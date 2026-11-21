import assert from 'node:assert/strict'
import {spawn} from 'node:child_process'
import {createHash} from 'node:crypto'
import {test} from 'node:test'
import {captureS3RecoveryCopies,recoveryScopeDigest} from '../services/tenant-dek-aws/s3-recovery-copy-inventory.mjs'
import {prepareRecoveryCopy,verifyRecoveryCopy} from '../services/tenant-dek-aws/recovery-copy-provenance.mjs'

const scope={workspace:'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',version:2,bucket:'synthetic-backups',
  owner:'111111111111',region:'eu-west-1',prefix:'archives/workspaces/'}
const generationPrefix=scope.prefix+'fixture-generation/'
const when='2026-11-11T00:00:00.000Z'
const providerAt='2026-11-12T00:00:00+00:00'
const scopeSha256=recoveryScopeDigest(scope)
const sha=value=>createHash('sha256').update(value).digest('hex')
const json=value=>Buffer.from(JSON.stringify(value))
const settings={AWS_CONTAINER_CREDENTIALS_RELATIVE_URI:'/v2/credentials/test-only',AWS_ENDPOINT_URL:'https://fake.example.invalid'}
const artifactBytes={
  'project.pgdump':Buffer.from('Synthetic exact archived database bytes\0for fixture'),
  'private-inventory.jsonl':Buffer.from('Synthetic exact private inventory'),
  'objects/storage-manifest.json':Buffer.from('Synthetic exact object catalog'),
}
artifactBytes['project-manifest.json']=json({version:1,capturedAt:when,
  files:Object.fromEntries(Object.entries(artifactBytes).map(([name,data])=>[name,sha(data)]))})
const artifacts=Object.entries(artifactBytes).map(([name,bytes],index)=>({
  name,bytes,key:generationPrefix+name,version:'opaque/+version-'+index,etag:'"synthetic-version-'+index+'"',
}))

async function inputs(){
  const inventoryRaw=json(await captureS3RecoveryCopies({input:scope,approvedScope:scopeSha256,settings,now:()=>new Date(when),
    run:async(_cli,args)=>({stdout:JSON.stringify(args[1]==='get-bucket-location'?{LocationConstraint:scope.region}
      :args[1]==='get-bucket-versioning'?{Status:'Enabled'}:{
        Name:scope.bucket,Prefix:encodeURIComponent(scope.prefix),EncodingType:'url',MaxKeys:1000,IsTruncated:false,
        Versions:artifacts.map(copy=>({Key:encodeURIComponent(copy.key),VersionId:copy.version,LastModified:when,
          IsLatest:copy.name!=='project.pgdump',Size:copy.bytes.length,ETag:copy.etag,StorageClass:'STANDARD'})),
        DeleteMarkers:[{Key:encodeURIComponent(generationPrefix+'project.pgdump'),VersionId:'retained-delete-marker',
          LastModified:when,IsLatest:true}],
      })}),
  }))
  const planRaw=json({format:'sectalk-s3-archive-version-plan-v1',scopeSha256,inventorySha256:sha(inventoryRaw),
    generationPrefix,versions:Object.fromEntries(artifacts.map(copy=>[copy.name,copy.version]))})
  const manifestRaw=artifactBytes['project-manifest.json']
  const providerRaw=json({format:'sectalk-provider-key-evidence-v1',workspace:scope.workspace,version:scope.version,
    eventSha256:'e'.repeat(64),eventTime:providerAt,recordedAt:providerAt,pinCommitment:'f'.repeat(64)})
  const archiveRaw=json({format:'sectalk-backup-key-evidence-v1',workspace:scope.workspace,capturedAt:when,
    manifestSha256:sha(manifestRaw),postgresSha256:sha(artifactBytes['project.pgdump']),
    exactKey:{version:scope.version,record:'external_reference',providerPinMatch:true},
    providerEvidence:{receiptSha256:sha(providerRaw),eventSha256:'e'.repeat(64),eventTime:providerAt,
      record:'independent_provider_receipt',archiveBinding:'matches'}})
  return approve({inventoryRaw,planRaw,manifestRaw,providerRaw,archiveRaw})
}

function approve(bundle){
  const approvalRaw=json({format:'sectalk-s3-archive-copy-approval-v1',scopeSha256,
    inventorySha256:sha(bundle.inventoryRaw),planSha256:sha(bundle.planRaw),projectManifestSha256:sha(bundle.manifestRaw),
    archiveFindingSha256:sha(bundle.archiveRaw),providerReceiptSha256:sha(bundle.providerRaw)})
  return {...bundle,approvalRaw,approvalSha256:sha(approvalRaw)}
}

test('binds the approved S3 inventory, archive keys and independent provider event without trusting names alone',async()=>{
  const bundle=await inputs()
  const prepared=prepareRecoveryCopy(bundle)
  assert.equal(prepared.selections.length,4)
  assert.equal(prepared.otherInventoryRecords,1)
  assert.equal(prepared.selections.find(copy=>copy.name==='project.pgdump').latest,false)
  assert.throws(()=>prepareRecoveryCopy({...bundle,archiveRaw:json({}),approvalSha256:bundle.approvalSha256}),
    /archived key finding differs/)
  const wrongPin={...JSON.parse(bundle.archiveRaw),exactKey:{version:scope.version,record:'external_reference',providerPinMatch:false}}
  assert.throws(()=>prepareRecoveryCopy(approve({...bundle,archiveRaw:json(wrongPin)})),/does not bind/)
  const wrongEvent={...JSON.parse(bundle.providerRaw),version:3}
  assert.throws(()=>prepareRecoveryCopy(approve({...bundle,providerRaw:json(wrongEvent)})),/wrong scope or event/)
  const plan=JSON.parse(bundle.planRaw)
  plan.versions['project.pgdump']='retained-delete-marker'
  assert.throws(()=>prepareRecoveryCopy(approve({...bundle,planRaw:json(plan)})),/absent from the approved inventory/)
})

test('Linux streams only approved explicit versions, checks bytes and metadata and fails on provider errors',
  {skip:process.platform!=='linux'},async()=>{
    const prepared=prepareRecoveryCopy(await inputs())
    let mode='clean'
    const calls=[]
    const launch=(bin,args,options)=>{
      assert.equal(bin,'/bin/bash')
      assert.deepEqual(args.slice(0,3),['-o','pipefail','-c'])
      assert.deepEqual(args.slice(6,8),['s3api','get-object'])
      assert.equal(args[args.indexOf('--expected-bucket-owner')+1],scope.owner)
      assert.equal(args[args.indexOf('--region')+1],scope.region)
      assert.equal(options.env.AWS_ENDPOINT_URL,undefined)
      const copy=artifacts.find(copy=>args.includes('--key='+copy.key))
      assert.ok(copy&&args.includes('--version-id='+copy.version))
      calls.push(copy.name)
      const bytes=Buffer.from(copy.bytes)
      if(mode==='bytes')bytes[0]^=1
      const reply={VersionId:mode==='version'?'unexpected':copy.version,ContentLength:bytes.length,
        ETag:copy.etag,LastModified:when,DeleteMarker:mode==='marker'}
      return spawn(bin,[...args.slice(0,5),process.execPath,'-e',`
        const fs=require('node:fs');
        fs.writeFileSync(process.argv[4],Buffer.from(process.argv[1],'base64'));
        process.stdout.write(process.argv[2]);
        process.exitCode=Number(process.argv[3]);
      `,bytes.toString('base64'),JSON.stringify(reply),mode==='failed'?'41':'0'],options)
    }
    const verify=confirmDownloads=>verifyRecoveryCopy({prepared,settings,confirmDownloads,launch})
    await assert.rejects(verify(false),/confirm|Confirm/)
    assert.equal(calls.length,0)
    const report=await verify(true)
    assert.equal(report.matchedArtifactVersions,4)
    assert.equal(report.backupErasure,'unverified')
    for(const value of [scope.workspace,scope.bucket,generationPrefix,...artifacts.map(item=>item.version)]) {
      assert.ok(!JSON.stringify(report).includes(value))
    }
    for(const negative of ['bytes','version','marker','failed']){
      mode=negative
      await assert.rejects(verify(true),/no longer matches|could not be streamed/)
    }
  })
