import assert from 'node:assert/strict'
import {spawnSync} from 'node:child_process'
import {createHash} from 'node:crypto'
import {mkdtemp,rmdir,unlink,writeFile} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import {test} from 'node:test'
import {fileURLToPath} from 'node:url'
import {captureS3RecoveryCopies,recoveryScopeDigest} from '../services/tenant-dek-aws/s3-recovery-copy-inventory.mjs'
import {verifyRecoveryCoverage} from '../services/tenant-dek-aws/recovery-coverage.mjs'

const scope={workspace:'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',version:5,bucket:'scoping-test-recovery-primary',
  owner:'111111111111',region:'eu-central-1',prefix:'approved/source/'}
const replica={...scope,bucket:'scoping-test-recovery-replica',region:'eu-west-1',prefix:'approved/replica/'}
const baselineAt='2026-11-07T04:05:00Z'
const eventTime='2026-11-08T04:05:00Z'
const recordedAt='2026-11-08T06:00:00Z'
const verifiedAt='2026-11-09T04:05:00Z'
const observedAt='2026-11-10T04:05:00Z'
const digest=value=>createHash('sha256').update(value).digest('hex')
const json=value=>Buffer.from(JSON.stringify(value))
const template=['project-manifest.json','project.pgdump','private-inventory.jsonl','objects/storage-manifest.json']
const settings={AWS_CONTAINER_CREDENTIALS_RELATIVE_URI:'/v2/credentials/synthetic-only'}

function version(Key,VersionId,IsLatest=true){
  return {Key:encodeURIComponent(Key),VersionId,IsLatest,LastModified:baselineAt,Size:42,ETag:'"fixture"',StorageClass:'STANDARD'}
}

function marker(key,VersionId){
  return {Key:encodeURIComponent(key),VersionId,IsLatest:true,LastModified:observedAt}
}

async function inventory(scope,versions,markers,capturedAt){
  return json(await captureS3RecoveryCopies({input:scope,settings,approvedScope:recoveryScopeDigest(scope),
    now:()=>new Date(capturedAt),run:async(_cli,args)=>({stdout:JSON.stringify(
      args[1]==='get-bucket-location'?{LocationConstraint:scope.region}:args[1]==='get-bucket-versioning'?{Status:'Enabled'}:{
        Name:scope.bucket,EncodingType:'url',Prefix:encodeURIComponent(scope.prefix),MaxKeys:1000,IsTruncated:false,
        Versions:versions,DeleteMarkers:markers,
      },
    )}),
  }))
}

async function fixture({clear=false,stale=false,overlap=false,drift=false}={}){
  const generationPrefix=scope.prefix+'generation-one/'
  const selected=template.map((file,index)=>version(generationPrefix+file,'selected-version-'+index))
  const separate=version(scope.prefix+'unbound-artifact','unbound-version')
  const hidden=selected[1]
  const hiddenKey=decodeURIComponent(hidden.Key)
  const replicas=overlap?{...scope,prefix:scope.prefix+'nested/'}:replica
  const data=new Map()
  data.set('provider-key-evidence.json',json({format:'sectalk-provider-key-evidence-v1',workspace:scope.workspace,
    version:scope.version,eventTime,recordedAt,eventSha256:'1'.repeat(64),pinCommitment:'2'.repeat(64)}))
  const providerDigest=digest(data.get('provider-key-evidence.json'))
  data.set('primary-baseline.json',await inventory(scope,[...selected,separate],[],baselineAt))
  data.set('primary-observed.json',await inventory(scope,clear?[]:[{...hidden,IsLatest:false,
    ...(drift&&{ETag:'"changed-bytes"'})}], [marker(hiddenKey,'delete-marker')],stale?recordedAt:observedAt))
  data.set('replica-baseline.json',await inventory(replicas,[],[],baselineAt))
  data.set('replica-observed.json',await inventory(replicas,clear?[]:[version(replicas.prefix+'restored.pgdump','new-copy')],
    [],observedAt))
  const primary={id:'primary',scopeSha256:recoveryScopeDigest(scope),baselineInventorySha256:digest(data.get('primary-baseline.json')),
    observedInventorySha256:digest(data.get('primary-observed.json'))}
  const plan=json({format:'sectalk-s3-archive-version-plan-v1',scopeSha256:primary.scopeSha256,
    inventorySha256:primary.baselineInventorySha256,generationPrefix,
    versions:Object.fromEntries(template.map((file,index)=>[file,selected[index].VersionId]))})
  const planSha=digest(plan)
  const provenance=json({format:'sectalk-s3-recovery-copy-provenance-v1',checkedAt:verifiedAt,
    scopeSha256:primary.scopeSha256,inventorySha256:primary.baselineInventorySha256,providerReceiptSha256:providerDigest,
    reviewedProviderEventSha256:'1'.repeat(64),planSha256:planSha,matchedArtifactVersions:4})
  const provenanceSha=digest(provenance)
  data.set('plan-'+planSha+'.json',plan)
  data.set('provenance-'+provenanceSha+'.json',provenance)
  primary.archiveProvenance=[{receiptSha256:provenanceSha,planSha256:planSha}]
  const approved={format:'sectalk-s3-recovery-coverage-approval-v1',workspace:scope.workspace,keyVersion:scope.version,
    providerReceiptSha256:providerDigest,observationFrom:'2026-11-10T00:00:00Z',observationThrough:'2026-11-11T00:00:00Z',
    cohorts:[primary,{id:'replica',scopeSha256:recoveryScopeDigest(replicas),
      baselineInventorySha256:digest(data.get('replica-baseline.json')),
      observedInventorySha256:digest(data.get('replica-observed.json')),archiveProvenance:[]}]}
  return {data,approved}
}

function verify({data,approved}){
  const approvalRaw=json(approved)
  return verifyRecoveryCoverage({approvalRaw,approvalSha256:digest(approvalRaw),read:async filename=>{
    assert.ok(data.has(filename),'Missing approved fixture evidence')
    return data.get(filename)
  }})
}

test('finds retained historical versions and copies that appear in an independently approved replica',async()=>{
  const report=await verify(await fixture())
  assert.equal(report.status,'residual_versions_in_approved_observations')
  assert.equal(report.scopedObjectVersions,2)
  const [primary,secondary]=report.cohorts
  assert.deepEqual([primary.verifiedArchiveVersions,primary.baselineVersionsWithoutByteProvenance,primary.knownStillPresent,
    primary.knownNotListed,primary.newlyObserved,primary.noncurrentRemaining,primary.deleteMarkers],[4,1,1,4,0,1,1])
  assert.deepEqual([secondary.observedVersions,secondary.knownStillPresent,secondary.newlyObserved],[1,0,1])
  assert.equal(report.backupErasure,'unverified')
  for(const raw of [scope.workspace,scope.bucket,replica.bucket,scope.prefix,'selected-version','new-copy']){
    assert.ok(!JSON.stringify(report).includes(raw))
  }
})

test('empty approved observations distinguish missing object versions and lingering marker metadata',async()=>{
  const report=await verify(await fixture({clear:true}))
  assert.equal(report.status,'no_versions_in_approved_observations')
  assert.equal(report.scopedObjectVersions,0)
  assert.equal(report.cohorts[0].knownNotListed,5)
  assert.equal(report.cohorts[0].deleteMarkers,1)
  assert.equal(report.backupErasure,'unverified')
})

test('rejects incomplete, stale, overlapping and inconsistent evidence',async()=>{
  await assert.rejects(verify(await fixture({stale:true})),/stale or outside/)
  await assert.rejects(verify(await fixture({overlap:true})),/overlapping/)
  await assert.rejects(verify(await fixture({drift:true})),/changed immutable metadata/)
  const missing=await fixture()
  missing.data.delete('replica-observed.json')
  await assert.rejects(verify(missing),/Missing approved fixture/)
  const empty=await fixture()
  empty.approved.cohorts[0].archiveProvenance=[]
  await assert.rejects(verify(empty),/populated baseline needs matching/)
  const reused=await fixture()
  reused.approved.cohorts[0].archiveProvenance.push(reused.approved.cohorts[0].archiveProvenance[0])
  await assert.rejects(verify(reused),/already accounted/)
  const wrongEvent=await fixture()
  const item=wrongEvent.approved.cohorts[0].archiveProvenance[0]
  const changed=json({...JSON.parse(wrongEvent.data.get('provenance-'+item.receiptSha256+'.json')),
    reviewedProviderEventSha256:'3'.repeat(64)})
  item.receiptSha256=digest(changed)
  wrongEvent.data.set('provenance-'+item.receiptSha256+'.json',changed)
  await assert.rejects(verify(wrongEvent),/same provider event/)
})

test('offline CLI reads exact approved evidence files and emits a redacted receipt',async()=>{
  const {data,approved}=await fixture()
  data.set('coverage-approval.json',json(approved))
  const base=await mkdtemp(join(tmpdir(),'sectalk-recovery-coverage-'))
  const saved=[]
  try{
    for(const [name,bytes] of data){
      const file=join(base,name)
      await writeFile(file,bytes,{mode:0o600,flag:'wx'})
      saved.push(file)
    }
    const script=fileURLToPath(new URL('../services/tenant-dek-aws/recovery-coverage.mjs',import.meta.url))
    const result=spawnSync(process.execPath,[script,'--bundle',base,'--approval-sha256',digest(data.get('coverage-approval.json'))],
      {encoding:'utf8',windowsHide:true,timeout:5000})
    assert.equal(result.status,0,result.stderr)
    assert.equal(JSON.parse(result.stdout).scopedObjectVersions,2)
    assert.equal(result.stdout.includes(scope.bucket),false)
  }finally{
    for(const file of saved)await unlink(file)
    await rmdir(base)
  }
})
