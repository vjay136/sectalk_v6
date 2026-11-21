import {createHash} from 'node:crypto'
import {lstat,readFile,realpath} from 'node:fs/promises'
import {dirname,isAbsolute,join,relative,resolve,sep} from 'node:path'
import {fileURLToPath,pathToFileURL} from 'node:url'
import {parseArgs} from 'node:util'
import {verifyS3RecoveryInventory} from './s3-recovery-copy-inventory.mjs'

const shaPattern=/^[0-9a-f]{64}$/
const uuid=/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/
const idPattern=/^[a-z0-9][a-z0-9-]{0,39}$/
const files=['project-manifest.json','project.pgdump','private-inventory.jsonl','objects/storage-manifest.json']
const sha=value=>createHash('sha256').update(value).digest('hex')
const versionIdentity=row=>JSON.stringify([row.key,row.version])
const maximumCohorts=32
const inventoryLimit=128*1024*1024

function requireValue(condition,message){
  if(!condition)throw new Error(message)
}

function pinnedJson(raw,digest,label){
  requireValue(Buffer.isBuffer(raw)&&shaPattern.test(digest??'')&&sha(raw)===digest,
    `The ${label} differs from its independent digest.`)
  try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw))}
  catch{throw new Error(`The ${label} is unsupported.`)}
}

function moment(value){
  requireValue(typeof value==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(value)&&
    Number.isFinite(Date.parse(value)),'A coverage timestamp is invalid.')
  return Date.parse(value)
}

function verifiedInventory(raw,digest,scopeSha256,expectedKey){
  const inventory=pinnedJson(raw,digest,'cohort inventory')
  const scope=inventory?.scope
  requireValue(scope?.workspace===expectedKey.workspace&&scope.version===expectedKey.keyVersion,
    'A recovery inventory belongs to another workspace or key version.')
  const receipt=verifyS3RecoveryInventory(raw,{input:scope,approvedScope:scopeSha256,approvedInventory:digest})
  return {scope,receipt,copies:inventory.copies,capturedAt:moment(receipt.capturedAt)}
}

function comparison(baseline,observation){
  const before=new Map(baseline.copies.map(item=>[versionIdentity(item),item]))
  let knownStillPresent=0,newlyObserved=0,noncurrentRemaining=0
  for(const current of observation.copies){
    const prior=before.get(versionIdentity(current))
    requireValue(!prior||(current.kind===prior.kind&&current.modifiedAt===prior.modifiedAt&&
      current.size===prior.size&&current.etag===prior.etag),
    'The provider inventory changed immutable metadata for an existing object version.')
    if(current.kind==='delete_marker')continue
    if(prior)knownStillPresent++
    else newlyObserved++
    if(!current.latest)noncurrentRemaining++
  }
  return {knownStillPresent,knownNotListed:baseline.receipt.objectVersions-knownStillPresent,newlyObserved,noncurrentRemaining}
}

async function verifiedArchiveVersions({cohort,baseline,observation,provider,providerDigest,read}){
  const known=new Set()
  const available=new Map(baseline.copies.filter(row=>row.kind==='object_version').map(row=>[versionIdentity(row),row]))
  for(const item of cohort.archiveProvenance){
    const report=pinnedJson(await read('provenance-'+item.receiptSha256+'.json',16384),
      item.receiptSha256,'archive provenance receipt')
    const copiedAt=moment(report?.checkedAt)
    requireValue(report?.format==='sectalk-s3-recovery-copy-provenance-v1'&&report.scopeSha256===cohort.scopeSha256&&
      report.inventorySha256===cohort.baselineInventorySha256&&report.providerReceiptSha256===providerDigest&&
      report.reviewedProviderEventSha256===provider.eventSha256&&report.planSha256===item.planSha256&&
      report.matchedArtifactVersions===files.length&&copiedAt>=baseline.capturedAt&&copiedAt<=observation.capturedAt,
    'An archive provenance receipt does not cover the same provider event and baseline.')
    const copyPlan=pinnedJson(await read('plan-'+item.planSha256+'.json',16384),
      item.planSha256,'archive version plan')
    requireValue(copyPlan?.format==='sectalk-s3-archive-version-plan-v1'&&copyPlan.scopeSha256===cohort.scopeSha256&&
      copyPlan.inventorySha256===cohort.baselineInventorySha256&&typeof copyPlan.generationPrefix==='string'&&
      copyPlan.generationPrefix.startsWith(baseline.scope.prefix)&&copyPlan.generationPrefix.length<=512&&
      /^(?:[A-Za-z0-9][A-Za-z0-9._=-]*\/)+$/.test(copyPlan.generationPrefix)&&
      copyPlan.versions&&Object.keys(copyPlan.versions).length===files.length,
    'An archive version plan does not cover the same scoped baseline.')
    for(const file of files){
      const key=copyPlan.generationPrefix+file
      const version=Object.hasOwn(copyPlan.versions,file)?copyPlan.versions[file]:null
      const identity=versionIdentity({key,version})
      requireValue(available.has(identity)&&!known.has(identity),
        'An archive version plan selected a missing or already accounted for baseline copy.')
      known.add(identity)
    }
  }
  return known.size
}

export async function verifyRecoveryCoverage({approvalRaw,approvalSha256,read}){
  const approved=pinnedJson(approvalRaw,approvalSha256,'coverage approval')
  requireValue(approved?.format==='sectalk-s3-recovery-coverage-approval-v1'&&uuid.test(approved.workspace??'')&&
    Number.isSafeInteger(approved.keyVersion)&&approved.keyVersion>0&&approved.keyVersion<=2147483647&&
    shaPattern.test(approved.providerReceiptSha256??'')&&Array.isArray(approved.cohorts)&&
    approved.cohorts.length>0&&approved.cohorts.length<=maximumCohorts,
  'The independent coverage approval is incomplete or unsupported.')
  const from=moment(approved.observationFrom),through=moment(approved.observationThrough)
  requireValue(from<=through,'The approved observation window is invalid.')
  const provider=pinnedJson(await read('provider-key-evidence.json',8192),approved.providerReceiptSha256,'provider receipt')
  requireValue(provider?.format==='sectalk-provider-key-evidence-v1'&&provider.workspace===approved.workspace&&
    provider.version===approved.keyVersion&&shaPattern.test(provider.eventSha256??'')&&shaPattern.test(provider.pinCommitment??''),
  'The independent provider receipt belongs to another workspace or key version.')
  const event=moment(provider.eventTime),recorded=moment(provider.recordedAt)
  requireValue(event<=recorded+30000&&through>=Math.max(event,recorded),
    'The approved observation window does not cover a valid reviewed provider event.')

  const ids=new Set(),scopes=[],cohorts=[]
  for(const cohort of approved.cohorts){
    requireValue(typeof cohort?.id==='string'&&idPattern.test(cohort.id)&&!ids.has(cohort.id)&&shaPattern.test(cohort.scopeSha256??'')&&
      shaPattern.test(cohort.baselineInventorySha256??'')&&shaPattern.test(cohort.observedInventorySha256??'')&&
      cohort.baselineInventorySha256!==cohort.observedInventorySha256&&Array.isArray(cohort.archiveProvenance)&&
      cohort.archiveProvenance.length<=500&&cohort.archiveProvenance.every(item=>
        shaPattern.test(item?.receiptSha256??'')&&shaPattern.test(item?.planSha256??'')),
    'The coverage approval contains a duplicated or unverified cohort.')
    ids.add(cohort.id)
    const baseline=verifiedInventory(await read(cohort.id+'-baseline.json',inventoryLimit),
      cohort.baselineInventorySha256,cohort.scopeSha256,approved)
    requireValue(!scopes.some(scope=>scope.bucket===baseline.scope.bucket&&
      (scope.owner!==baseline.scope.owner||scope.region!==baseline.scope.region||
        scope.prefix.startsWith(baseline.scope.prefix)||baseline.scope.prefix.startsWith(scope.prefix))),
    'The approved coverage contains overlapping or inconsistent bucket scopes.')
    scopes.push(baseline.scope)
    const observation=verifiedInventory(await read(cohort.id+'-observed.json',inventoryLimit),
      cohort.observedInventorySha256,cohort.scopeSha256,approved)
    requireValue(observation.capturedAt>baseline.capturedAt&&observation.capturedAt>=Math.max(from,event,recorded)&&
      observation.capturedAt<=through,'A cohort inventory is stale or outside the approved review window.')
    requireValue((baseline.receipt.objectVersions>0)===(cohort.archiveProvenance.length>0),
      'A populated baseline needs matching archive provenance, and an empty baseline cannot claim it.')
    const verifiedArchiveVersionsCount=await verifiedArchiveVersions({
      cohort,baseline,observation,provider,providerDigest:approved.providerReceiptSha256,read,
    })
    cohorts.push({scopeSha256:cohort.scopeSha256,baselineInventorySha256:cohort.baselineInventorySha256,
      observedInventorySha256:cohort.observedInventorySha256,verifiedArchiveVersions:verifiedArchiveVersionsCount,
      baselineVersionsWithoutByteProvenance:baseline.receipt.objectVersions-verifiedArchiveVersionsCount,
      observedVersions:observation.receipt.objectVersions,deleteMarkers:observation.receipt.deleteMarkers,
      ...comparison(baseline,observation)})
  }
  const retained=cohorts.reduce((total,cohort)=>total+cohort.observedVersions,0)
  return {format:'sectalk-s3-recovery-coverage-v1',approvalSha256,providerReceiptSha256:approved.providerReceiptSha256,
    reviewedProviderEventSha256:provider.eventSha256,observationFrom:approved.observationFrom,observationThrough:approved.observationThrough,
    status:retained?'residual_versions_in_approved_observations':'no_versions_in_approved_observations',
    scopedObjectVersions:retained,cohorts,backupErasure:'unverified'}
}

async function openEvidenceBundle(value){
  const path=await realpath(value)
  const installed=await realpath(dirname(fileURLToPath(import.meta.url)))
  const checkout=resolve(installed,'../..')
  const repo=await lstat(join(checkout,'package.json')).catch(error=>{
    if(error?.code!=='ENOENT')throw error
    return null
  })
  const outside=relative(repo?.isFile()?checkout:installed,path)
  requireValue(isAbsolute(outside)||outside==='..'||outside.startsWith('..'+sep),
    'Use a restricted coverage bundle outside the source checkout.')
  return async (name,maximum)=>{
    const file=join(path,name)
    const info=await lstat(file)
    requireValue(info.isFile()&&info.size<=maximum&&await realpath(file)===file,
      'Use bounded regular files for the approved coverage bundle.')
    const bytes=await readFile(file)
    requireValue(bytes.length<=maximum,'An approved coverage input exceeds its size limit.')
    return bytes
  }
}

if(process.argv[1]&&pathToFileURL(process.argv[1]).href===import.meta.url){
  try{
    let values
    try{({values}=parseArgs({options:{bundle:{type:'string'},'approval-sha256':{type:'string'}}}))}
    catch{throw new Error('Invalid backup coverage options.')}
    requireValue(values.bundle&&shaPattern.test(values['approval-sha256']??''),
      'Choose the protected coverage bundle and independently recorded approval digest.')
    const read=await openEvidenceBundle(values.bundle)
    console.log(JSON.stringify(await verifyRecoveryCoverage({
      approvalRaw:await read('coverage-approval.json',256*1024),approvalSha256:values['approval-sha256'],read,
    })))
  }catch(error){
    console.error(error?.code?'The approved recovery coverage inputs could not be read.':error.message)
    process.exitCode=1
  }
}
