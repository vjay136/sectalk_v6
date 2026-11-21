import {createHash} from 'node:crypto'
import {lstat,readFile,realpath} from 'node:fs/promises'
import {isAbsolute,join,relative,sep} from 'node:path'
import {fileURLToPath,pathToFileURL} from 'node:url'
import {parseArgs} from 'node:util'
import {verifySupabaseBackupObservation} from './supabase-backup-observation.mjs'

const digest=/^[a-f0-9]{64}$/
const sha=value=>createHash('sha256').update(value).digest('hex')
const observedCatalog=new Set(['empty_reported_list','entries_reported'])
const comparableTimeFields=['reviewFrom','reviewThrough']
const comparableScopeFields=['sourceProject','testProject','region','workspace','keyVersion']

function requireValue(condition,message){
  if(!condition)throw new Error(message)
}

function object(raw,name){
  let parsed
  try{parsed=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw))}
  catch{throw new Error(`The ${name} is invalid JSON.`)}
  requireValue(parsed&&typeof parsed==='object'&&!Array.isArray(parsed),`The ${name} must be a JSON object.`)
  return parsed
}

function pinned(raw,expected,name){
  requireValue(Buffer.isBuffer(raw)&&digest.test(expected??'')&&sha(raw)===expected,`The ${name} differs from its independent digest.`)
  return object(raw,name)
}

function moment(value){
  requireValue(typeof value==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|[+-]\d\d:\d\d)$/.test(value)&&
    Number.isFinite(Date.parse(value)),'A provider evidence timestamp is invalid.')
  return Date.parse(value)
}

function verifySnapshot(approvalRaw,approvalSha256,captureRaw,captureSha256){
  const report=verifySupabaseBackupObservation({approvalRaw,approvalSha256,captureRaw,captureSha256})
  return {report,approval:object(approvalRaw,'observation approval'),captureRaw}
}

function compareCatalog(baseline,later){
  const baselineState=baseline.report.catalog.state,laterState=later.report.catalog.state
  if(!observedCatalog.has(baselineState)||!observedCatalog.has(laterState)){
    return {state:'comparison_unknown',baselineState,laterState}
  }
  const records=raw=>object(Buffer.from(object(raw,'backup capture').body,'base64'),'captured backup response').backups
  const original=new Map(records(baseline.captureRaw).map(item=>[item.id,item]))
  const current=records(later.captureRaw)
  let stillListed=0,firstListed=0,changedStatus=0,changedToRemoved=0
  for(const item of current){
    const before=original.get(item.id)
    if(!before){firstListed++;continue}
    requireValue(item.is_physical_backup===before.is_physical_backup&&Date.parse(item.inserted_at)===Date.parse(before.inserted_at),
      'A repeated backup identifier changed its observed creation time or backup kind.')
    stillListed++
    if(item.status!==before.status){
      changedStatus++
      if(item.status==='REMOVED')changedToRemoved++
    }
  }
  const statuses=later.report.catalog.statusCounts
  return {state:'reported_catalogs_compared',baselineState,laterState,stillListed,firstListed,
    notListedLater:original.size-stillListed,changedStatus,changedToRemoved,
    laterRemovedStatus:statuses.removed,laterCompletedOrArchivedStatus:statuses.completed+statuses.archived,
    baselineUnknownStatus:baseline.report.catalog.unknownStatus,laterUnknownStatus:later.report.catalog.unknownStatus}
}

function compareBounds(baseline,later){
  const earlier=baseline.report.physicalBounds,newer=later.report.physicalBounds
  const report={baselineState:earlier.state,laterState:newer.state,
    baselineReviewRelation:earlier.reviewRelation,laterReviewRelation:newer.reviewRelation,
    baselinePitr:baseline.report.pitr,laterPitr:later.report.pitr}
  if(earlier.state!=='both_reported'||newer.state!=='both_reported')return {state:'comparison_unknown',...report}
  const direction=(before,after)=>Date.parse(after)===Date.parse(before)?'unchanged':
    Date.parse(after)>Date.parse(before)?'moved_later':'moved_earlier'
  return {state:'reported_bounds_compared',...report,earliestMovement:direction(earlier.earliest,newer.earliest),
    latestMovement:direction(earlier.latest,newer.latest)}
}

export function verifySupabaseBackupTimeline({comparisonRaw,comparisonSha256,baselineApproval,baselineInventory,laterApproval,
  laterInventory,providerReceipt}){
  const comparison=pinned(comparisonRaw,comparisonSha256,'timeline approval')
  requireValue(comparison.format==='sectalk-supabase-backup-timeline-approval-v1'&&
    comparison.baselineApprovalSha256!==comparison.laterApprovalSha256&&
    comparison.baselineInventorySha256!==comparison.laterInventorySha256,
  'Use separately approved baseline and later Supabase observations.')
  const baseline=verifySnapshot(baselineApproval,comparison.baselineApprovalSha256,baselineInventory,comparison.baselineInventorySha256)
  const later=verifySnapshot(laterApproval,comparison.laterApprovalSha256,laterInventory,comparison.laterInventorySha256)
  requireValue(comparableScopeFields.every(field=>baseline.approval[field]===later.approval[field])&&
    comparableTimeFields.every(field=>moment(baseline.approval[field])===moment(later.approval[field]))&&
    moment(baseline.approval.observeThrough)<moment(later.approval.observeFrom),
  'The observations must use the same exact test scope and disjoint approved observation windows.')
  const provider=pinned(providerReceipt,comparison.providerReceiptSha256,'provider key receipt')
  requireValue(provider.format==='sectalk-provider-key-evidence-v1'&&provider.workspace===baseline.approval.workspace&&
    provider.version===baseline.approval.keyVersion&&digest.test(provider.eventSha256??'')&&digest.test(provider.pinCommitment??''),
  'The independent provider receipt has a different workspace or key version.')
  const event=moment(provider.eventTime),recorded=moment(provider.recordedAt)
  requireValue(event<=recorded+30000&&moment(baseline.report.observedAt)<event&&
    moment(later.report.observedAt)>=Math.max(event,recorded),
  'Observations must bracket the reviewed provider event and later receipt.')
  return {format:'sectalk-supabase-backup-timeline-v1',comparisonSha256,providerReceiptSha256:comparison.providerReceiptSha256,
    reviewedProviderEventSha256:provider.eventSha256,baselineInventorySha256:comparison.baselineInventorySha256,
    laterInventorySha256:comparison.laterInventorySha256,baselineObservedAt:baseline.report.observedAt,
    laterObservedAt:later.report.observedAt,scope:'approved_test_project',catalog:compareCatalog(baseline,later),
    physicalBounds:compareBounds(baseline,later),restoreAvailability:'unverified',providerDeletion:'unverified',backupErasure:'unverified'}
}

async function readBundle(bundle){
  const root=await realpath(bundle)
  const repository=await realpath(fileURLToPath(new URL('../',import.meta.url)))
  const outside=relative(repository,root)
  requireValue(isAbsolute(outside)||outside==='..'||outside.startsWith('..'+sep),
    'Keep the backup comparison bundle outside the source checkout.')
  const report={}
  for(const [input,file,limit] of [
    ['comparisonRaw','timeline-approval.json',8192],['providerReceipt','provider-key-evidence.json',8192],
    ['baselineApproval','baseline-approval.json',8192],['laterApproval','later-approval.json',8192],
    ['baselineInventory','baseline-inventory.json',3*1024*1024],['laterInventory','later-inventory.json',3*1024*1024],
  ]){
    const path=join(root,file)
    const info=await lstat(path)
    requireValue(info.isFile()&&info.size<=limit&&await realpath(path)===path,'Use bounded regular backup evidence files.')
    report[input]=await readFile(path)
    requireValue(report[input].length<=limit,'A backup evidence file exceeded its supported size.')
  }
  return report
}

if(process.argv[1]&&pathToFileURL(process.argv[1]).href===import.meta.url){
  try{
    let values
    try{({values}=parseArgs({options:{bundle:{type:'string'},'approval-sha256':{type:'string'}}}))}
    catch{throw new Error('Invalid backup timeline options.')}
    requireValue(values.bundle&&digest.test(values['approval-sha256']??''),
      'Provide the protected bundle and independently recorded timeline approval digest.')
    console.log(JSON.stringify(verifySupabaseBackupTimeline({
      ...await readBundle(values.bundle),comparisonSha256:values['approval-sha256'],
    })))
  }catch(error){
    console.error(error?.code?'The protected backup timeline evidence could not be read.':error.message)
    process.exitCode=1
  }
}
