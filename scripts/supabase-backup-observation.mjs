import {createHash} from 'node:crypto'
import {lstat,readFile,realpath,writeFile} from 'node:fs/promises'
import {basename,dirname,isAbsolute,join,relative,resolve,sep} from 'node:path'
import {fileURLToPath,pathToFileURL} from 'node:url'
import {parseArgs} from 'node:util'

const shaPattern=/^[a-f0-9]{64}$/
const uuid=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/
const projectRef=/^[a-z]{20}$/
const states=['COMPLETED','FAILED','PENDING','REMOVED','ARCHIVED','CANCELLED']
const providerLimit=2*1024*1024
const captureLimit=3*1024*1024
const format='sectalk-supabase-backup-observation-v1'
const hash=value=>createHash('sha256').update(value).digest('hex')

function requireValue(condition,message){
  if(!condition)throw new Error(message)
}

function timestamp(value){
  if(typeof value!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|[+-]\d\d:\d\d)$/.test(value))return null
  const instant=Date.parse(value)
  return Number.isFinite(instant)?instant:null
}

function jsonObject(raw,label){
  let result
  try {result=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw))}
  catch{throw new Error(`The ${label} is invalid JSON.`)}
  requireValue(result&&typeof result==='object'&&!Array.isArray(result),`The ${label} must be a JSON object.`)
  return result
}

function approvedScope(raw,digest){
  requireValue(Buffer.isBuffer(raw)&&raw.length<=8192&&shaPattern.test(digest??'')&&hash(raw)===digest,
    'The approval does not match its independently recorded digest.')
  const approval=jsonObject(raw,'approved project scope')
  const {sourceProject,testProject,region,workspace,keyVersion}=approval
  const reviewFrom=timestamp(approval.reviewFrom),reviewThrough=timestamp(approval.reviewThrough)
  const observeFrom=timestamp(approval.observeFrom),observeThrough=timestamp(approval.observeThrough)
  requireValue(approval.format==='sectalk-supabase-backup-approval-v1'&&typeof sourceProject==='string'&&
    projectRef.test(sourceProject)&&typeof testProject==='string'&&projectRef.test(testProject)&&sourceProject!==testProject&&
    typeof region==='string'&&/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/.test(region)&&typeof workspace==='string'&&uuid.test(workspace)&&
    Number.isSafeInteger(keyVersion)&&keyVersion>0&&keyVersion<=2147483647&&
    [reviewFrom,reviewThrough,observeFrom,observeThrough].every(value=>value!==null)&&
    reviewFrom<=reviewThrough&&reviewThrough<=observeFrom&&observeFrom<=observeThrough,
  'Approve a distinct test project, expected region, exact workspace key and valid review and observation intervals.')
  return {testProject,region,reviewFrom,reviewThrough,observeFrom,observeThrough}
}

async function responseBody(response){
  const type=response.headers.get('content-type')??''
  if(response.status!==200||response.redirected||!response.body||!/^application\/json(?:\s*;|$)/i.test(type)){
    await response.body?.cancel().catch(()=>undefined)
    throw new Error('Supabase did not return an authorized backup observation.')
  }
  const reader=response.body.getReader()
  try{
    const chunks=[]
    let size=0
    for(;;){
      const {done,value}=await reader.read()
      if(done)return Buffer.concat(chunks,size)
      size+=value.byteLength
      if(size>providerLimit){
        await reader.cancel()
        throw new Error('The Supabase backup observation exceeded its supported size.')
      }
      chunks.push(value)
    }
  }finally{reader.releaseLock()}
}

export async function captureSupabaseBackups({approvalRaw,approvalSha256,token,captureConfirmed,fetcher=fetch,now=()=>new Date()}){
  const scope=approvedScope(approvalRaw,approvalSha256)
  requireValue(captureConfirmed===true&&typeof token==='string'&&/^[A-Za-z0-9_.~-]{16,512}$/.test(token),
    'Confirm the read-only observation and provide its scoped Supabase Management API token.')
  const started=now().getTime()
  requireValue(started>=scope.observeFrom&&started<=scope.observeThrough,'The approved observation interval is closed.')
  let response
  try{
    response=await fetcher('https://api.supabase.com/v1/projects/'+scope.testProject+'/database/backups',{
      method:'GET',redirect:'error',cache:'no-store',signal:AbortSignal.timeout(15000),
      headers:{Authorization:'Bearer '+token,Accept:'application/json'},
    })
  }catch{throw new Error('The approved Supabase backup endpoint was unavailable.')}
  const raw=await responseBody(response)
  const end=now().getTime()
  requireValue(end>=started&&end<=scope.observeThrough,'The backup observation finished outside the approved interval.')
  const provider=jsonObject(raw,'Supabase backup response')
  requireValue(provider.region===scope.region,'Supabase did not confirm the approved test project region.')
  return Buffer.from(JSON.stringify({format,approvalSha256,projectRef:scope.testProject,observedAt:new Date(end).toISOString(),
    continuationIndicated:/\brel\s*=\s*["']?next\b/i.test(response.headers.get('link')??''),
    responseSha256:hash(raw),body:raw.toString('base64')})+'\n')
}

function catalog(provider,scope,at,continuationIndicated){
  if(continuationIndicated||provider.has_more===true||provider.truncated===true||provider.next_page_token||provider.next_cursor) {
    return {state:'possibly_incomplete',entries:null,inReviewInterval:null}
  }
  if(!Array.isArray(provider.backups)||provider.backups.length>10000)return {state:'unknown',entries:null,inReviewInterval:null}
  const seen=new Set()
  const counts=Object.fromEntries(states.map(status=>[status.toLowerCase(),0]))
  let unknownStatus=0,physical=0,inReviewInterval=0
  for(const entry of provider.backups){
    const inserted=timestamp(entry?.inserted_at)
    if(!Number.isSafeInteger(entry?.id)||seen.has(entry.id)||typeof entry.is_physical_backup!=='boolean'||
      typeof entry.status!=='string'||inserted===null||inserted>at+30000){
      return {state:'unknown',entries:null,inReviewInterval:null}
    }
    seen.add(entry.id)
    if(states.includes(entry.status))counts[entry.status.toLowerCase()]++
    else unknownStatus++
    physical+=Number(entry.is_physical_backup)
    inReviewInterval+=Number(inserted>=scope.reviewFrom&&inserted<=scope.reviewThrough)
  }
  return {state:provider.backups.length?'entries_reported':'empty_reported_list',entries:provider.backups.length,
    inReviewInterval,physical,logical:provider.backups.length-physical,statusCounts:counts,unknownStatus}
}

function physicalBounds(provider,scope,at){
  const raw=provider.physical_backup_data
  const unknown=state=>({state,earliest:null,latest:null,reviewRelation:'unknown'})
  if(raw===undefined||raw===null)return unknown('omitted')
  if(typeof raw!=='object'||Array.isArray(raw))return unknown('inconsistent')
  const lower=raw.earliest_physical_backup_date_unix,upper=raw.latest_physical_backup_date_unix
  const reported=value=>value!==undefined&&value!==null
  const valid=value=>Number.isSafeInteger(value)&&value>0&&value*1000<=at+30000
  if((reported(lower)&&!valid(lower))||(reported(upper)&&!valid(upper)))return unknown('inconsistent')
  const low=reported(lower)?lower*1000:null,high=reported(upper)?upper*1000:null
  const earliest=low===null?null:new Date(low).toISOString()
  const latest=high===null?null:new Date(high).toISOString()
  if(low===null&&high===null)return unknown('omitted')
  if(low===null||high===null)return {...unknown('partially_reported'),earliest,latest}
  if(low>high)return unknown('inconsistent')
  const reviewRelation=high<scope.reviewFrom||low>scope.reviewThrough?'no_intersection':
    low<=scope.reviewFrom&&high>=scope.reviewThrough?'bounds_span_interval':'bounds_intersect_interval'
  return {state:'both_reported',earliest,latest,reviewRelation}
}

export function verifySupabaseBackupObservation({approvalRaw,approvalSha256,captureRaw,captureSha256}){
  const scope=approvedScope(approvalRaw,approvalSha256)
  requireValue(Buffer.isBuffer(captureRaw)&&captureRaw.length<=captureLimit&&shaPattern.test(captureSha256??'')&&
    hash(captureRaw)===captureSha256,'The backup observation does not match its independently recorded digest.')
  const capture=jsonObject(captureRaw,'captured backup observation')
  const at=timestamp(capture.observedAt)
  requireValue(capture.format===format&&capture.approvalSha256===approvalSha256&&capture.projectRef===scope.testProject&&
    at!==null&&at>=scope.observeFrom&&at<=scope.observeThrough&&typeof capture.body==='string'&&
    typeof capture.continuationIndicated==='boolean'&&shaPattern.test(capture.responseSha256??''),
  'The backup observation has a different project scope or freshness window.')
  const body=Buffer.from(capture.body,'base64')
  requireValue(body.length<=providerLimit&&body.toString('base64')===capture.body&&hash(body)===capture.responseSha256,
    'The saved Supabase response differs from the captured bytes.')
  const provider=jsonObject(body,'saved Supabase response')
  requireValue(provider.region===scope.region,'The observed region differs from the approved region.')
  const bounds=physicalBounds(provider,scope,at)
  const pitr=typeof provider.pitr_enabled!=='boolean'?'unknown':provider.pitr_enabled?
    (bounds.state==='both_reported'?'enabled_with_reported_bounds':'enabled_bounds_unconfirmed'):'reported_disabled'
  return {format:'sectalk-supabase-backup-evidence-v1',approvalSha256,captureSha256,responseSha256:capture.responseSha256,
    observedAt:new Date(at).toISOString(),scope:'approved_test_project',catalog:catalog(provider,scope,at,capture.continuationIndicated),
    pitr,walG:typeof provider.walg_enabled==='boolean'?(provider.walg_enabled?'reported_enabled':'reported_disabled'):'unknown',
    physicalBounds:bounds,restoreAvailability:'unverified',providerDeletion:'unverified',backupErasure:'unverified'}
}

async function readProtected(path,maximum){
  const info=await lstat(path)
  requireValue(info.isFile()&&info.size<=maximum&&await realpath(path)===path,'Use bounded regular evidence files.')
  const value=await readFile(path)
  requireValue(value.length<=maximum,'A protected backup observation input exceeds its supported size.')
  return value
}

async function protectedPath(value){
  requireValue(typeof value==='string'&&value.length>0,'Choose an evidence path in restricted storage outside the checkout.')
  const absolute=resolve(value)
  const path=join(await realpath(dirname(absolute)),basename(absolute))
  const checkout=await realpath(fileURLToPath(new URL('../',import.meta.url)))
  const outside=relative(checkout,path)
  requireValue(isAbsolute(outside)||outside==='..'||outside.startsWith('..'+sep),
    'Choose an evidence path in restricted storage outside the checkout.')
  return path
}

if(process.argv[1]&&pathToFileURL(process.argv[1]).href===import.meta.url){
  try{
    let values
    try{
      ({values}=parseArgs({options:{approval:{type:'string'},'approval-sha256':{type:'string'},inventory:{type:'string'},
        'inventory-sha256':{type:'string'},'capture-confirmed-test-project':{type:'boolean'}}}))
    }catch{throw new Error('Invalid backup observation options.')}
    requireValue(Boolean(values['capture-confirmed-test-project'])!==Boolean(values['inventory-sha256']),
      'Choose an explicitly confirmed test project capture or verification against an independent inventory digest.')
    const approvalRaw=await readProtected(await protectedPath(values.approval),8192)
    const approvalSha256=values['approval-sha256']
    const path=await protectedPath(values.inventory)
    const captureRaw=values['capture-confirmed-test-project']?
      await captureSupabaseBackups({approvalRaw,approvalSha256,captureConfirmed:true,token:process.env.SECTALK_BACKUP_OBSERVER_TOKEN}):
      await readProtected(path,captureLimit)
    const captureSha256=values['capture-confirmed-test-project']?hash(captureRaw):values['inventory-sha256']
    const report=verifySupabaseBackupObservation({approvalRaw,approvalSha256,captureRaw,captureSha256})
    if(values['capture-confirmed-test-project'])await writeFile(path,captureRaw,{mode:0o600,flag:'wx'})
    console.log(JSON.stringify(report))
  }catch(error){
    console.error(error?.code?'The protected Supabase backup evidence could not be read or written.':error.message)
    process.exitCode=1
  }
}
