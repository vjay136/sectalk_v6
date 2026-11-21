import {spawn} from 'node:child_process'
import {createHash} from 'node:crypto'
import {lstat,readFile,realpath} from 'node:fs/promises'
import {dirname,isAbsolute,join,relative,resolve,sep} from 'node:path'
import {fileURLToPath,pathToFileURL} from 'node:url'
import {parseArgs} from 'node:util'
import {workloadEnvironment} from './adapter.mjs'
import {verifyS3RecoveryInventory} from './s3-recovery-copy-inventory.mjs'

const digest=/^[0-9a-f]{64}$/
const files=['project-manifest.json','project.pgdump','private-inventory.jsonl','objects/storage-manifest.json']
const cli='/usr/local/aws-cli/v2/current/bin/aws'
const pipe='"$@" /dev/fd/3 3>&1 1>&2 | /bin/cat'
const hash=value=>createHash('sha256').update(value).digest('hex')

function requireValue(condition,message){
  if(!condition)throw new Error(message)
}

function pinnedJson(raw,expected,label){
  requireValue(Buffer.isBuffer(raw)&&digest.test(expected??'')&&hash(raw)===expected,
    `The ${label} differs from its independently recorded digest.`)
  try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw))}
  catch{throw new Error(`The ${label} is unsupported.`)}
}

export function prepareRecoveryCopy({approvalRaw,approvalSha256,inventoryRaw,planRaw,manifestRaw,archiveRaw,providerRaw}){
  const approval=pinnedJson(approvalRaw,approvalSha256,'copy approval')
  requireValue(approval?.format==='sectalk-s3-archive-copy-approval-v1','The copy approval format is unsupported.')
  const inventory=pinnedJson(inventoryRaw,approval.inventorySha256,'S3 inventory')
  const scope=inventory?.scope
  const verified=verifyS3RecoveryInventory(inventoryRaw,{
    input:scope,approvedScope:approval.scopeSha256,approvedInventory:approval.inventorySha256,
  })
  const plan=pinnedJson(planRaw,approval.planSha256,'S3 copy plan')
  requireValue(plan?.format==='sectalk-s3-archive-version-plan-v1'&&plan.inventorySha256===verified.inventorySha256&&
    plan.scopeSha256===verified.checkedScope&&typeof plan.generationPrefix==='string'&&
    plan.generationPrefix.startsWith(scope.prefix)&&plan.generationPrefix.length<=512&&
    /^(?:[A-Za-z0-9][A-Za-z0-9._=-]*\/)+$/.test(plan.generationPrefix)&&
    plan.versions&&Object.keys(plan.versions).length===files.length,
  'The copy plan does not match the approved generation inventory.')

  const manifest=pinnedJson(manifestRaw,approval.projectManifestSha256,'project manifest')
  const archive=pinnedJson(archiveRaw,approval.archiveFindingSha256,'archived key finding')
  const provider=pinnedJson(providerRaw,approval.providerReceiptSha256,'provider key receipt')
  requireValue(manifest?.version===1&&manifest.files&&Object.keys(manifest.files).length===files.length-1&&
    files.slice(1).every(name=>digest.test(manifest.files[name]??''))&&Number.isFinite(Date.parse(manifest.capturedAt)),
  'The project manifest does not describe the required archive artifacts.')
  requireValue(provider?.format==='sectalk-provider-key-evidence-v1'&&provider.workspace===scope.workspace&&
    provider.version===scope.version&&digest.test(provider.eventSha256??'')&&digest.test(provider.pinCommitment??'')&&
    Number.isFinite(Date.parse(provider.eventTime))&&Number.isFinite(Date.parse(provider.recordedAt))&&
    Date.parse(provider.eventTime)<=Date.parse(provider.recordedAt)+30000,
  'The independently reviewed provider receipt has the wrong scope or event.')
  requireValue(archive?.format==='sectalk-backup-key-evidence-v1'&&archive.workspace===scope.workspace&&
    archive.capturedAt===manifest.capturedAt&&archive.manifestSha256===approval.projectManifestSha256&&
    archive.postgresSha256===manifest.files['project.pgdump']&&archive.exactKey?.version===scope.version&&
    archive.exactKey.record==='external_reference'&&archive.exactKey.providerPinMatch===true&&
    archive.providerEvidence?.receiptSha256===approval.providerReceiptSha256&&
    archive.providerEvidence.eventSha256===provider.eventSha256&&archive.providerEvidence.eventTime===provider.eventTime&&
    archive.providerEvidence.record==='independent_provider_receipt'&&archive.providerEvidence.archiveBinding==='matches',
  'The archived key finding does not bind this exact provider receipt to the same generation and key version.')

  const selections=files.map(name=>{
    const version=Object.hasOwn(plan.versions,name)?plan.versions[name]:null
    const key=plan.generationPrefix+name
    requireValue(typeof version==='string'&&version.length>0&&version!=='null',
      'The plan must select one immutable version for every required archive artifact.')
    const copy=inventory.copies.find(row=>row.key===key&&row.version===version)
    requireValue(copy?.kind==='object_version','A selected exact archive version is absent from the approved inventory.')
    return {...copy,name,sha256:name===files[0]?approval.projectManifestSha256:manifest.files[name]}
  })
  return {scope,selections,approvalSha256,inventorySha256:approval.inventorySha256,scopeSha256:approval.scopeSha256,
    planSha256:approval.planSha256,projectManifestSha256:approval.projectManifestSha256,
    archiveFindingSha256:approval.archiveFindingSha256,providerReceiptSha256:approval.providerReceiptSha256,
    reviewedProviderEventSha256:provider.eventSha256,otherInventoryRecords:inventory.copies.length-selections.length}
}

export function observeExactS3Object(scope,copy,env,timeout,launch=spawn){
  return new Promise((resolveResult,reject)=>{
    const child=launch('/bin/bash',['-o','pipefail','-c',pipe,'sectalk-s3-copy',cli,'s3api','get-object',
      '--bucket',scope.bucket,'--expected-bucket-owner',scope.owner,'--region',scope.region,
      '--key='+copy.key,'--version-id='+copy.version,'--output','json','--no-cli-pager','--cli-connect-timeout','3',
      '--cli-read-timeout','30'],{cwd:'/tmp',env,detached:true,stdio:['ignore','pipe','pipe']})
    const checksum=createHash('sha256')
    let size=0,metadataSize=0,failed=false
    const metadata=[]
    function stop(){
      failed=true
      if(child.pid)try{process.kill(-child.pid,'SIGKILL')}catch{child.kill('SIGKILL')}
    }
    const timer=setTimeout(stop,timeout)
    child.stdout.on('data',chunk=>{
      size+=chunk.length
      if(size>copy.size){chunk.fill(0);stop();return}
      checksum.update(chunk)
      chunk.fill(0)
    })
    child.stderr.on('data',chunk=>{
      metadataSize+=chunk.length
      if(metadataSize>65536){chunk.fill(0);stop();return}
      metadata.push(chunk)
    })
    child.on('error',()=>{failed=true})
    child.stdout.on('error',stop)
    child.stderr.on('error',stop)
    child.on('close',code=>{
      clearTimeout(timer)
      const raw=Buffer.concat(metadata)
      for(const chunk of metadata)chunk.fill(0)
      try{
        if(failed||code!==0)throw new Error()
        const info=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw))
        resolveResult({size,sha256:checksum.digest('hex'),version:info.VersionId,contentLength:info.ContentLength,
          etag:info.ETag,modifiedAt:info.LastModified,deleteMarker:info.DeleteMarker===true})
      }catch{reject(new Error('The approved S3 version could not be streamed and verified.'))}
      finally{raw.fill(0)}
    })
  })
}

export async function verifyRecoveryCopy({prepared,settings,confirmDownloads,timeoutSeconds=600,launch=spawn}){
  requireValue(confirmDownloads===true&&Number.isSafeInteger(timeoutSeconds)&&timeoutSeconds>=30&&timeoutSeconds<=3600,
    'Confirm the exact version reads and supply a timeout between 30 and 3600 seconds per object.')
  const env=workloadEnvironment(settings)
  for(const copy of prepared.selections){
    const observed=await observeExactS3Object(prepared.scope,copy,env,timeoutSeconds*1000,launch)
    requireValue(observed.version===copy.version&&observed.size===copy.size&&observed.contentLength===copy.size&&
      observed.sha256===copy.sha256&&observed.etag===copy.etag&&Date.parse(observed.modifiedAt)===Date.parse(copy.modifiedAt)&&
      !observed.deleteMarker,'An exact S3 archive version no longer matches its approved bytes and inventory.')
  }
  return {format:'sectalk-s3-recovery-copy-provenance-v1',checkedAt:new Date().toISOString(),
    approvalSha256:prepared.approvalSha256,scopeSha256:prepared.scopeSha256,inventorySha256:prepared.inventorySha256,
    planSha256:prepared.planSha256,projectManifestSha256:prepared.projectManifestSha256,
    archiveFindingSha256:prepared.archiveFindingSha256,providerReceiptSha256:prepared.providerReceiptSha256,
    reviewedProviderEventSha256:prepared.reviewedProviderEventSha256,matchedArtifactVersions:prepared.selections.length,
    otherInventoryRecords:prepared.otherInventoryRecords,backupErasure:'unverified'}
}

async function readProtectedBundle(path){
  const root=await realpath(path)
  const installed=await realpath(dirname(fileURLToPath(import.meta.url)))
  const checkout=resolve(installed,'../..')
  const checkoutMetadata=await lstat(join(checkout,'package.json')).catch(error=>{
    if(error?.code!=='ENOENT')throw error
    return null
  })
  const directory=relative(checkoutMetadata?.isFile()?checkout:installed,root)
  requireValue(isAbsolute(directory)||directory==='..'||directory.startsWith('..'+sep),
    'Use a restricted evidence bundle outside the source checkout.')
  const bundle={
    approvalRaw:['copy-approval.json',8192],inventoryRaw:['s3-inventory.json',128*1024*1024],
    planRaw:['s3-archive-plan.json',16384],manifestRaw:['project-manifest.json',16384],
    archiveRaw:['archive-key-evidence.json',16384],providerRaw:['provider-key-evidence.json',8192],
  }
  const values={}
  for(const [label,[name,maximum]] of Object.entries(bundle)){
    const file=join(root,name)
    const details=await lstat(file)
    requireValue(details.isFile()&&details.size<=maximum&&await realpath(file)===file,
      'Use bounded regular evidence files in the selected bundle.')
    values[label]=await readFile(file)
    requireValue(values[label].length<=maximum,'A protected evidence file exceeded its supported size.')
  }
  return values
}

if(process.argv[1]&&pathToFileURL(process.argv[1]).href===import.meta.url){
  try{
    let values
    try{
      ({values}=parseArgs({options:{bundle:{type:'string'},'approval-sha256':{type:'string'},
        'check-inputs-only':{type:'boolean'},'confirm-version-downloads':{type:'boolean'},'timeout-seconds':{type:'string'}}}))
    }catch{throw new Error('Invalid recovery copy provenance options.')}
    requireValue(values.bundle&&digest.test(values['approval-sha256']??'')&&
      Boolean(values['check-inputs-only'])!==Boolean(values['confirm-version-downloads']),
    'Provide the protected bundle and independent approval digest and choose offline input checks or exact version reads.')
    const prepared=prepareRecoveryCopy({...await readProtectedBundle(values.bundle),approvalSha256:values['approval-sha256']})
    const report=values['check-inputs-only']
      ? {status:'recovery_copy_inputs_pinned',approvalSha256:prepared.approvalSha256,selectedVersions:prepared.selections.length,
        backupErasure:'unverified'}
      : await verifyRecoveryCopy({prepared,settings:process.env,confirmDownloads:values['confirm-version-downloads'],
        timeoutSeconds:values['timeout-seconds']===undefined?600:Number(values['timeout-seconds'])})
    console.log(JSON.stringify(report))
  }catch(error){
    console.error(error?.code?'The protected recovery evidence could not be read.':error.message)
    process.exitCode=1
  }
}
