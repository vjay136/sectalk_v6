import {execFile} from 'node:child_process'
import {createHash} from 'node:crypto'
import {lstat,readFile,realpath,writeFile} from 'node:fs/promises'
import {basename,dirname,isAbsolute,join,relative,resolve,sep} from 'node:path'
import {fileURLToPath,pathToFileURL} from 'node:url'
import {parseArgs,promisify} from 'node:util'
import {workloadEnvironment} from './adapter.mjs'

const aws=promisify(execFile)
const cli='/usr/local/aws-cli/v2/current/bin/aws'
const digest=/^[a-f0-9]{64}$/
const uuid=/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/
const hash=data=>createHash('sha256').update(data).digest('hex')
const format='sectalk-s3-copy-inventory-v1'
const pageSize=1000
const maximumPages=200
const maximumManifestBytes=128*1024*1024

function requireValue(condition,message){
  if(!condition)throw new Error(message)
}

function canonicalScope(input){
  const {workspace,version,bucket,owner,region,prefix}=input??{}
  requireValue(typeof workspace==='string'&&uuid.test(workspace)&&Number.isSafeInteger(version)&&version>0&&version<=2147483647&&
    typeof bucket==='string'&&/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(bucket)&&
    !bucket.includes('..')&&!/^\d+\.\d+\.\d+\.\d+$/.test(bucket)&&
    typeof owner==='string'&&/^[0-9]{12}$/.test(owner)&&typeof region==='string'&&/^[a-z]{2}-[a-z]+-[1-9][0-9]?$/.test(region)&&
    typeof prefix==='string'&&prefix.length<=256&&/^(?:[A-Za-z0-9][A-Za-z0-9._=-]*\/)+$/.test(prefix),
  'Supply the exact workspace, key version, AWS bucket owner, region, bucket and nonempty recovery prefix.')
  return {workspace,version,bucket,owner,region,prefix}
}

export function recoveryScopeDigest(input){
  return hash(JSON.stringify(['sectalk-s3-copy-scope-v1',canonicalScope(input)]))
}

function exactScope(input,approvedScope){
  const scope=canonicalScope(input)
  requireValue(digest.test(approvedScope??'')&&recoveryScopeDigest(scope)===approvedScope,
    'The selected S3 scope does not match the independently recorded scope digest.')
  return scope
}

function timestamp(value){
  requireValue(typeof value==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?(?:Z|\+00:00)$/.test(value)&&
    Number.isFinite(Date.parse(value)),'The inventory contains an invalid timestamp.')
  return new Date(value).toISOString()
}

function objectKey(value,prefix){
  requireValue(typeof value==='string'&&Buffer.byteLength(value)<=1024&&value.startsWith(prefix),
    'The provider inventory contains an object outside its approved scope.')
  return value
}

function versionId(value){
  requireValue(typeof value==='string'&&value.length>0&&value.length<=1024&&value!=='null'&&!/[\x00-\x20\x7f]/.test(value),
    'An object or marker lacks an exact immutable version ID.')
  return value
}

function decodeProviderKey(value){
  requireValue(typeof value==='string','The provider returned an invalid URL-encoded object key.')
  try {return decodeURIComponent(value)}
  catch {throw new Error('The provider returned an invalid URL-encoded object key.')}
}

function copyRecord(input,scope){
  requireValue(input&&(input.kind==='object_version'||input.kind==='delete_marker')&&typeof input.latest==='boolean',
    'The inventory contains an unsupported object version or marker.')
  const record={kind:input.kind,key:objectKey(input.key,scope.prefix),version:versionId(input.version),
    latest:input.latest,modifiedAt:timestamp(input.modifiedAt)}
  if(record.kind==='object_version'){
    requireValue(Number.isSafeInteger(input.size)&&input.size>=0&&typeof input.etag==='string'&&
      input.etag.length>0&&input.etag.length<=128&&!/[\x00-\x20\x7f]/.test(input.etag)&&
      typeof input.storageClass==='string'&&/^[A-Z_0-9]{1,40}$/.test(input.storageClass),
    'The provider inventory has incomplete object metadata.')
    Object.assign(record,{size:input.size,etag:input.etag,storageClass:input.storageClass})
  }
  return record
}

function canonicalCopies(copies,scope){
  requireValue(Array.isArray(copies)&&copies.length<=pageSize*maximumPages,
    'The exact version inventory exceeds the supported bounds.')
  const versions=new Set()
  const latest=new Map()
  const canonical=copies.map(raw=>{
    const record=copyRecord(raw,scope)
    const identity=JSON.stringify([record.key,record.version])
    requireValue(!versions.has(identity),'The provider repeated an object version or delete marker.')
    versions.add(identity)
    latest.set(record.key,(latest.get(record.key)??0)+Number(record.latest))
    return record
  })
  requireValue([...latest.values()].every(count=>count===1),'At least one object lacks a single current version or delete marker.')
  return canonical.sort((a,b)=>a.key===b.key?(a.version<b.version?-1:1):(a.key<b.key?-1:1))
}

function listingDigest(scope,copies){
  return hash(JSON.stringify(['sectalk-s3-copy-listing-v1',scope,copies]))
}

export async function captureS3RecoveryCopies({input,approvedScope,settings,run=aws,now=()=>new Date()}){
  const scope=exactScope(input,approvedScope)
  const env=workloadEnvironment(settings)
  async function read(action,extra=[]){
    try{
      const {stdout}=await run(cli,['s3api',action,'--bucket',scope.bucket,'--expected-bucket-owner',scope.owner,
        '--region',scope.region,'--output','json','--no-cli-pager','--cli-connect-timeout','3','--cli-read-timeout','8',...extra],
      {cwd:'/tmp',env,timeout:15000,maxBuffer:8*1024*1024})
      return JSON.parse(stdout)
    }catch{throw new Error('The scoped AWS S3 observation was denied or could not be completed.')}
  }
  async function ensureVersioning(){
    requireValue((await read('get-bucket-versioning'))?.Status==='Enabled',
      'The approved bucket must have active versioning for exact copy inventory.')
  }
  async function scan(){
    const rows=[],seenMarkers=new Set()
    let markerKey='',markerVersion=''
    for(let index=0;index<maximumPages;index++){
      const page=await read('list-object-versions',['--no-paginate','--prefix',scope.prefix,
        '--encoding-type','url','--max-keys',String(pageSize),
        ...(markerKey?['--key-marker='+markerKey,'--version-id-marker='+markerVersion]:[])])
      requireValue(page&&page.Name===scope.bucket&&page.EncodingType==='url'&&page.MaxKeys===pageSize&&
        decodeProviderKey(page.Prefix)===scope.prefix&&typeof page.IsTruncated==='boolean'&&
        decodeProviderKey(page.KeyMarker??'')===markerKey&&(page.VersionIdMarker??'')===markerVersion&&
        !page.Delimiter&&(page.CommonPrefixes===undefined||(Array.isArray(page.CommonPrefixes)&&!page.CommonPrefixes.length)),
      'The provider returned a different scope or invalid version page.')
      const versions=page.Versions===undefined?[]:page.Versions
      const markers=page.DeleteMarkers===undefined?[]:page.DeleteMarkers
      requireValue(Array.isArray(versions)&&Array.isArray(markers)&&versions.length+markers.length<=pageSize,
        'The provider returned invalid versions or delete markers.')
      for(const [items,kind] of [[versions,'object_version'],[markers,'delete_marker']]){
        for(const item of items){
          const key=decodeProviderKey(item?.Key)
          rows.push({kind,key,version:item?.VersionId,latest:item?.IsLatest,modifiedAt:item?.LastModified,
            ...(kind==='object_version'&&{size:item.Size,etag:item.ETag,storageClass:item.StorageClass})})
        }
      }
      if(!page.IsTruncated){
        requireValue(!page.NextKeyMarker&&!page.NextVersionIdMarker,'A completed version page still contained continuation state.')
        return canonicalCopies(rows,scope)
      }
      requireValue(versions.length+markers.length>0,'A truncated version page was empty.')
      markerKey=objectKey(decodeProviderKey(page.NextKeyMarker),scope.prefix)
      markerVersion=versionId(page.NextVersionIdMarker)
      const marker=JSON.stringify([markerKey,markerVersion])
      requireValue(!seenMarkers.has(marker),'The provider repeated an inventory continuation marker.')
      seenMarkers.add(marker)
    }
    throw new Error('The inventory exceeded its page limit. Divide the known namespace into separately approved scopes.')
  }
  const location=(await read('get-bucket-location'))?.LocationConstraint
  const actualRegion=location===null?'us-east-1':location==='EU'?'eu-west-1':location
  requireValue(actualRegion===scope.region,'The actual S3 bucket region does not match the approved scope.')
  await ensureVersioning()
  const first=await scan()
  const second=await scan()
  await ensureVersioning()
  const listingSha256=listingDigest(scope,second)
  requireValue(listingDigest(scope,first)===listingSha256,'The approved S3 scope changed between complete inventory passes.')
  return {format,capturedAt:timestamp(now().toISOString()),scope,scopeSha256:approvedScope,listingSha256,copies:second}
}

export function verifyS3RecoveryInventory(raw,{input,approvedScope,approvedInventory}){
  const scope=exactScope(input,approvedScope)
  requireValue(Buffer.isBuffer(raw)&&raw.length<=maximumManifestBytes,'The protected inventory exceeds its supported size.')
  requireValue(digest.test(approvedInventory??'')&&
    hash(raw)===approvedInventory,'The inventory does not match its independently recorded digest.')
  let manifest
  try{manifest=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw))}
  catch{throw new Error('The approved inventory could not be parsed.')}
  requireValue(manifest?.format===format&&Object.keys(manifest).sort().join(',')==='capturedAt,copies,format,listingSha256,scope,scopeSha256'&&
    JSON.stringify(manifest.scope)===JSON.stringify(scope)&&
    manifest.scopeSha256===approvedScope&&timestamp(manifest.capturedAt)===manifest.capturedAt,
  'The approved inventory does not belong to the selected recovery scope.')
  const copies=canonicalCopies(manifest.copies,scope)
  requireValue(JSON.stringify(copies)===JSON.stringify(manifest.copies)&&listingDigest(scope,copies)===manifest.listingSha256,
    'The approved inventory has inconsistent version provenance.')
  let objectVersions=0,noncurrentVersions=0,deleteMarkers=0
  for(const copy of copies){
    if(copy.kind==='delete_marker'){deleteMarkers++;continue}
    objectVersions++
    if(!copy.latest)noncurrentVersions++
  }
  return {status:'scoped_s3_version_inventory_verified',checkedScope:approvedScope,inventorySha256:approvedInventory,
    listingSha256:manifest.listingSha256,capturedAt:manifest.capturedAt,objectVersions,noncurrentVersions,deleteMarkers,
    backupErasure:'unverified'}
}

async function protectedPath(value){
  requireValue(typeof value==='string'&&value.length>0,'Choose an inventory file in restricted storage outside the source checkout.')
  const absolute=resolve(value)
  const path=join(await realpath(dirname(absolute)),basename(absolute))
  const installed=await realpath(dirname(fileURLToPath(import.meta.url)))
  const checkout=resolve(installed,'../..')
  const checkoutMetadata=await lstat(join(checkout,'package.json')).catch(error=>{
    if(error?.code!=='ENOENT')throw error
    return null
  })
  const source=checkoutMetadata?.isFile()?checkout:installed
  const outside=relative(source,path)
  requireValue(isAbsolute(outside)||outside==='..'||outside.startsWith('..'+sep),
    'Choose an inventory file in restricted storage outside the source checkout.')
  return path
}

if(process.argv[1]&&pathToFileURL(process.argv[1]).href===import.meta.url){
  try{
    let values
    try {
      ({values}=parseArgs({options:{mode:{type:'string'},workspace:{type:'string'},version:{type:'string'},
        bucket:{type:'string'},owner:{type:'string'},region:{type:'string'},prefix:{type:'string'},inventory:{type:'string'},
        'scope-sha256':{type:'string'},'inventory-sha256':{type:'string'}}}))
    }catch{throw new Error('Invalid recovery inventory options.')}
    requireValue(/^[1-9][0-9]{0,9}$/.test(values.version??''),'Choose the exact positive integer key version.')
    const input={...values,version:Number(values.version)}
    if(values.mode==='scope'){
      console.log(JSON.stringify({scopeSha256:recoveryScopeDigest(input)}))
    }else{
      requireValue(['capture','verify'].includes(values.mode),'Choose scope, capture or verify.')
      const approvedScope=values['scope-sha256']
      const path=await protectedPath(values.inventory)
      if(values.mode==='capture'){
        const manifest=await captureS3RecoveryCopies({input,approvedScope,settings:process.env})
        const raw=Buffer.from(JSON.stringify(manifest)+'\n')
        const approvedInventory=hash(raw)
        const report=verifyS3RecoveryInventory(raw,{input,approvedScope,approvedInventory})
        await writeFile(path,raw,{mode:0o600,flag:'wx'})
        console.log(JSON.stringify({...report,status:'scoped_s3_version_inventory_captured'}))
      }else{
        const info=await lstat(path)
        requireValue(info.isFile()&&info.size<=maximumManifestBytes,'Choose a regular bounded recovery inventory file.')
        console.log(JSON.stringify(verifyS3RecoveryInventory(await readFile(path),{
          input,approvedScope,approvedInventory:values['inventory-sha256'],
        })))
      }
    }
  }catch(error){
    console.error(error?.code?'The protected recovery inventory could not be read or written.':error.message)
    process.exitCode=1
  }
}
