import {createHash} from 'node:crypto'
import {createReadStream,createWriteStream} from 'node:fs'
import {lstat,mkdir,readFile,realpath,writeFile} from 'node:fs/promises'
import {basename,dirname,isAbsolute,join,relative,resolve} from 'node:path'
import {createInterface} from 'node:readline'
import {Readable,Transform,Writable} from 'node:stream'
import {pipeline} from 'node:stream/promises'
import {fileURLToPath} from 'node:url'
import {parseArgs} from 'node:util'

const buckets=new Set(['sectalk-vault','sectalk-chat-files','sectalk-avatars','recordings','sectalk-exports',
  'sectalk-workspace-files','sectalk-encrypted-group-files'])
const manifestName='storage-manifest.json'
const repo=await realpath(fileURLToPath(new URL('../',import.meta.url)))
const mime=/^[\w!#$&^.+-]+\/[\w!#$&^.+-]+$/i
const digestPattern=/^[a-f0-9]{64}$/

function safeArchivePath(path){
  const local=relative(repo,path)
  if(local===''||(!isAbsolute(local)&&local!=='..'&&!local.startsWith('../')&&!local.startsWith('..\\'))){
    throw new Error('Use a protected archive directory outside the checkout.')
  }
}

function connection(write){
  const raw=process.env.SECTALK_DR_STORAGE_URL
  const key=process.env.SECTALK_DR_STORAGE_KEY
  if(!raw||!key)throw new Error('Configure the explicit Storage origin and a private recovery credential.')
  const origin=new URL(raw)
  const local=origin.hostname==='127.0.0.1'&&origin.port&&['http:','https:'].includes(origin.protocol)
  if(origin.username||origin.password||origin.search||origin.hash||origin.pathname!=='/'||
     (write?!local:!local&&origin.protocol!=='https:'))throw new Error('Use a trusted HTTPS read source or a dedicated loopback recovery project.')
  const headers={Authorization:'Bearer '+key,apikey:key}
  return function request(path,options={}){
    return fetch(new URL('/storage/v1/'+path,origin),{
      ...options,headers:{...headers,...options.headers},redirect:'error',signal:AbortSignal.timeout(120000),
    })
  }
}

function validated(row){
  if(!row||!buckets.has(row.bucket)||typeof row.key!=='string'||row.key.length>1024||
    row.key.split('/').some(part=>!part||part==='.'||part==='..'||/[/\\\u0000-\u001f]/u.test(part))){
    throw new Error('Storage inventory contains an unsupported object identifier.')
  }
  const size=typeof row.size==='string'&&/^\d+$/.test(row.size)?Number(row.size):row.size
  const contentType=typeof row.contentType==='string'?row.contentType.split(';')[0].trim():''
  if(!Number.isSafeInteger(size)||size<0||!mime.test(contentType))throw new Error('Storage inventory contains invalid object metadata.')
  const objectId=createHash('sha256').update(row.bucket+'\n'+row.key).digest('hex')
  return {...row,size,objectId,contentType}
}

async function loadInventory(file){
  if(!(await lstat(file)).isFile())throw new Error('Use a Storage metadata inventory file.')
  const input=createInterface({input:createReadStream(file),crlfDelay:Infinity})
  const seen=new Set()
  const objects=[]
  for await(const line of input){
    if(!line.trim())continue
    const entry=validated(JSON.parse(line))
    if(seen.has(entry.objectId))throw new Error('Storage metadata inventory includes a duplicate object.')
    seen.add(entry.objectId)
    objects.push(entry)
  }
  return objects
}

const objectPath=entry=>'object/'+entry.bucket+'/'+entry.key.split('/').map(encodeURIComponent).join('/')

async function privateBucket(request,bucket){
  const info=await request('bucket/'+bucket)
  if(!info.ok||(await info.json()).public!==false)throw new Error('The recovery project must have matching private Storage buckets.')
}

async function inspectBytes(stream,entry,output){
  const hash=createHash('sha256')
  let bytes=0
  const meter=new Transform({transform(chunk,_encoding,ready){
    bytes+=chunk.length
    if(bytes>entry.size){ready(new Error('The Storage object is larger than its recorded size.'));return}
    hash.update(chunk)
    ready(null,chunk)
  }})
  await pipeline(stream,meter,output??new Writable({write(_chunk,_encoding,ready){ready()}}))
  if(bytes!==entry.size)throw new Error('The Storage object changed after inventory capture.')
  return hash.digest('hex')
}

async function inspectRemote(request,entry,destination){
  const response=await request(objectPath(entry))
  if(!response.ok||!response.body)throw new Error('A referenced private Storage object could not be read.')
  const output=destination?createWriteStream(destination,{flags:'wx',mode:0o600}):undefined
  return inspectBytes(Readable.fromWeb(response.body),entry,output)
}

async function backup(archive,inventory){
  const root=await realpath(dirname(archive))
  safeArchivePath(root)
  const destination=join(root,basename(archive))
  const objects=await loadInventory(inventory)
  const request=connection(false)
  for(const bucket of new Set(objects.map(entry=>entry.bucket)))await privateBucket(request,bucket)
  await mkdir(destination,{mode:0o700})
  for(const entry of objects){
    entry.sha256=await inspectRemote(request,entry,join(destination,entry.objectId))
  }
  await writeFile(join(destination,manifestName),JSON.stringify({format:1,capturedAt:new Date().toISOString(),objects})+'\n',
    {flag:'wx',mode:0o600})
  console.log(JSON.stringify({status:'storage_backup_created',objects:objects.length,bytes:objects.reduce((total,row)=>total+row.size,0)}))
}

async function readManifest(archive){
  const directory=await realpath(archive)
  safeArchivePath(directory)
  const file=join(directory,manifestName)
  if(!(await lstat(file)).isFile())throw new Error('The Storage archive needs a complete manifest.')
  const manifest=JSON.parse(await readFile(file,'utf8'))
  if(manifest.format!==1||!Array.isArray(manifest.objects))throw new Error('The Storage archive format is unsupported.')
  const seen=new Set()
  const files=[]
  for(const row of manifest.objects){
    const entry=validated(row)
    if(row.objectId!==entry.objectId||seen.has(entry.objectId)||!digestPattern.test(entry.sha256??'')){
      throw new Error('The Storage manifest has inconsistent object identifiers.')
    }
    seen.add(entry.objectId)
    const name=join(directory,entry.objectId)
    if(!(await lstat(name)).isFile()||await inspectBytes(createReadStream(name),entry)!==entry.sha256){
      throw new Error('A Storage archive file failed integrity verification.')
    }
    files.push({entry,name})
  }
  return files
}

async function restore(archive){
  const files=await readManifest(archive)
  const request=connection(true)
  for(const bucket of new Set(files.map(({entry})=>entry.bucket)))await privateBucket(request,bucket)
  let reused=0
  for(const {entry,name} of files){
    const upload=await request(objectPath(entry),{
      method:'POST',body:createReadStream(name),duplex:'half',headers:{
        'Content-Type':entry.contentType,'Content-Length':String(entry.size),'x-upsert':'false',
      },
    })
    if(!upload.ok&&upload.status!==409&&upload.status!==400)throw new Error('A Storage recovery write failed.')
    await upload.body?.cancel()
    if(await inspectRemote(request,entry)!==entry.sha256)throw new Error('The recovered object does not match the archive.')
    if(!upload.ok)reused++
  }
  console.log(JSON.stringify({status:'storage_restore_verified',objects:files.length,reused}))
}

try{
  const [mode,...args]=process.argv.slice(2)
  const {values}=parseArgs({args,options:{archive:{type:'string'},inventory:{type:'string'}}})
  if(!values.archive||!['backup','verify','restore'].includes(mode)||Boolean(values.inventory)!==(mode==='backup')){
    throw new Error('Use backup with --archive and --inventory or verify or restore with --archive.')
  }
  const archive=resolve(values.archive)
  if(mode==='backup')await backup(archive,values.inventory)
  else if(mode==='restore')await restore(archive)
  else console.log(JSON.stringify({status:'storage_archive_verified',objects:(await readManifest(archive)).length}))
}catch(error){
  console.error(error?.code||error instanceof SyntaxError?'The Storage recovery job could not read or write its inputs.':error.message)
  process.exitCode=1
}
