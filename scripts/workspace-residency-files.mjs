import {createHash} from 'node:crypto'
import {resolve} from 'node:path'
import {pathToFileURL} from 'node:url'
import {parseArgs} from 'node:util'

const idPattern=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/
const bucket='sectalk-workspace-files'
const maxBytes=4*1024*1024
const digest=bytes=>createHash('sha256').update(bytes).digest('hex')

function validateSelection(workspace,exportId,files) {
  if(!idPattern.test(workspace??'')||!idPattern.test(exportId??'')||!Array.isArray(files)||!files.length||files.length>200||
    !files.every(file=>typeof file==='string'&&idPattern.test(file))||new Set(files).size!==files.length) {
    throw new Error('Supply the exact approved workspace, export and distinct file identifiers.')
  }
}

export function loopback(value) {
  const parsed=URL.parse(value??'')
  if(!parsed||parsed.protocol!=='http:'||parsed.hostname!=='127.0.0.1'||!parsed.port||
    parsed.pathname!=='/'||parsed.username||parsed.password||parsed.search||parsed.hash) {
    throw new Error('Use separate disposable loopback app and Supabase origins.')
  }
  return parsed.origin
}

export function residencyDatabaseOrigins(sourceDatabase,targetDatabase,sourceProject,targetProject) {
  const source=URL.parse(sourceDatabase??'')
  const target=URL.parse(targetDatabase??'')
  if(source?.protocol!=='https:'&&target?.protocol!=='https:')return [loopback(sourceDatabase),loopback(targetDatabase)]
  if(![sourceProject,targetProject].every(ref=>typeof ref==='string'&&/^[a-z]{20}$/.test(ref))||
    sourceProject===targetProject||![[source,sourceProject],[target,targetProject]].every(([url,ref])=>
      url?.protocol==='https:'&&url.hostname===ref+'.supabase.co'&&!url.port&&url.pathname==='/'&&
      !url.username&&!url.password&&!url.search&&!url.hash)) {
    throw new Error('Use the exact HTTPS Supabase origins for the two separately approved project references.')
  }
  return [source.origin,target.origin]
}

export function residencyMemberKeys(origin,sourceKey,targetKey) {
  const keys=[sourceKey,targetKey]
  if(keys.some(key=>typeof key!=='string'||!key||key.startsWith('sb_secret_')))return false
  return !origin.startsWith('https:')||sourceKey!==targetKey&&keys.every(key=>key.startsWith('sb_publishable_'))
}

function approvedAppOrigin(value,configured) {
  const url=URL.parse(value??'')
  if(url?.protocol!=='https:'||url.origin!==configured||url.pathname!=='/'||url.port||url.username||url.password||
    url.search||url.hash||!/^(?:[a-z0-9-]+\.)+[a-z]{2,}$/i.test(url.hostname)||/\.(local|localhost|internal|test|invalid)$/i.test(url.hostname)) {
    throw new Error('Use only the exact HTTPS application origins approved for the source and destination projects.')
  }
  return url.origin
}

export function request(origin,path,options={}) {
  return fetch(origin+path,{...options,redirect:'error',cache:'no-store',signal:AbortSignal.timeout(15000)})
}

async function bytes(response,maximum) {
  if(!response.ok||!response.body) {
    await response.body?.cancel()
    throw new Error('An approved private object could not be read.')
  }
  const reader=response.body.getReader()
  const chunks=[]
  let size=0
  try {
    for(;;) {
      const part=await reader.read()
      if(part.done)break
      size+=part.value.byteLength
      if(size>maximum) {
        await reader.cancel()
        throw new Error('The object exceeds the workspace file limit.')
      }
      chunks.push(part.value)
    }
    return Buffer.concat(chunks,size)
  } finally {reader.releaseLock()}
}

export async function stageWorkspaceFiles({sourceApp,sourceDatabase,targetDatabase,authorization,targetKey,workspace,exportId,files}) {
  const app=loopback(sourceApp)
  const control=loopback(sourceDatabase)
  const target=loopback(targetDatabase)
  if(new Set([app,control,target]).size!==3)throw new Error('The rehearsal source and target must be separate.')
  validateSelection(workspace,exportId,files)
  if(typeof authorization!=='string'||typeof targetKey!=='string'||!authorization||!targetKey||authorization===targetKey) {
    throw new Error('Provide the source owner session and a separate private target credential.')
  }
  const authHeaders={Authorization:'Bearer '+authorization}
  const targetHeaders={Authorization:'Bearer '+targetKey,apikey:targetKey}
  const bucketResponse=await request(target,'/storage/v1/bucket/'+bucket,{headers:targetHeaders})
  const bucketInfo=JSON.parse((await bytes(bucketResponse,8192)).toString('utf8'))
  if(bucketInfo.id!==bucket||bucketInfo.public!==false)throw new Error('The target workspace bucket must be private.')
  let copied=0
  let reused=0
  const records=[]
  for(const file of [...files].sort()) {
    const sourceQuery=new URLSearchParams({workspace,file,offboarding:exportId})
    const response=await request(app,'/api/workspace-files?'+sourceQuery,{headers:authHeaders})
    const approved=await bytes(response,maxBytes)
    const hash=digest(approved)
    if(!approved.byteLength||response.headers.get('x-sectalk-file-sha256')!==hash) {
      throw new Error('The approved source bytes do not match the source digest.')
    }
    const path='/storage/v1/object/'+bucket+'/'+workspace+'/'+file
    const upload=await request(target,path,{method:'POST',body:approved,headers:{...targetHeaders,
      'Content-Type':'application/octet-stream','x-upsert':'false'},})
    if(!upload.ok&&upload.status!==409&&upload.status!==400) {
      await upload.body?.cancel()
      throw new Error('The isolated target refused a private object.')
    }
    await upload.body?.cancel()
    const verified=await bytes(await request(target,path,{headers:targetHeaders}),maxBytes)
    if(verified.byteLength!==approved.byteLength||digest(verified)!==hash) {
      throw new Error('The target object differs from the approved source. Existing data was preserved.')
    }
    if(upload.ok)copied++
    else reused++
    records.push({file,bytes:verified.byteLength,sha256:hash})
  }
  return {status:'private_bytes_staged',copied,reused,manifestSha256:digest(JSON.stringify({workspace,exportId,records}))}
}

export async function publishWorkspaceFiles({sourceApp,sourceDatabase,sourceProject,sourceKey,authorization,targetApp,targetSession,
  targetDatabase,targetProject,targetPublicKey,cell,installationNonce,approvedAppOrigins,workspace,exportId,files,room}) {
  const hosted=[sourceApp,sourceDatabase,targetApp,targetDatabase].some(value=>URL.parse(value??'')?.protocol==='https:')
  const [database,destinationDatabase]=hosted?residencyDatabaseOrigins(sourceDatabase,targetDatabase,sourceProject,targetProject):
    [loopback(sourceDatabase),undefined]
  const source=hosted?approvedAppOrigin(sourceApp,approvedAppOrigins?.[sourceProject]):loopback(sourceApp)
  const target=hosted?approvedAppOrigin(targetApp,approvedAppOrigins?.[targetProject]):loopback(targetApp)
  if(new Set([source,database,target]).size!==3)throw new Error('The rehearsal source and target must be separate.')
  validateSelection(workspace,exportId,files)
  if(room!==undefined&&(typeof room!=='string'||!idPattern.test(room)))throw new Error('Provide the exact approved room identifier.')
  if(![sourceKey,authorization,targetSession].every(value=>typeof value==='string'&&value)||
    new Set([sourceKey,authorization,targetSession]).size!==3||sourceKey.startsWith('sb_secret_')) {
    throw new Error('Provide separate source and destination owner sessions.')
  }
  if(hosted){
    if(!database.startsWith('https:')||[source,target].includes(destinationDatabase)||
      ![cell,installationNonce].every(value=>idPattern.test(value??''))||
      !residencyMemberKeys(database,sourceKey,targetPublicKey)) {
      throw new Error('Provide separate publishable keys and the approved destination installation.')
    }
    const ready=await request(destinationDatabase,'/rest/v1/rpc/st_v8_residency_target_ready',{
      method:'POST',headers:{apikey:targetPublicKey,'Content-Type':'application/json'},
      body:JSON.stringify({p_cell:cell,p_project:targetProject,p_installation_nonce:installationNonce}),
    })
    if(!ready.ok){
      await ready.body?.cancel()
      throw new Error('The approved destination installation could not be verified.')
    }
    if((await bytes(ready,1024)).toString('utf8').trim()!=='true')throw new Error('The approved destination installation could not be verified.')
  }
  const sourceAuth={Authorization:'Bearer '+authorization}
  const targetAuth={Authorization:'Bearer '+targetSession}
  const fileRoute=room?'/api/room-files?':'/api/workspace-files?'
  const scope=room?{room}:{workspace}
  const accessRpc=room?'st_v8_offboarding_room_file_access':'st_v8_offboarding_file_access'
  if(hosted){
    const destinationAccess=await request(target,fileRoute+new URLSearchParams(scope),{headers:targetAuth})
    await destinationAccess.body?.cancel()
    if(!destinationAccess.ok)throw new Error('The approved destination app could not confirm current access to this file scope.')
  }
  if(room){
    const match=new URLSearchParams({id:'eq.'+room,workspace_id:'eq.'+workspace,select:'id'})
    const result=await request(database,'/rest/v1/st_v6_rooms?'+match,{headers:{...sourceAuth,apikey:sourceKey}})
    const approvedRoom=JSON.parse((await bytes(result,4096)).toString('utf8'))
    if(!Array.isArray(approvedRoom)||approvedRoom.length!==1||approvedRoom[0]?.id!==room) {
      throw new Error('The approved room is unavailable in the selected source workspace.')
    }
  }
  const records=[]
  for(const file of [...files].sort()) {
    const from=new URLSearchParams({...scope,file,offboarding:exportId})
    const response=await request(source,fileRoute+from,{headers:sourceAuth})
    const approved=await bytes(response,maxBytes)
    const hash=digest(approved)
    if(!approved.byteLength||response.headers.get('x-sectalk-file-sha256')!==hash) {
      throw new Error('The approved source bytes do not match the source digest.')
    }
    const access=await request(database,'/rest/v1/rpc/'+accessRpc,{
      method:'POST',headers:{...sourceAuth,apikey:sourceKey,'Content-Type':'application/json'},
      body:JSON.stringify({...(room?{p_room:room}:{p_workspace:workspace}),p_export:exportId,p_file:file,p_hash:hash}),
    })
    const sourceFile=JSON.parse((await bytes(access,8192)).toString('utf8'))
    if(sourceFile?.file!==file||sourceFile.bytes!==approved.length||typeof sourceFile.filename!=='string'||
      (room&&(sourceFile.room!==room||sourceFile.sha256!==hash))) {
      throw new Error('The source did not confirm the exact approved file revision.')
    }
    const to=new URLSearchParams({...scope,file,'residency-import':exportId})
    const publish=await request(target,fileRoute+to,{method:'POST',body:approved,headers:{...targetAuth,
      'Content-Type':'application/octet-stream','X-SecTalk-File-Name':encodeURIComponent(sourceFile.filename)}})
    const receipt=JSON.parse((await bytes(publish,8192)).toString('utf8'))
    if(receipt?.id!==file)throw new Error('The destination did not publish the approved file ID.')
    const readParams=new URLSearchParams({...scope,file})
    const readBack=await bytes(await request(target,fileRoute+readParams,{headers:targetAuth}),maxBytes)
    if(readBack.length!==approved.length||digest(readBack)!==hash)throw new Error('The published destination file differed.')
    records.push({file,bytes:readBack.byteLength,sha256:hash})
  }
  return {status:room?'room_files_published':'workspace_files_published',count:records.length,
    manifestSha256:digest(JSON.stringify({workspace,exportId,...(room?{room}:{}),records}))}
}

async function main() {
  const {values}=parseArgs({options:{workspace:{type:'string'},export:{type:'string'},room:{type:'string'},cell:{type:'string'},file:{type:'string',multiple:true},publish:{type:'boolean'}}})
  if(values.room&&!values.publish)throw new Error('Room files can be published only after their exact approved manifest is staged.')
  const selection={sourceApp:process.env.SECTALK_RESIDENCY_SOURCE_APP,sourceDatabase:process.env.SECTALK_RESIDENCY_SOURCE_DATABASE,
    authorization:process.env.SECTALK_RESIDENCY_SOURCE_SESSION,workspace:values.workspace,exportId:values.export,files:values.file}
  const result=values.publish ? await publishWorkspaceFiles({...selection,sourceKey:process.env.SECTALK_RESIDENCY_SOURCE_PUBLIC_KEY,
    sourceProject:process.env.SECTALK_RESIDENCY_SOURCE_PROJECT,targetDatabase:process.env.SECTALK_RESIDENCY_TARGET_DATABASE,
    targetProject:process.env.SECTALK_RESIDENCY_TARGET_PROJECT,targetPublicKey:process.env.SECTALK_RESIDENCY_TARGET_PUBLIC_KEY,
    approvedAppOrigins:JSON.parse(process.env.SECTALK_RESIDENCY_PUBLISH_ORIGINS||'{}'),
    installationNonce:process.env.SECTALK_RESIDENCY_INSTALLATION_NONCE,cell:values.cell,
    targetApp:process.env.SECTALK_RESIDENCY_TARGET_APP,targetSession:process.env.SECTALK_RESIDENCY_TARGET_SESSION,room:values.room}) :
    await stageWorkspaceFiles({...selection,targetDatabase:process.env.SECTALK_RESIDENCY_TARGET_DATABASE,
      targetKey:process.env.SECTALK_RESIDENCY_TARGET_KEY})
  console.log(JSON.stringify(result))
}

if(process.argv[1]&&pathToFileURL(resolve(process.argv[1])).href===import.meta.url) {
  try {await main()}
  catch(error){console.error(error.message);process.exitCode=1}
}
