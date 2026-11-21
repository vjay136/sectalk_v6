import {fileFailure,fileHeaders} from '../../../../lib/authenticated-file-request'
import {readBoundedText} from '../../../../lib/request-body'
import {exportIdPattern,exportStorage} from '../../../../lib/export-storage-server'
import {operationalReportViewer} from '../../../../lib/operational-report-server'
import {openTenantRecord,sealTenantRecord,wrapFreshTenantKey,type TenantRecordEnvelope,type TenantRecordKey} from '../../../../lib/tenant-artifact-keys'
import {managedRoomRevision} from '../../../../lib/managed-room-revision'

export const runtime='nodejs'
type Context={params:Promise<{room:string}>}
type Row={room:string;id:string;sender:string;created_at:string;key:TenantRecordKey;envelope:TenantRecordEnvelope;source_revision?:string}
const unavailable=()=>fileFailure(404,'Managed room unavailable.')
const failed=()=>fileFailure(503,'Managed room encryption is unavailable.')
const validId=(id:unknown):id is string=>typeof id==='string'&&exportIdPattern.test(id)
const normalized=(value:string)=>value.normalize('NFKC').toLowerCase()
const pageSize=50

function validCursor(before:unknown,id:unknown){
  return (before===null&&id===null)||(typeof before==='string'&&before.length<=44
    &&Number.isFinite(Date.parse(before))&&validId(id))
}

function databaseError(error:{code:string;message:string}){
  if(error.code==='42501')return unavailable()
  if(error.code==='22023')return fileFailure(400,error.message)
  if(error.code==='PT409')return fileFailure(409,error.message)
  if(error.code==='PT422')return fileFailure(422,error.message)
  if(error.code==='PT423')return fileFailure(423,error.message)
  return failed()
}

export async function POST(request:Request,{params}:Context){
  const room=(await params).room.toLowerCase()
  if(!validId(room))return unavailable()
  const viewer=await operationalReportViewer(request)
  const store=exportStorage()
  if(!viewer)return fileFailure(401,'Sign in to post in this room.')
  if(!store)return failed()
  try{
    const raw=await readBoundedText(request,25000)
    if(raw===undefined)return fileFailure(413,'Message too large.')
    const data=JSON.parse(raw??'null')
    if(data?.action==='search'){
      if(typeof data.query!=='string'||data.query.length>120)return fileFailure(400,'Enter a valid room search.')
      const query=normalized(data.query.trim())
      if(query.length<2||query.length>120)return fileFailure(400,'Enter a valid room search.')
      const before=data.before??null,id=data.id??null
      if(!validCursor(before,id))return fileFailure(400,'Choose a valid message page.')
      return readPage(viewer,store,room,before,id,query)
    }
    if(!validId(data?.id)||typeof data.body!=='string'||[...data.body.trim()].length>4000||!data.body.trim())
      return fileFailure(400,'Enter a message between 1 and 4,000 characters.')
    const id=data.id.toLowerCase(),body=data.body.replace(/^ +| +$/g,'')
    const ticket=await viewer.client.rpc('st_v8_managed_room_ticket',{p_room:room,p_post:id,p_body:body})
    if(ticket.error)return databaseError(ticket.error)
    if(ticket.data?.already_sent===true)return new Response(null,{status:204,headers:fileHeaders})
    if(!validId(ticket.data?.ticket)||!validId(ticket.data?.workspace))return unavailable()
    const scope={p_ticket:ticket.data.ticket,p_actor:viewer.actor}
    let result=await store.rpc('st_v8_managed_room_work',{...scope,p_action:'key'})
    if(result.error)return databaseError(result.error)
    if(!result.data)return unavailable()
    if(result.data.version===null){
      const key=await wrapFreshTenantKey(ticket.data.workspace,1,'managed')
      result=await store.rpc('st_v8_managed_room_work',{...scope,p_action:'key',p_data:{wrapped:key.wrapped}})
      if(result.error)return databaseError(result.error)
    }
    const key=result.data as TenantRecordKey|null
    if(!key||key.workspace!==ticket.data.workspace||!Number.isInteger(key.version))return failed()
    const clear=Buffer.from(body,'utf8')
    try{
      const envelope=await sealTenantRecord(key,'room:'+room,id,viewer.actor,clear)
      const written=await store.rpc('st_v8_managed_room_work',{...scope,p_action:'finish',p_data:{...envelope,version:key.version}})
      if(written.error)return databaseError(written.error)
      return written.data===true?new Response(null,{status:204,headers:fileHeaders}):unavailable()
    }finally{clear.fill(0)}
  }catch(error){return error instanceof SyntaxError?fileFailure(400,'Invalid message request.'):failed()}
}

export async function GET(request:Request,{params}:Context){
  const room=(await params).room.toLowerCase()
  if(!validId(room))return unavailable()
  const viewer=await operationalReportViewer(request)
  const store=exportStorage()
  if(!viewer)return fileFailure(401,'Sign in to read this room.')
  if(!store)return failed()
  const query=new URL(request.url).searchParams
  const before=query.get('before'),id=query.get('id')
  if(!validCursor(before,id))return fileFailure(400,'Choose a valid message page.')
  return readPage(viewer,store,room,before,id)
}

async function readPage(viewer:NonNullable<Awaited<ReturnType<typeof operationalReportViewer>>>,
  store:NonNullable<ReturnType<typeof exportStorage>>,room:string,before:string|null,id:string|null,query?:string){
  try{
    const ticket=await viewer.client.rpc('st_v8_managed_room_ticket',{p_room:room})
    if(ticket.error)return databaseError(ticket.error)
    if(!validId(ticket.data?.ticket))return unavailable()
    const result=await store.rpc('st_v8_managed_room_work',{
      p_ticket:ticket.data.ticket,p_actor:viewer.actor,p_action:'read',p_data:{before,id},
    })
    if(result.error)return databaseError(result.error)
    if(!Array.isArray(result.data)||result.data.length>pageSize+1)return unavailable()
    const rows=(result.data as Row[]).slice(0,pageSize)
    const filtered=await Promise.all(rows.map(async row=>{
      if(row.room!==room||!validId(row.id)||!validId(row.sender)||row.key.workspace!==ticket.data.workspace)
        throw new Error('Invalid room envelope')
      const clear=await openTenantRecord(row.key,'room:'+room,row.id,row.sender,row.envelope)
      try{
        const body=new TextDecoder('utf-8',{fatal:true}).decode(clear)
        if(query&&!normalized(body).includes(query))return null
        const revision=row.source_revision??managedRoomRevision(row)
        if(!/^[a-f0-9]{64}$/.test(revision))throw new Error('Invalid room revision')
        return {id:row.id,sender:row.sender,created_at:row.created_at,body,revision}
      }
      finally{clear.fill(0)}
    }))
    const access=await viewer.client.rpc('st_v8_managed_room_readable',{p_room:room})
    if(access.data!==true||access.error)return unavailable()
    const last=rows.at(-1)
    return Response.json({messages:filtered.filter(message=>message!==null),
      next:result.data.length>pageSize&&last?{before:last.created_at,id:last.id}:null},{headers:fileHeaders})
  }catch{return failed()}
}
