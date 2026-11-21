import { fileFailure, fileHeaders } from '../../../../lib/authenticated-file-request'
import { readBoundedText } from '../../../../lib/request-body'
import { exportIdPattern, exportStorage } from '../../../../lib/export-storage-server'
import { operationalReportViewer } from '../../../../lib/operational-report-server'
import { openTenantRecord, sealTenantRecord, wrapFreshTenantKey, type TenantRecordEnvelope, type TenantRecordKey } from '../../../../lib/tenant-artifact-keys'

export const runtime='nodejs'
type RequestContext = { params: Promise<{ channel: string }> }
type Row = { id: string; sender: string; channel_id: string; created_at: string; quarantined_at: string | null;
  envelope: TenantRecordEnvelope; key: TenantRecordKey }
const unavailable=()=>fileFailure(404,'Managed channel unavailable.')
const failed=()=>fileFailure(503,'Managed channel encryption is unavailable.')
const validId=(value: unknown): value is string => typeof value==='string' && exportIdPattern.test(value)
const searchBatch=50

function validCursor(before:unknown,beforeId:unknown) {
  return (before===null && beforeId===null) || (typeof before==='string' && before.length<=44
    && Number.isFinite(Date.parse(before)) && validId(beforeId))
}

function actionError(error: { code: string; message: string; details?: string }) {
  if (error.code==='42501') return unavailable()
  if (error.code==='22023') return fileFailure(400,error.message)
  if (error.code==='PT409') return fileFailure(409,error.message)
  if (error.code==='PT422' || error.code==='PT428') return Response.json({
    code:error.code, error:error.message, details:error.details,
  },{status:error.code==='PT422'?422:428,headers:fileHeaders})
  return failed()
}

export async function POST(request: Request, {params}: RequestContext) {
  const {channel}=await params
  if (!validId(channel)) return unavailable()
  const viewer=await operationalReportViewer(request)
  if (!viewer) return fileFailure(401,'Sign in to send a message.')
  const storage=exportStorage()
  if (!storage) return failed()
  try {
    const raw=await readBoundedText(request,27000)
    const input=raw && JSON.parse(raw)
    if (typeof input?.search==='string') {
      const query=input.search.trim().normalize('NFKC').toLowerCase()
      const before=input.before??null, beforeId=input.beforeId??null
      if (query.length<2 || query.length>120) return fileFailure(400,'Choose a valid channel search.')
      if (!validCursor(before,beforeId)) return fileFailure(400,'Choose a valid channel page.')
      return readPage(viewer,storage,channel.toLowerCase(),before,beforeId,query)
    }
    if (!validId(input?.id) || typeof input.body!=='string' || [...input.body.trim()].length>4000) {
      return fileFailure(400,'Enter a message between 1 and 4,000 characters.')
    }
    const id=input.id.toLowerCase()
    const scope=channel.toLowerCase()
    const plan=await viewer.client.rpc('st_v8_managed_channel_ticket',{
      p_channel:scope,p_purpose:'send',p_post:id,p_body:input.body,
    })
    if (plan.error) return actionError(plan.error)
    const data=plan.data
    if (data?.already_sent===true) return new Response(null,{status:204,headers:fileHeaders})
    if (!validId(data?.workspace) || !validId(data?.ticket) || typeof data.body!=='string') return failed()
    const params={p_ticket:data.ticket,p_actor:viewer.actor}
    let prepared=await storage.rpc('st_v8_channel_write_key',params)
    if (prepared.error || !prepared.data) return failed()
    if (prepared.data.version===null) {
      const newKey=await wrapFreshTenantKey(data.workspace,1,'managed')
      prepared=await storage.rpc('st_v8_channel_write_key',{...params,p_wrapped:newKey.wrapped})
    }
    const configured=prepared.data as TenantRecordKey | null
    if (prepared.error || !configured || configured.workspace!==data.workspace || !Number.isSafeInteger(configured.version)) return failed()
    const bytes=Buffer.from(data.body,'utf8')
    try {
      const encrypted=await sealTenantRecord(configured,scope,id,viewer.actor,bytes)
      const result=await storage.rpc('st_v8_finish_managed_channel_send',{
        ...params,p_version:configured.version,p_payload:encrypted,
      })
      if (result.error) return actionError(result.error)
      if (result.data!==true) return unavailable()
      return new Response(null,{status:204,headers:fileHeaders})
    } finally { bytes.fill(0) }
  } catch { return failed() }
}

export async function GET(request: Request, {params}: RequestContext) {
  const {channel}=await params
  if (!validId(channel)) return unavailable()
  const scope=channel.toLowerCase()
  const viewer=await operationalReportViewer(request)
  if (!viewer) return fileFailure(401,'Sign in to read messages.')
  const storage=exportStorage()
  if (!storage) return failed()
  const parameters=new URL(request.url).searchParams
  const before=parameters.get('before')
  const beforeId=parameters.get('beforeId')
  if (!validCursor(before,beforeId)) {
    return fileFailure(400,'Choose a valid channel page.')
  }
  return readPage(viewer,storage,scope,before,beforeId)
}

async function readPage(viewer: NonNullable<Awaited<ReturnType<typeof operationalReportViewer>>>,
  storage: NonNullable<ReturnType<typeof exportStorage>>,scope: string,before: string | null,beforeId: string | null,query?: string) {
  try {
    const permission=await viewer.client.rpc('st_v8_managed_channel_ticket',{p_channel:scope,p_purpose:'read'})
    if (permission.error) return actionError(permission.error)
    if (!validId(permission.data?.ticket)) return unavailable()
    const result=await storage.rpc('st_v8_read_managed_channel',{
      p_ticket:permission.data.ticket,p_actor:viewer.actor,p_before:before,p_before_id:beforeId,p_limit:searchBatch+1,
    })
    if (result.error || !Array.isArray(result.data) || result.data.length>100) return unavailable()
    const rows=result.data as Row[]
    const entries=await Promise.all((query ? rows.slice(0,searchBatch) : rows).map(async (row)=>{
      if (row.channel_id!==scope || !validId(row.id) || !validId(row.sender)) throw new Error('Invalid managed channel record')
      let body='Message quarantined'
      if (!row.quarantined_at) {
        const bytes=await openTenantRecord(row.key,scope,row.id,row.sender,row.envelope)
        try { body=new TextDecoder('utf-8',{fatal:true}).decode(bytes) }
        finally { bytes.fill(0) }
      }
      return { id:row.id,sender:row.sender,created_at:row.created_at,quarantined_at:row.quarantined_at,body }
    }))
    const current=await viewer.client.rpc('st_v8_managed_channel_still_readable',{p_channel:scope})
    if (current.error || current.data!==true) return unavailable()
    if (!query) return Response.json(entries,{headers:fileHeaders})
    const last=entries.at(-1)
    return Response.json({
      matches:entries.filter(entry=>!entry.quarantined_at&&entry.body.normalize('NFKC').toLowerCase().includes(query)),
      next:rows.length>searchBatch&&last ? {before:last.created_at,beforeId:last.id} : null,
    },{headers:fileHeaders})
  } catch { return failed() }
}
