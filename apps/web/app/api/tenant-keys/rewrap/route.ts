import { fileHeaders } from '../../../../lib/authenticated-file-request'
import { exportStorage } from '../../../../lib/export-storage-server'
import { notificationDrainAuthorized } from '../../../../lib/notification-email-server'
import { readBoundedText } from '../../../../lib/request-body'
import { rewrapManagedTenantRecord, type TenantRecordEnvelope, type TenantRecordKey } from '../../../../lib/tenant-artifact-keys'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

type RewrapJob = { workspace: string; post: string; channel?: string; room?: string; actor: string; policy_revision: string;
  source_revision: string; source_key: TenantRecordKey; target_key: TenantRecordKey; payload: TenantRecordEnvelope }
const validId=(value:unknown):value is string=>typeof value==='string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value)

export async function POST(request: Request) {
  const secret = process.env.SECTALK_DEK_REWRAP_SECRET
  if (!secret || Buffer.byteLength(secret)<32) return new Response(null,{status:503,headers:fileHeaders})
  if (!notificationDrainAuthorized(request,secret)) return new Response(null,{status:401,headers:fileHeaders})
  let data: {workspace?:unknown;kind?:unknown;after?:{post?:unknown;room?:unknown}|null}|null
  try {
    const raw=await readBoundedText(request,256)
    if (raw===undefined) return new Response(null,{status:413,headers:fileHeaders})
    data=raw===null ? null : JSON.parse(raw)
  } catch { return new Response(null,{status:400,headers:fileHeaders}) }
  const {workspace,kind='channel',after}=data??{}
  if (!validId(workspace) || (kind!=='channel' && kind!=='room') ||
    (after!==undefined && (!after || !validId(after.post) || (kind==='room' ? !validId(after.room) : after.room!==undefined)))) {
    return new Response(null,{status:400,headers:fileHeaders})
  }
  const storage=exportStorage()
  if (!storage) return new Response(null,{status:503,headers:fileHeaders})
  const due=kind==='room' ? await storage.rpc('st_v8_due_managed_room_rewrap',{
    p_workspace:workspace,p_after_room:after?.room??null,p_after_post:after?.post??null,
  }) : after ? await storage.rpc('st_v8_due_managed_channel_rewrap_after',{
    p_workspace:workspace,p_after_post:after.post,
  }) : await storage.rpc('st_v8_due_managed_channel_rewrap',{p_workspace:workspace})
  if (due.error || !Array.isArray(due.data) || due.data.length>16) return new Response(null,{status:503,headers:fileHeaders})

  let rewrapped=0, failed=0
  const jobs=due.data as RewrapJob[]
  for (const job of jobs) {
    try {
      const scope=kind==='room' ? job.room : job.channel
      if (!validId(scope) || job.workspace.toLowerCase()!==workspace.toLowerCase()) throw new Error('Invalid rewrap job scope')
      const capsule=await rewrapManagedTenantRecord(job.source_key,job.target_key,kind==='room' ? 'room:'+scope : scope,
        job.post,job.actor,job.payload)
      const commit={
        p_workspace:job.workspace,p_post:job.post,p_policy_revision:job.policy_revision,p_source_revision:job.source_revision,
        p_previous:job.source_key.version,p_target:job.target_key.version,p_wrapped_dek:capsule,
      }
      const result=kind==='room' ? await storage.rpc('st_v8_commit_managed_room_rewrap',{...commit,p_room:scope}) :
        await storage.rpc('st_v8_commit_managed_channel_rewrap',commit)
      if (result.error) failed++
      else if (result.data===true) rewrapped++
    } catch {
      failed++
    }
  }
  const last=jobs.at(-1)
  const next=last && (jobs.length===16 || failed>0) ? {post:last.post,...(kind==='room' ? {room:last.room} : {})} : undefined
  return Response.json({processed:jobs.length,rewrapped,failed,next},{status:failed ? 503 : 200,headers:fileHeaders})
}
