import { fileFailure,fileHeaders } from '../../../../../lib/authenticated-file-request'
import { exportIdPattern,exportStorage } from '../../../../../lib/export-storage-server'
import { operationalReportViewer } from '../../../../../lib/operational-report-server'
import { readBoundedText } from '../../../../../lib/request-body'
import { openTenantRecord } from '../../../../../lib/tenant-artifact-keys'

export const runtime='nodejs'
const unavailable=()=>fileFailure(404,'Managed channel report unavailable.')
const failed=()=>fileFailure(503,'Could not capture the exact channel evidence.')
const id=(value: unknown): value is string=>typeof value==='string' && exportIdPattern.test(value)

export async function POST(request: Request,context: { params: Promise<{ channel: string }> }) {
  const {channel}=await context.params
  if (!id(channel)) return unavailable()
  const viewer=await operationalReportViewer(request)
  if (!viewer) return fileFailure(401,'Sign in to report this message.')
  const storage=exportStorage()
  if (!storage) return failed()
  let input
  try {
    const raw=await readBoundedText(request,10000)
    if (!raw) return fileFailure(400,'Choose a message, category, and consent.')
    input=JSON.parse(raw)
  } catch { return fileFailure(400,'Choose a message, category, and consent.') }
  if (!id(input?.post) || typeof input.category!=='string' || typeof input.details!=='string'
    || input.shareWithSafety!==true || typeof input.shareWithWorkspace!=='boolean') {
    return fileFailure(400,'Affirmative consent and report details are required.')
  }
  const scope=channel.toLowerCase(), post=input.post.toLowerCase()
  const plan=await viewer.client.rpc('st_v8_begin_managed_channel_report',{
    p_channel:scope,p_post:post,p_category:input.category,p_details:input.details,
    p_share_with_safety:input.shareWithSafety,p_share_with_workspace:input.shareWithWorkspace,
  })
  if (plan.error?.code==='42501') return unavailable()
  if (plan.error?.code==='22023') return fileFailure(400,plan.error.message)
  if (plan.error) return failed()
  if (id(plan.data?.report)) return Response.json({id:plan.data.report},{headers:fileHeaders})
  if (!id(plan.data?.ticket)) return failed()
  const payload={p_ticket:plan.data.ticket,p_actor:viewer.actor}
  try {
    const material=await storage.rpc('st_v8_load_managed_channel_report',payload)
    if (material.error) return failed()
    const source=material.data
    if (!source || source.channel!==scope || source.id!==post || !id(source.sender)) return unavailable()
    const bytes=await openTenantRecord(source.key,scope,post,source.sender,source.envelope)
    try {
      const evidence=new TextDecoder('utf-8',{fatal:true}).decode(bytes)
      const result=await storage.rpc('st_v8_finish_managed_channel_report',{...payload,p_evidence:evidence})
      if (result.error) return failed()
      if (!id(result.data)) return unavailable()
      return Response.json({id:result.data},{status:201,headers:fileHeaders})
    } finally { bytes.fill(0) }
  } catch { return failed() }
}
