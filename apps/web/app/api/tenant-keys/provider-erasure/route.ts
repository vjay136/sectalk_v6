import { fileFailure,fileHeaders } from '../../../../lib/authenticated-file-request'
import { exportIdPattern,exportStorage } from '../../../../lib/export-storage-server'
import { operationalReportViewer } from '../../../../lib/operational-report-server'
import { observeProviderErasure } from '../../../../lib/provider-key-erasure'
import { readBoundedText } from '../../../../lib/request-body'

export const runtime='nodejs'
export const dynamic='force-dynamic'

export async function POST(request:Request) {
  const viewer=await operationalReportViewer(request)
  if (!viewer) return fileFailure(401,'Sign in to verify provider key evidence.')
  const storage=exportStorage()
  if (!storage) return fileFailure(503,'Provider key evidence is unavailable.')
  let input
  try {
    const raw=await readBoundedText(request,256)
    if (raw===undefined) return fileFailure(413,'Provider evidence request is too large.')
    input=raw ? JSON.parse(raw) : null
  } catch { return fileFailure(400,'Choose an exact workspace and external key version.') }
  if (!input || typeof input.workspace!=='string' || !exportIdPattern.test(input.workspace) ||
    input.confirmation!==input.workspace.toLowerCase() || !Number.isSafeInteger(input.version) || input.version<1 || input.version>2147483647) {
    return fileFailure(400,'Choose an exact workspace and external key version.')
  }
  const workspace=input.workspace.toLowerCase()
  const result=await viewer.client.rpc('st_v8_begin_tenant_provider_erasure',{
    p_workspace:workspace,p_version:input.version,p_confirmation:input.confirmation,
  })
  if (result.error?.code==='42501') return fileFailure(403,'Fresh independent reviewer verification and clear holds are required.')
  if (result.error?.code==='PT409') return fileFailure(409,'Choose a pinned external key version.')
  if (!result.error && result.data?.verified===true) return Response.json({state:'deleted_event'},{headers:fileHeaders})
  const ticket=result.data
  if (result.error || !exportIdPattern.test(ticket?.ticket??'') || ticket.version!==input.version ||
    typeof ticket.reference!=='string' || typeof ticket.marker!=='string' || typeof ticket.stagedAt!=='string') {
    return fileFailure(503,'Provider key evidence is unavailable.')
  }
  const observed=await observeProviderErasure(workspace,ticket.version,ticket.reference,ticket.marker,ticket.stagedAt)
  if (observed.state==='deleted_event') {
    const saved=await storage.rpc('st_v8_commit_tenant_provider_erasure',{
      p_ticket:ticket.ticket,p_actor:viewer.actor,p_event:observed.event,p_event_time:observed.eventTime,p_sha256:observed.sha256,
    })
    if (saved.error || saved.data!==true) return fileFailure(409,'Workspace review changed. Refresh and verify again.')
  }
  return Response.json({state:observed.state},{headers:fileHeaders})
}
