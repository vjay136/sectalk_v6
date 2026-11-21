import { readBoundedText } from '../../../lib/request-body'
import { fileFailure, fileHeaders } from '../../../lib/authenticated-file-request'
import { exportIdPattern, exportStorage } from '../../../lib/export-storage-server'
import { operationalReportViewer } from '../../../lib/operational-report-server'
import { wrapFreshTenantKey } from '../../../lib/tenant-artifact-keys'

export const runtime='nodejs'

export async function POST(request: Request) {
  const viewer=await operationalReportViewer(request)
  if (!viewer) return fileFailure(401,'Sign in to manage workspace keys.')
  const storage=exportStorage()
  if (!storage) return fileFailure(503,'Workspace key custody is unavailable.')
  let input
  try {
    const body=await readBoundedText(request,2048)
    if (!body) return fileFailure(400,'Choose a workspace, custody mode and reason.')
    input=JSON.parse(body)
  } catch { return fileFailure(400,'Choose a workspace, custody mode and reason.') }
  if (typeof input?.workspace!=='string' || !exportIdPattern.test(input.workspace)
    || (input.custody!=='managed' && input.custody!=='byok') || typeof input.reason!=='string'
    || [...input.reason.trim()].length<15 || [...input.reason.trim()].length>240) {
    return fileFailure(400,'Choose a workspace, custody mode and reason.')
  }
  const workspace=input.workspace.toLowerCase()
  const started=await viewer.client.rpc('st_v7_begin_tenant_key_rotation',{
    p_workspace:workspace,p_custody:input.custody,p_reason:input.reason,
  })
  if (started.error?.code==='42501') return fileFailure(403,'Fresh workspace owner verification is required.')
  if (started.error?.code==='PT409') return fileFailure(409,'The workspace key state has changed.')
  if (started.error || !exportIdPattern.test(started.data?.ticket ?? '') || !Number.isSafeInteger(started.data?.version)
    || started.data.version<1) return fileFailure(503,'Could not reserve a workspace key version.')
  try {
    const key=await wrapFreshTenantKey(workspace,started.data.version,input.custody)
    const committed=await storage.rpc('st_v7_commit_tenant_key_rotation',{
      p_ticket:started.data.ticket,p_actor:viewer.actor,p_wrapped:key.wrapped,p_ref:key.ref,
    })
    if (committed.error) return fileFailure(503,'Could not activate the workspace key.')
    if (committed.data!==true) return fileFailure(409,'Verify your session and refresh the key state.')
    return Response.json({ version:started.data.version },{headers:fileHeaders})
  } catch {
    return fileFailure(503,'The configured key custody service is unavailable.')
  }
}
