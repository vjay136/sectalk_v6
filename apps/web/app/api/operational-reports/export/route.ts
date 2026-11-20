import { emailHeaders } from '../../../../lib/notification-email-server'
import { operationalReportViewer, reportCsv, reportFilename, type OperationalReport } from '../../../../lib/operational-report-server'
import { saveExportResponse } from '../../../../lib/export-storage-server'

export const runtime = 'nodejs'
export const maxDuration = 30
const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i

export async function GET(request: Request) {
  const viewer = await operationalReportViewer(request)
  if (!viewer) return new Response(null, {status: 401, headers: emailHeaders})
  const proof=await viewer.client.rpc('st_v7_sensitive_action_status',{p_kind:'export'})
  if (proof.error||proof.data!=='verified') return new Response(null,{status:403,headers:emailHeaders})
  const run = new URL(request.url).searchParams.get('run')
  if (!run || !uuid.test(run)) return new Response(null, {status: 400, headers: emailHeaders})
  const result = await viewer.client.rpc('st_v6_operational_report_export', {p_run: run})
  if (result.error) return new Response(null, {status: result.error.code === '42501' ? 403 : 503, headers: emailHeaders})
  if (!result.data) return new Response(null, {status: 404, headers: emailHeaders})
  const report = result.data as OperationalReport
  try {
    return await saveExportResponse(viewer.actor, { kind: 'operations', scope_id: run },
      { filename: reportFilename(report), media_type: 'text/csv' }, reportCsv(report))
  } catch { return new Response(null, {status: 503, headers: emailHeaders}) }
}
