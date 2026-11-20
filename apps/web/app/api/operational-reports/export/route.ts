import { emailHeaders } from '../../../../lib/notification-email-server'
import { operationalReportViewer, reportCsv, reportFilename, type OperationalReport } from '../../../../lib/operational-report-server'

export const runtime = 'nodejs'
const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i

export async function GET(request: Request) {
  const viewer = await operationalReportViewer(request)
  if (!viewer) return new Response(null, {status: 401, headers: emailHeaders})
  const run = new URL(request.url).searchParams.get('run')
  if (!run || !uuid.test(run)) return new Response(null, {status: 400, headers: emailHeaders})
  const result = await viewer.rpc('st_v6_operational_report_export', {p_run: run})
  if (result.error) return new Response(null, {status: result.error.code === '42501' ? 403 : 503, headers: emailHeaders})
  if (!result.data) return new Response(null, {status: 404, headers: emailHeaders})
  const report = result.data as OperationalReport
  try {
    return new Response(reportCsv(report), {headers: {
      ...emailHeaders, 'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': 'attachment; filename="' + reportFilename(report) + '"',
    }})
  } catch { return new Response(null, {status: 503, headers: emailHeaders}) }
}
