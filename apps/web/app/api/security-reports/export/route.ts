import { emailHeaders } from '../../../../lib/notification-email-server'
import { operationalReportViewer } from '../../../../lib/operational-report-server'
import { securityReportCsv, securityReportPdf, type SecurityReport } from '../../../../lib/security-report-export'
import { saveExportResponse } from '../../../../lib/export-storage-server'

export const runtime = 'nodejs'
export const maxDuration = 30

export async function GET(request: Request) {
  const viewer = await operationalReportViewer(request)
  if (!viewer) return new Response(null, {status: 401, headers: emailHeaders})
  const query = new URL(request.url).searchParams
  const period = query.get('period')
  const format = query.get('format')
  if ((period !== 'daily' && period !== 'weekly') || (format !== 'csv' && format !== 'pdf')) {
    return new Response(null, {status: 400, headers: emailHeaders})
  }
  const result = await viewer.client.rpc('st_v6_security_report', {p_period: period})
  if (result.error || !result.data) {
    return new Response(null, {status: result.error?.code === '42501' ? 403 : 503, headers: emailHeaders})
  }
  const report = result.data as SecurityReport
  try {
    const body = format === 'pdf' ? Buffer.from(await securityReportPdf(report)) : securityReportCsv(report)
    const response = await saveExportResponse(viewer.actor, { kind: 'security', period },
      { filename: 'sectalk-security-report-' + period + '.' + format, media_type: format === 'pdf' ? 'application/pdf' : 'text/csv' },
      body)
    if (format === 'pdf' && request.headers.get('Accept') === 'application/octet-stream') {
      response.headers.set('Content-Type', 'application/octet-stream')
      response.headers.delete('Content-Disposition')
    }
    return response
  } catch { return new Response(null, {status: 503, headers: emailHeaders}) }
}
