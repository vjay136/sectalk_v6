import { emailHeaders } from '../../../../lib/notification-email-server'
import { operationalReportViewer } from '../../../../lib/operational-report-server'
import { securityReportCsv, securityReportPdf, type SecurityReport } from '../../../../lib/security-report-export'

export const runtime = 'nodejs'

export async function GET(request: Request) {
  const viewer = await operationalReportViewer(request)
  if (!viewer) return new Response(null, {status: 401, headers: emailHeaders})
  const query = new URL(request.url).searchParams
  const period = query.get('period')
  const format = query.get('format')
  if ((period !== 'daily' && period !== 'weekly') || (format !== 'csv' && format !== 'pdf')) {
    return new Response(null, {status: 400, headers: emailHeaders})
  }
  const result = await viewer.rpc('st_v6_security_report', {p_period: period})
  if (result.error || !result.data) {
    return new Response(null, {status: result.error?.code === '42501' ? 403 : 503, headers: emailHeaders})
  }
  const report = result.data as SecurityReport
  try {
    const body = format === 'pdf' ? Buffer.from(await securityReportPdf(report)) : securityReportCsv(report)
    return new Response(body, {headers: {
      ...emailHeaders, 'Content-Type': format === 'pdf' ? 'application/pdf' : 'text/csv; charset=utf-8',
      'Content-Disposition': 'attachment; filename="sectalk-security-report-' + period + '.' + format + '"',
    }})
  } catch { return new Response(null, {status: 503, headers: emailHeaders}) }
}
