import {
  emailHeaders, notificationDrainAuthorized, notificationEmailService, notificationSMTPConfiguration, notificationProviderFailure,
} from '../../../../lib/notification-email-server'
import { sendOperationalReport, type OperationalReportJob } from '../../../../lib/operational-report-server'
import { workerAcquisitionId } from '../../../../lib/worker-acquisition'
import { logProviderFailure } from '../../../../lib/provider-log.mjs'

export const runtime = 'nodejs'

function configuration() {
  const mail = notificationSMTPConfiguration()
  const service = notificationEmailService()
  const secret = process.env.SECTALK_REPORT_DRAIN_SECRET
  return mail && service && secret && Buffer.byteLength(secret) >= 32 ? {mail, service, secret} : null
}

export function GET() {
  return Response.json({available: Boolean(configuration())}, {headers: emailHeaders})
}

export async function POST(request: Request) {
  const config = configuration()
  if (!config) return new Response(null, {status: 503, headers: emailHeaders})
  if (!notificationDrainAuthorized(request, config.secret)) return new Response(null, {status: 401, headers: emailHeaders})
  const acquisition = workerAcquisitionId(request)
  if (!acquisition) return new Response(null, {status: 400, headers: emailHeaders})
  const claims = await config.service.rpc('st_v6_claim_operational_reports', {p_request: acquisition})
  if (claims.error) return new Response(null, {status: 503, headers: emailHeaders})
  const outcomes = await Promise.all((claims.data as OperationalReportJob[]).map(async job => {
    const lease = {p_run: job.id, p_lease: job.lease}
    const confirmed = await config.service.rpc('st_v6_confirm_operational_report', lease)
    if (confirmed.error) return {error: true, sent: false}
    let next: 'cancelled' | 'sent' | 'failed' | 'retry' = 'cancelled'
    if (confirmed.data === true) {
      try { next = await sendOperationalReport(config.mail, job) ? 'sent' : 'failed' }
      catch (error) {
        next = notificationProviderFailure(error) === 'rejected' ? 'failed' : 'retry'
        logProviderFailure('operational_report_email', 'unavailable')
      }
    }
    const settled = await config.service.rpc('st_v6_finish_operational_report', {...lease, p_state: next})
    return {error: Boolean(settled.error), sent: next === 'sent'}
  }))
  return Response.json({processed: outcomes.length, accepted: outcomes.filter(result => result.sent).length},
    {status: outcomes.some(result => result.error) ? 503 : 200, headers: emailHeaders})
}
