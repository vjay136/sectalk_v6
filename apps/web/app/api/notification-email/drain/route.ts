import {
  emailHeaders, notificationDrainAuthorized, notificationEmailService, notificationMailConfiguration,
  notificationProviderFailure, sendNotificationEmail,
  type NotificationEmail,
} from '../../../../lib/notification-email-server'
import { logProviderFailure } from '../../../../lib/provider-log.mjs'
import { workerAcquisitionId } from '../../../../lib/worker-acquisition'

export const runtime = 'nodejs'

export function GET() {
  return Response.json({ available: Boolean(notificationMailConfiguration() && notificationEmailService()) },
    { headers: emailHeaders })
}

export async function POST(request: Request) {
  const config = notificationMailConfiguration()
  const service = notificationEmailService()
  if (!config || !service) return new Response(null, { status: 503, headers: emailHeaders })
  if (!notificationDrainAuthorized(request, config.secret)) return new Response(null, { status: 401, headers: emailHeaders })
  const acquisition = workerAcquisitionId(request)
  if (!acquisition) return new Response(null, { status: 400, headers: emailHeaders })
  const jobs = await service.rpc('st_v6_claim_notification_email', { p_request: acquisition })
  if (jobs.error) return new Response(null, { status: 503, headers: emailHeaders })
  const results = await Promise.all((jobs.data as NotificationEmail[]).map(async job => {
    const lease = { p_recipient: job.recipient, p_lease: job.lease }
    const confirmed = await service.rpc('st_v6_confirm_notification_email', lease)
    if (confirmed.error) return { error: true, sent: false }
    let result: 'sent' | 'retry' | 'rejected' | 'discarded' = 'discarded'
    if (confirmed.data === true) {
      try { result = await sendNotificationEmail(config, job) ? 'sent' : 'rejected' }
      catch (error) {
        result = notificationProviderFailure(error)
        logProviderFailure('notification_email', 'unavailable')
      }
    }
    const settled = await service.rpc('st_v6_finish_notification_email', { ...lease, p_result: result })
    return { error: Boolean(settled.error), sent: result === 'sent' }
  }))
  return Response.json({ processed: results.length, accepted: results.filter(result => result.sent).length },
    { status: results.some(result => result.error) ? 503 : 200, headers: emailHeaders })
}
