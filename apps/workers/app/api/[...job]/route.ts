import { POST as reconcileBilling } from '../../../../web/app/api/billing/reconcile/route'
import { POST as sendRenewalMail } from '../../../../web/app/api/billing/renewal-mail/route'
import { POST as purgeExports } from '../../../../web/app/api/exports/purge/route'
import { POST as purgeFiles } from '../../../../web/app/api/files/purge/route'
import { POST as purgeGroupFiles } from '../../../../web/app/api/group-files/purge/route'
import { POST as drainWebhooks } from '../../../../web/app/api/integrations/webhooks/drain/route'
import { POST as drainNotificationEmail } from '../../../../web/app/api/notification-email/drain/route'
import { POST as drainReports } from '../../../../web/app/api/operational-reports/drain/route'
import { POST as dispatchPush } from '../../../../web/app/api/push/dispatch/route'
import { POST as drainSiem } from '../../../../web/app/api/siem/drain/route'
import { POST as rewrapManagedChannelKeys } from '../../../../web/app/api/tenant-keys/rewrap/route'
import { GET as rotateDueTenantKeys } from '../../../../web/app/api/tenant-keys/rotate-due/route'
import { POST as maintainWorkspaceFiles } from '../../../../web/app/api/workspace-files/maintenance/route'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'
export const maxDuration = 60

type JobHandler = (request: Request) => Response | Promise<Response>
type JobContext = { params: Promise<{ job: string[] }> }
const handlers = new Map<string, JobHandler>([
  ['POST billing/reconcile', reconcileBilling],
  ['POST billing/renewal-mail', sendRenewalMail],
  ['POST exports/purge', purgeExports],
  ['POST files/purge', purgeFiles],
  ['POST group-files/purge', purgeGroupFiles],
  ['POST integrations/webhooks/drain', drainWebhooks],
  ['POST notification-email/drain', drainNotificationEmail],
  ['POST operational-reports/drain', drainReports],
  ['POST push/dispatch', dispatchPush],
  ['POST siem/drain', drainSiem],
  ['POST tenant-keys/rewrap', rewrapManagedChannelKeys],
  ['GET tenant-keys/rotate-due', rotateDueTenantKeys],
  ['POST workspace-files/maintenance', maintainWorkspaceFiles],
])

async function dispatch(request: Request, context: JobContext) {
  const { job } = await context.params
  const handler = handlers.get(`${request.method} ${job.join('/')}`)
  if (!handler) return new Response(null, { status:404, headers:{ 'Cache-Control':'no-store' } })
  return handler(request)
}

export const GET = dispatch
export const POST = dispatch
