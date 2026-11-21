import { fileHeaders } from '../../../../lib/authenticated-file-request'
import { exportStorage } from '../../../../lib/export-storage-server'
import { notificationDrainAuthorized } from '../../../../lib/notification-email-server'
import { wrapFreshTenantKey } from '../../../../lib/tenant-artifact-keys'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

type DueRotation = { workspace: string; version: number; revision: string }

export async function GET(request: Request) {
  const secret = process.env.CRON_SECRET
  if (!secret || Buffer.byteLength(secret) < 32) return new Response(null, { status: 503, headers: fileHeaders })
  if (!notificationDrainAuthorized(request,secret)) return new Response(null, { status: 401, headers: fileHeaders })
  const storage = exportStorage()
  if (!storage) return new Response(null, { status: 503, headers: fileHeaders })
  const due = await storage.rpc('st_v8_due_tenant_key_rotations')
  if (due.error || !Array.isArray(due.data)) return new Response(null, { status: 503, headers: fileHeaders })

  const results = await Promise.all((due.data as DueRotation[]).map(async job => {
    try {
      const key = await wrapFreshTenantKey(job.workspace,job.version+1,'managed')
      const activated = await storage.rpc('st_v8_commit_scheduled_tenant_key_rotation', {
        p_workspace:job.workspace,p_previous:job.version,p_revision:job.revision,p_wrapped:key.wrapped,
      })
      if (activated.error) return 'failed'
      return activated.data === true ? 'activated' : 'skipped'
    } catch {
      return 'failed'
    }
  }))
  const failed = results.filter(result => result === 'failed').length
  return Response.json({ processed:results.length,activated:results.filter(result => result === 'activated').length,failed },
    { status:failed ? 503 : 200,headers:fileHeaders })
}
