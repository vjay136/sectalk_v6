import { dispatchAuthorized, pushConfiguration, pushHeaders, sendWebPush } from '../../../../lib/web-push-server'
import { workerAcquisitionId } from '../../../../lib/worker-acquisition'

export const runtime = 'nodejs'
type Job = {
  job: string; lease: string; endpoint: string | null; p256dh: string | null; auth_secret: string | null; ttl: number
  terminal: 'discard' | 'expired' | 'exhausted' | null
}

export async function POST(request: Request) {
  const configuration = pushConfiguration()
  if (!configuration) return new Response(null, { status: 503, headers: pushHeaders })
  if (!dispatchAuthorized(request, configuration.dispatchSecret)) return new Response(null, { status: 401, headers: pushHeaders })
  const acquisition = workerAcquisitionId(request)
  if (!acquisition) return new Response(null, { status: 400, headers: pushHeaders })
  const claimed = await configuration.service.rpc('st_v6_claim_web_push', { p_request: acquisition })
  if (claimed.error) return new Response(null, { status: 503, headers: pushHeaders })
  const jobs = claimed.data as Job[]
  const results = await Promise.all(jobs.map(async job => {
    const result = job.terminal ?? await sendWebPush({
      endpoint: job.endpoint, keys: { p256dh: job.p256dh, auth: job.auth_secret },
    }, job.ttl, configuration.vapid)
    return configuration.service.rpc('st_v6_finish_web_push', { p_job: job.job, p_lease: job.lease, p_result: result })
  }))
  return Response.json({ processed: results.filter(result => !result.error).length },
    { status: results.some(result => result.error) ? 503 : 200, headers: pushHeaders })
}
