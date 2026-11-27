import { after } from 'next/server'
import { authenticatePush, pushConfiguration, pushHeaders, pushInput, sendWebPush } from '../../../../lib/web-push-server'

export const runtime = 'nodejs'
export const maxDuration = 15

type CallPush = {
  job: string; lease: string; endpoint: string | null; p256dh: string | null; auth_secret: string | null; ttl: number
  terminal: 'discard' | 'expired' | 'exhausted' | null
}

const uuid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i
const response = (status: number) => new Response(null, { status, headers: pushHeaders })

export async function POST(request: Request) {
  const configuration = pushConfiguration()
  if (!configuration) return response(204)
  const identity = await authenticatePush(request, configuration)
  if (!identity) return response(401)
  const input = await pushInput(request)
  if (typeof input?.call !== 'string' || !uuid.test(input.call)) return response(400)
  const call = input.call
  after(async () => {
    const claimed = await configuration.service.rpc('st_v6_claim_incoming_call_push', { ...identity, p_call: call })
    if (claimed.error) return
    await Promise.all((claimed.data as CallPush[]).map(async job => {
      const result = job.terminal ?? await sendWebPush({
        endpoint: job.endpoint, keys: { p256dh: job.p256dh, auth: job.auth_secret },
      }, job.ttl, configuration.vapid, true)
      await configuration.service.rpc('st_v6_finish_web_push', { p_job: job.job, p_lease: job.lease, p_result: result })
    }))
  })
  return response(204)
}
