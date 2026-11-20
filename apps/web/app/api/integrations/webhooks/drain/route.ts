import { timingSafeEqual } from 'node:crypto'
import { integrationFailure, integrationHeaders, integrationsWriter } from '../../../../../lib/integration-server'
import { openWebhookSecret, resolveWebhook, sendWebhook, webhookUrl } from '../../../../../lib/webhook-transport'

export const runtime = 'nodejs'
export const maxDuration = 30

type Job = {
  id: string; workspace_id: string; endpoint_id: string; event_id: string
  payload: unknown; destination: string; wrapped_key: string; lease: string
}

const expected = process.env.SECTALK_WEBHOOK_DRAIN_SECRET ?? ''

async function processJob(job: Job) {
  const writer = integrationsWriter!
  const scope = { p_job: job.id, p_lease: job.lease }
  const lease = await writer.rpc('st_v6_webhook_lease_active', scope)
  if (lease.error) throw new Error('Webhook claim unavailable')
  if (lease.data !== true) return false

  let status: number | null = null
  let retry = false
  const url = webhookUrl(job.destination)
  let address: string | null = null
  if (url) {
    try { address = await resolveWebhook(url) }
    catch { retry = true }
  }
  if (url && address) {
    const current = await writer.rpc('st_v6_webhook_lease_active', scope)
    if (current.error) throw new Error('Webhook claim unavailable')
    if (current.data !== true) return false
    try {
      const secret = openWebhookSecret(job.wrapped_key, job.workspace_id, job.endpoint_id)
      status = await sendWebhook(url, address, secret, job.event_id, JSON.stringify(job.payload))
      retry = status === 408 || status === 429 || status >= 500
    } catch { retry = true }
  }
  const settled = await writer.rpc('st_v6_finish_webhook', { ...scope, p_status: status, p_retry: retry })
  if (settled.error) throw new Error('Webhook result unavailable')
  return status !== null && status >= 200 && status < 300
}

export async function POST(request: Request) {
  if (!integrationsWriter || Buffer.byteLength(expected) < 32) return integrationFailure(503, 'Webhook delivery is unavailable.')
  const received = Buffer.from(request.headers.get('Authorization') ?? '')
  const authorization = Buffer.from('Bearer ' + expected)
  if (received.length !== authorization.length || !timingSafeEqual(received, authorization)) {
    return integrationFailure(401, 'A webhook worker credential is required.')
  }
  const claimed = await integrationsWriter.rpc('st_v6_claim_webhooks')
  if (claimed.error || !Array.isArray(claimed.data)) return integrationFailure(503, 'Could not claim webhook deliveries.')
  const results = await Promise.allSettled((claimed.data as Job[]).map(processJob))
  const errors = results.filter(result => result.status === 'rejected').length
  return Response.json({ claimed: results.length, sent: results.filter(item => item.status === 'fulfilled' && item.value).length, errors },
    { status: errors ? 503 : 200, headers: integrationHeaders })
}
