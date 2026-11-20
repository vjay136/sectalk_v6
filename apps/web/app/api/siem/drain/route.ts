import { createClient } from '@supabase/supabase-js'
import { notificationDrainAuthorized } from '../../../../lib/notification-email-server'
import { deliverSiem, siemConnectors, siemEnvelope, signingKey, type Batch } from '../../../../lib/siem-export-server'

export const runtime = 'nodejs'
export const maxDuration = 30
const headers = {'Cache-Control': 'no-store'}

export async function POST(request: Request) {
  const secret = process.env.SECTALK_SIEM_DRAIN_SECRET
  const serviceKey = process.env.SECTALK_SIEM_SERVICE_KEY
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL
  if (!secret || Buffer.byteLength(secret) < 32 || !serviceKey || !url) return new Response(null, {status: 503, headers})
  if (!notificationDrainAuthorized(request, secret)) return new Response(null, {status: 401, headers})
  try {
    const connectors = siemConnectors()
    const key = signingKey()
    const client = createClient(url, serviceKey, {auth: {persistSession: false, autoRefreshToken: false}})
    const results = await Promise.all(connectors.map(async connector => {
      const {data, error} = await client.rpc('st_v7_siem_claim', {p_workspace: connector.workspace, p_channel: connector.channel})
      if (error) return {error: true, sent: false}
      if (!data) return {error: false, sent: false}
      const batch = data as Batch
      let state: 'sent' | 'retry' | 'failed' = 'retry'
      try { state = await deliverSiem(connector, batch, siemEnvelope(batch, key)) }
      catch { /* The provider can be unavailable without exposing credentials or destinations. */ }
      const completion = await client.rpc('st_v7_siem_finish', {p_batch: batch.id, p_channel: connector.channel,
        p_lease: batch.lease, p_result: state})
      return {error: Boolean(completion.error) || completion.data !== true, sent: state === 'sent' && completion.data === true}
    }))
    return Response.json({accepted: results.filter(value => value.sent).length},
      {headers, status: results.some(value => value.error) ? 503 : 200})
  } catch { return new Response(null, {status: 503, headers}) }
}
