import { version } from '../../../package.json'
import { withOperationalMetrics } from '../../../lib/operational-metrics-server'

export async function GET() {
  return withOperationalMetrics('health_read', async () => {
    const configured = Boolean(process.env.NEXT_PUBLIC_SUPABASE_URL && process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY)
    return Response.json({ status: configured ? 'configured' : 'configuration_required', version }, {
      status: configured ? 200 : 503,
      headers: { 'Cache-Control': 'no-store' },
    })
  })
}
