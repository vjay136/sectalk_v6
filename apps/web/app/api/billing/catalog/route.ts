import { configuredPlans } from '../../../../lib/stripe-server'

export function GET() {
  return Response.json({ plans: configuredPlans() }, { headers: { 'Cache-Control': 'no-store' } })
}
