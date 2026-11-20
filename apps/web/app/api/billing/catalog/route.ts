import { configuredCatalog, stripe } from '../../../../lib/stripe-server'

import { billingPortalConfigured } from '../../../../lib/stripe-portal'

export async function GET() {
  const headers = { 'Cache-Control': 'no-store' }
  try {
    return Response.json({ plans: await configuredCatalog(), checkoutAvailable: Boolean(stripe), portalConfigured: billingPortalConfigured() }, { headers })
  } catch {
    return Response.json({ error: 'Billing catalog unavailable.' }, { headers, status: 503 })
  }
}
