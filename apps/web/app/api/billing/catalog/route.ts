import { configuredCatalog, stripe } from '../../../../lib/stripe-server'

import { billingPortalConfigured } from '../../../../lib/stripe-portal'
import { razorpayOffers } from '../../../../lib/razorpay-billing'
import { billingTaxConfigured } from '../../../../lib/stripe-billing-tax'

export async function GET() {
  const headers = { 'Cache-Control': 'no-store' }
  try {
    const plans=await configuredCatalog()
    const taxConfigured=billingTaxConfigured()
    return Response.json({plans,checkoutAvailable:Boolean(stripe),portalConfigured:billingPortalConfigured(),
      razorpayOffers:taxConfigured?[]:razorpayOffers(plans),taxConfigured},{headers})
  } catch {
    return Response.json({ error: 'Billing catalog unavailable.' }, { headers, status: 503 })
  }
}
