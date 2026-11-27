import { configuredCatalog, stripe } from '../../../../lib/stripe-server'

import { billingPortalConfigured } from '../../../../lib/stripe-portal'
import { razorpayOffers } from '../../../../lib/razorpay-billing'
import { billingTaxConfigured } from '../../../../lib/stripe-billing-tax'
import { billingMode } from '../../../../lib/billing-mode'

export async function GET() {
  const headers = { 'Cache-Control': 'no-store' }
  const mode = billingMode()
  try {
    const plans=await configuredCatalog()
    if (mode === 'free') {
      return Response.json({ billingMode: mode, plans: plans.filter(plan => plan.plan === 'free'),
        checkoutAvailable: false, portalConfigured: false, razorpayOffers: [], taxConfigured: false }, { headers })
    }
    const taxConfigured=billingTaxConfigured()
    return Response.json({billingMode:mode,plans,checkoutAvailable:Boolean(stripe),portalConfigured:billingPortalConfigured(),
      razorpayOffers:taxConfigured?[]:razorpayOffers(plans),taxConfigured},{headers})
  } catch {
    return Response.json({ error: 'Billing catalog unavailable.' }, { headers, status: 503 })
  }
}
