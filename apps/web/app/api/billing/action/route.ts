import { withOperationalMetrics } from '../../../../lib/operational-metrics-server'
import { billingIdentity, billingWriter, catalogPriceId, origin, stripe } from '../../../../lib/stripe-server'
import { isBillingCurrency, isPaidPlan } from '../../../../lib/billing'

async function handlePost(request: Request) {
  if (!stripe || !origin || !billingWriter) return Response.json({ error: 'Payment checkout is unavailable on this deployment.' }, { status: 503 })
  const identity = await billingIdentity(request)
  if (!identity) return Response.json({ error: 'Sign in first.' }, { status: 401 })
  const payload = await request.json().catch(() => null)
  const { user, client } = identity
  const { data: subscription, error } = await client.from('st_v2_subscriptions').select('customer_id,status').eq('user_id', user.id).maybeSingle()
  if (error) return Response.json({ error: 'Could not load your subscription.' }, { status: 503 })
  try {
    if (payload?.action === 'portal') {
      if (!subscription?.customer_id) return Response.json({ error: 'No billing account is linked yet.' }, { status: 404 })
      const session = await stripe.billingPortal.sessions.create({ customer: subscription.customer_id, return_url: origin })
      return Response.json({ url: session.url })
    }
    if (payload?.action !== 'checkout' || !isPaidPlan(payload.plan) || (payload.cadence !== 'monthly' && payload.cadence !== 'annual')
      || !isBillingCurrency(payload.currency) || !Number.isInteger(payload.version) || payload.version < 1 || payload.version > 2147483647) {
      return Response.json({ error: 'Choose an available plan, currency and billing interval.' }, { status: 400 })
    }
    const selected = await catalogPriceId(payload.plan, payload.cadence, payload.currency, payload.version)
    if (!selected) return Response.json({ error: 'This offer has changed or is unavailable. Refresh the plans and try again.' }, { status: 422 })
    if (subscription && !['canceled','incomplete_expired','unpaid'].includes(subscription.status)) {
      return Response.json({ error: 'Manage your existing subscription in the billing portal.' }, { status: 409 })
    }

    const providerPrice = await stripe.prices.retrieve(selected.id)
    if (!providerPrice.active || providerPrice.type !== 'recurring' || providerPrice.billing_scheme !== 'per_unit'
      || providerPrice.currency.toUpperCase() !== payload.currency || providerPrice.recurring?.interval_count !== 1
      || providerPrice.recurring.interval !== (payload.cadence === 'annual' ? 'year' : 'month')
      || providerPrice.recurring.usage_type !== 'licensed' || providerPrice.unit_amount === null
      || (selected.amount !== null && providerPrice.unit_amount !== selected.amount)) {
      return Response.json({ error: 'The payment provider has different terms for this offer.' }, { status: 422 })
    }
    const { data: lease, error: reserveError } = await billingWriter.rpc('st_v2_reserve_checkout', { p_user: user.id, p_price: selected.id })
    if (reserveError || !lease?.id) return Response.json({ error: 'An open checkout already exists for another plan. Try again after it expires.' }, { status: 409 })
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      currency: payload.currency.toLowerCase(),
      adaptive_pricing: { enabled: false },
      client_reference_id: user.id,
      ...(subscription?.customer_id ? { customer: subscription.customer_id } : { customer_email: user.email }),
      line_items: [{ price: selected.id, quantity: 1 }],
      allow_promotion_codes: true,
      subscription_data: { metadata: { sectalk_user: user.id } },
      success_url: origin + '/?billing=success',
      cancel_url: origin + '/?billing=cancel',
      expires_at: lease.expires_epoch,
    }, { idempotencyKey: 'sectalk-checkout-' + lease.id })
    if (!session.url) return Response.json({ error: 'Checkout has already closed.' }, { status: 409 })
    return Response.json({ url: session.url })
  } catch {
    return Response.json({ error: 'The payment provider could not process this request.' }, { status: 502 })
  }
}

export async function POST(request: Request) {
  return withOperationalMetrics('billing_action', () => handlePost(request))
}
