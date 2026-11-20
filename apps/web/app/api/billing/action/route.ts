import { withOperationalMetrics } from '../../../../lib/operational-metrics-server'
import { billingIdentity, billingWriter, origin, priceId, stripe } from '../../../../lib/stripe-server'
import { isPaidPlan } from '../../../../lib/billing'

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
    if (payload?.action !== 'checkout' || !isPaidPlan(payload.plan) || (payload.cadence !== 'monthly' && payload.cadence !== 'annual')) {
      return Response.json({ error: 'Choose an available plan and billing interval.' }, { status: 400 })
    }
    const selected = priceId(payload.plan, payload.cadence)
    if (!selected) return Response.json({ error: 'This billing interval is unavailable.' }, { status: 422 })
    if (subscription && !['canceled','incomplete_expired','unpaid'].includes(subscription.status)) {
      return Response.json({ error: 'Manage your existing subscription in the billing portal.' }, { status: 409 })
    }

    const { data: lease, error: reserveError } = await billingWriter.rpc('st_v2_reserve_checkout', { p_user: user.id, p_price: selected })
    if (reserveError || !lease?.id) return Response.json({ error: 'An open checkout already exists for another plan. Try again after it expires.' }, { status: 409 })
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      client_reference_id: user.id,
      ...(subscription?.customer_id ? { customer: subscription.customer_id } : { customer_email: user.email }),
      line_items: [{ price: selected, quantity: 1 }],
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
