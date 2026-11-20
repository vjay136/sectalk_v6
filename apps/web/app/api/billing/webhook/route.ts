import { withOperationalMetrics } from '../../../../lib/operational-metrics-server'
import type Stripe from 'stripe'
import { billingWriter, legacyOfferForPrice, stripe, webhookSecret } from '../../../../lib/stripe-server'

export const runtime = 'nodejs'

async function handlePost(request: Request) {
  if (!stripe || !webhookSecret || !billingWriter) return new Response('Billing unavailable', { status: 503 })
  const signature = request.headers.get('Stripe-Signature')
  if (!signature) return new Response('Missing signature', { status: 400 })
  let event: Stripe.Event
  try {
    event = stripe.webhooks.constructEvent(await request.text(), signature, webhookSecret)
  } catch {
    return new Response('Invalid signature', { status: 400 })
  }
  if (event.type !== 'customer.subscription.created' && event.type !== 'customer.subscription.updated' && event.type !== 'customer.subscription.deleted') {
    return new Response(null, { status: 204 })
  }
  try {
    const change = event.data.object
    const subscription = event.type === 'customer.subscription.deleted' ? change : await stripe.subscriptions.retrieve(change.id)
    const user = subscription.metadata.sectalk_user
    if (!user || !/^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/i.test(user)) return new Response(null, { status: 204 })
    const item = subscription.items.data[0]
    if (!item?.price.id || subscription.items.data.length !== 1 || item.price.unit_amount === null) {
      return new Response('Unsupported subscription price', { status: 422 })
    }
    const legacy = legacyOfferForPrice(item.price.id)
    const customer = typeof subscription.customer === 'string' ? subscription.customer : subscription.customer.id
    const { error } = await billingWriter.rpc('st_v6_sync_catalog_subscription', {
      p_event: event.id, p_user: user, p_customer: customer, p_subscription: subscription.id,
      p_provider_price: item.price.id, p_legacy_plan: legacy?.plan ?? null, p_legacy_cadence: legacy?.cadence ?? null,
      p_status: subscription.status, p_end: new Date(item.current_period_end * 1000).toISOString(),
      p_cancel: subscription.cancel_at_period_end, p_synced: new Date(event.created * 1000).toISOString(),
      p_currency: item.price.currency.toUpperCase(), p_amount: item.price.unit_amount,
    })
    if (error?.code === '22023') return new Response('Unsupported subscription price', { status: 422 })
    return error ? new Response('Subscription update failed', { status: 503 }) : new Response(null, { status: 204 })
  } catch {
    return new Response('Provider synchronization failed', { status: 503 })
  }
}

export async function POST(request: Request) {
  return withOperationalMetrics('billing_webhook', () => handlePost(request))
}
