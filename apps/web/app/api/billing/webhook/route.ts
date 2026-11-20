import { createHash } from 'node:crypto'
import { withOperationalMetrics } from '../../../../lib/operational-metrics-server'
import type Stripe from 'stripe'
import { billingWriter, stripe, stripeLiveMode, webhookSecret } from '../../../../lib/stripe-server'
import { stripeBillingUuid, stripeSubscriptionSnapshot } from '../../../../lib/stripe-reconciliation'
import { couponCheckoutSnapshot } from '../../../../lib/stripe-coupon'
import { stripeRenewalSnapshot } from '../../../../lib/stripe-renewal'
import { renewWorkspaceSeats } from '../../../../lib/stripe-workspace-seats'
import { reconcileInvoiceAdjustmentEvent } from '../../../../lib/stripe-invoice-adjustments'
import { razorpayWebhook } from '../../../../lib/razorpay-billing'
import { readBoundedBody } from '../../../../lib/request-body'

export const runtime = 'nodejs'
const headers = {'Cache-Control': 'no-store'}
const reply = (status: number) => new Response(null, {status, headers})
const id = /^(?:evt|sub|cs|seti|in)_[a-zA-Z0-9_]{1,100}$/

async function handlePost(request: Request) {
  const razorpaySignature=request.headers.get('X-Razorpay-Signature')
  if (razorpaySignature!==null) {
    if (request.headers.has('Stripe-Signature')) return reply(400)
    return razorpayWebhook(request,razorpaySignature)
  }
  if (!stripe || !webhookSecret || !billingWriter) return reply(503)
  const signature = request.headers.get('Stripe-Signature')
  if (!signature) return reply(400)
  let event: Stripe.Event
  let payload: Buffer
  try {
    const body = await readBoundedBody(request, 1024 * 1024)
    if (body === undefined) return reply(413)
    if (!body?.length) return reply(400)
    payload = body
    event = stripe.webhooks.constructEvent(payload, signature, webhookSecret)
  } catch { return reply(400) }

  const data = event.data?.object
  if (!data || typeof data !== 'object' || event.account
    || (typeof event.livemode === 'boolean' && event.livemode !== stripeLiveMode)) return reply(400)
  const adjustmentStatus=await reconcileInvoiceAdjustmentEvent(event.type,'id' in data?data.id:null)
  if (adjustmentStatus!==null) return reply(adjustmentStatus)
  let kind: 'subscription' | 'subscription_deleted' | 'trial' | 'invoice_renewal' | 'coupon_checkout'
  let reservation: string | undefined
  let trial: Stripe.Checkout.Session | undefined
  switch (event.type) {
    case 'checkout.session.completed': {
      if (event.data.object.mode==='subscription' && event.data.object.metadata?.sectalk_coupon_hold) {
        kind='coupon_checkout'
        break
      }
      trial = event.data.object
      reservation = trial.metadata?.sectalk_workspace_trial
      if (trial.mode !== 'setup' || trial.status !== 'complete' || typeof trial.setup_intent !== 'string'
        || !trial.setup_intent.startsWith('seti_') || !id.test(trial.setup_intent)
        || !reservation || reservation !== trial.client_reference_id || !stripeBillingUuid.test(reservation)) return reply(204)
      kind = 'trial'
      break
    }
    case 'checkout.session.expired':
    case 'checkout.session.async_payment_succeeded':
      if (!event.data.object.metadata?.sectalk_coupon_hold) return reply(204)
      kind='coupon_checkout'
      break
    case 'invoice.payment_failed':
    case 'invoice.paid':
    case 'invoice.payment_succeeded':
    case 'invoice.voided':
    case 'invoice.marked_uncollectible':
    case 'invoice.updated':
      kind = 'invoice_renewal'
      break
    case 'customer.subscription.created':
    case 'customer.subscription.updated':
    case 'customer.subscription.pending_update_applied':
    case 'customer.subscription.pending_update_expired':
    case 'customer.subscription.paused':
    case 'customer.subscription.resumed':
      kind = 'subscription'
      break
    case 'customer.subscription.deleted':
      kind = 'subscription_deleted'
      break
    default: return reply(204)
  }
  const resource = data && 'id' in data ? data.id : null
  if (!event.id?.startsWith('evt_') || !id.test(event.id) || !resource || !id.test(resource)
    || !(resource.startsWith(kind === 'trial' || kind === 'coupon_checkout' ? 'cs_' : kind === 'invoice_renewal' ? 'in_' : 'sub_'))
    || !Number.isSafeInteger(event.created) || event.created <= 0 || event.created > Date.now() / 1000 + 300) return reply(400)

  const claim = await billingWriter.rpc('st_v7_stripe_claim', {p_event: event.id,
    p_hash: createHash('sha256').update(payload).digest('hex'), p_kind: kind, p_resource: resource,
    p_event_at: new Date(event.created * 1000).toISOString()})
  if (claim.error) return reply(503)
  const state = claim.data?.state
  if (state === 'done') return reply(204)
  if (state === 'conflict' || state === 'invalid') return reply(400)
  if (state !== 'claimed' || typeof claim.data.lease !== 'string') return reply(503)
  const store = billingWriter
  async function finish(outcome: 'apply' | 'ignore' | 'retry', values?: object) {
    const result = await store.rpc('st_v7_stripe_finish', {p_event: event.id, p_lease: claim.data.lease,
      p_outcome: outcome, p_payload: values ?? null})
    return result
  }

  try {
    if (trial) {
      const setup = await stripe.setupIntents.retrieve(trial.setup_intent as string)
      const setupCustomer = typeof setup.customer === 'string' ? setup.customer : setup.customer?.id
      const trialCustomer = typeof trial.customer === 'string' ? trial.customer : trial.customer?.id
      if (setup.status !== 'succeeded' || !setup.payment_method || !setup.payment_method_types.includes('card')
        || setupCustomer !== trialCustomer) {
        await finish('retry')
        return reply(422)
      }
      const result = await finish('apply', {reservation})
      return reply(!result.error && result.data === true ? 204 : 503)
    }
    if (kind === 'coupon_checkout') {
      const current=await stripe.checkout.sessions.retrieve(resource,{expand:['line_items']})
      if(current.id!==resource) throw new Error('Checkout identity changed')
      const snapshot=couponCheckoutSnapshot(current)
      const result=snapshot ? await finish('apply',snapshot) : await finish('ignore')
      if (!result.error && result.data===true) return reply(204)
      await finish('retry')
      return reply(503)
    }
    if (kind === 'invoice_renewal') {
      const invoice = await stripe.invoices.retrieve(resource)
      if (invoice.id !== resource) throw new Error('Invoice identity changed')
      const renewal = stripeRenewalSnapshot(invoice)
      let providerSubscription = null
      if (renewal) {
        const current = await stripe.subscriptions.retrieve(renewal.subscription)
        const seatRenewal=await renewWorkspaceSeats(current,renewal.stage==='paid'&&current.id===renewal.subscription
          && (typeof current.customer==='string'?current.customer:current.customer.id)===renewal.customer?invoice.id:null)
        if (seatRenewal!==null) {
          const result=await finish(seatRenewal?'ignore':'retry')
          return reply(seatRenewal&&!result.error&&result.data===true?204:503)
        }
        const snapshot = stripeSubscriptionSnapshot(current)
        if (snapshot?.customer === renewal.customer && snapshot.subscription === renewal.subscription) providerSubscription = snapshot
      }
      const result = renewal ? await finish('apply',{...renewal, provider_subscription:providerSubscription,
        new_failure:event.type==='invoice.payment_failed'}) : await finish('ignore')
      if (!result.error && result.data === true) return reply(204)
      await finish('retry')
      return reply(503)
    }
    const subscription = await stripe.subscriptions.retrieve(resource)
    if (subscription.id !== resource) throw new Error('Subscription identity changed')
    const seatRenewal=await renewWorkspaceSeats(subscription)
    if (seatRenewal!==null) {
      const result=await finish(seatRenewal?'ignore':'retry')
      return reply(seatRenewal&&!result.error&&result.data===true?204:503)
    }
    const snapshot = stripeSubscriptionSnapshot(subscription)
    const result = await finish(snapshot ? 'apply' : 'ignore', snapshot ?? undefined)
    if (!result.error && result.data === true) return reply(204)
    await finish('retry')
    return reply(result.error?.code === '22023' ? 422 : 503)
  } catch {
    await finish('retry')
    return reply(503)
  }
}

export async function POST(request: Request) {
  return withOperationalMetrics('billing_webhook', () => handlePost(request))
}
