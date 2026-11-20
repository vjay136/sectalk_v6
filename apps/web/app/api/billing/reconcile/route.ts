import {billingWriter, stripe} from '../../../../lib/stripe-server'
import {couponCheckoutSnapshot} from '../../../../lib/stripe-coupon'
import {stripeRenewalSnapshot} from '../../../../lib/stripe-renewal'
import {stripeSubscriptionSnapshot} from '../../../../lib/stripe-reconciliation'
import {notificationDrainAuthorized} from '../../../../lib/notification-email-server'

export const runtime = 'nodejs'
export const maxDuration = 40
const headers = {'Cache-Control': 'no-store'}
type Candidate = {id: string; customer: string; user: string; lease: string}
type Probe = {invoice:string; customer:string; subscription:string; probe_at:string}

export async function POST(request: Request) {
  const secret = process.env.SECTALK_STRIPE_RECONCILE_SECRET
  if (!stripe || !billingWriter || !secret || Buffer.byteLength(secret) < 32) return new Response(null, {status: 503, headers})
  if (!notificationDrainAuthorized(request, secret)) return new Response(null, {status: 401, headers})
  const provider = stripe
  const store = billingWriter
  const [claims,probes,coupons] = await Promise.all([
    store.rpc('st_v7_stripe_reconcile_claim'), store.rpc('st_v7_renewal_probe_claim'), store.rpc('st_v7_coupon_probe_claim'),
  ])
  if (claims.error || probes.error || coupons.error) return new Response(null, {status: 503, headers})
  const subscriptions = Promise.all((claims.data as Candidate[]).map(async candidate => {
    let snapshot = null
    try {
      const subscription = await provider.subscriptions.retrieve(candidate.id)
      const current = stripeSubscriptionSnapshot(subscription)
      if (current?.subscription === candidate.id && current.customer === candidate.customer && current.user === candidate.user) snapshot = current
    } catch { /* The next worker pass retries unavailable provider state. */ }
    const args = {p_subscription: candidate.id, p_lease: candidate.lease}
    const result = await store.rpc('st_v7_stripe_reconcile_finish', {...args, p_payload: snapshot})
    if (result.error) await store.rpc('st_v7_stripe_reconcile_finish', args)
    return result.data === true
  }))
  const renewals = Promise.allSettled((probes.data as Probe[]).map(async probe => {
    const invoice = await provider.invoices.retrieve(probe.invoice)
    const snapshot = stripeRenewalSnapshot(invoice)
    if (invoice.id !== probe.invoice || snapshot?.customer !== probe.customer || snapshot.subscription !== probe.subscription) return
    let providerSubscription = null
    if (snapshot.stage !== 'open') {
      const current = stripeSubscriptionSnapshot(await provider.subscriptions.retrieve(probe.subscription))
      if (current?.subscription === probe.subscription && current.customer === probe.customer) providerSubscription = current
    }
    await store.rpc('st_v7_renewal_probe_finish',{p_invoice:probe.invoice,p_probe_at:probe.probe_at,
      p_payload:{...snapshot, provider_subscription:providerSubscription}})
  }))
  const discounts=Promise.allSettled((coupons.data as {id:string;provider_session:string}[]).map(async lease=>{
    const session=await provider.checkout.sessions.retrieve(lease.provider_session,{expand:['line_items']})
    const snapshot=couponCheckoutSnapshot(session)
    if (session.id===lease.provider_session && snapshot?.hold===lease.id)
      await store.rpc('st_v7_coupon_probe_finish',{p_session:session.id,p_payload:snapshot})
  }))
  const [outcomes] = await Promise.all([subscriptions,renewals,discounts])
  return Response.json({processed: outcomes.length, synchronized: outcomes.filter(Boolean).length}, {headers})
}
