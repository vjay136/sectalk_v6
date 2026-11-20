import {billingWriter, stripe} from '../../../../lib/stripe-server'
import {stripeSubscriptionSnapshot} from '../../../../lib/stripe-reconciliation'
import {notificationDrainAuthorized} from '../../../../lib/notification-email-server'

export const runtime = 'nodejs'
export const maxDuration = 40
const headers = {'Cache-Control': 'no-store'}
type Candidate = {id: string; customer: string; user: string; lease: string}

export async function POST(request: Request) {
  const secret = process.env.SECTALK_STRIPE_RECONCILE_SECRET
  if (!stripe || !billingWriter || !secret || Buffer.byteLength(secret) < 32) return new Response(null, {status: 503, headers})
  if (!notificationDrainAuthorized(request, secret)) return new Response(null, {status: 401, headers})
  const provider = stripe
  const store = billingWriter
  const claims = await store.rpc('st_v7_stripe_reconcile_claim')
  if (claims.error) return new Response(null, {status: 503, headers})
  const outcomes = await Promise.all((claims.data as Candidate[]).map(async candidate => {
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
  return Response.json({processed: outcomes.length, synchronized: outcomes.filter(Boolean).length}, {headers})
}
