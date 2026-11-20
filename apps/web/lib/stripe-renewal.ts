import type Stripe from 'stripe'
import {stripeLiveMode} from './stripe-server'

const stripeObject = (value: string | {id:string} | null | undefined) => typeof value==='string' ? value : value?.id

export function stripeRenewalSnapshot(invoice: Stripe.Invoice) {
  const customer = stripeObject(invoice.customer)
  const subscription = stripeObject(invoice.parent?.subscription_details?.subscription)
  if (invoice.billing_reason!=='subscription_cycle' || invoice.collection_method!=='charge_automatically'
    || invoice.livemode!==stripeLiveMode || invoice.on_behalf_of || !customer?.startsWith('cus_')
    || !subscription?.startsWith('sub_') || !invoice.status_transitions?.finalized_at) return null
  const stage = invoice.status==='paid' ? 'paid' : invoice.status==='void'||invoice.status==='uncollectible'
    ? 'closed' : invoice.status==='open' && invoice.attempted && invoice.amount_remaining>0 ? 'open' : null
  if (!stage) return null
  const retry = invoice.next_payment_attempt
  return {customer,subscription,stage,attempt:invoice.attempt_count,
    retry_at:typeof retry==='number'&&Number.isSafeInteger(retry)&&retry>0&&retry<253402300800
      ? new Date(retry*1000).toISOString() : null}
}
