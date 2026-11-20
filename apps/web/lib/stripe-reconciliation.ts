import type Stripe from 'stripe'
import {legacyOfferForPrice} from './stripe-server'

export const stripeBillingUuid = /^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/i

export function stripeSubscriptionSnapshot(subscription: Stripe.Subscription) {
  const user = subscription.metadata?.sectalk_user
  if (!user || !stripeBillingUuid.test(user)) return null
  const item = subscription.items?.data?.[0]
  const customer = typeof subscription.customer === 'string' ? subscription.customer : subscription.customer?.id
  if (!customer?.startsWith('cus_') || !item?.price?.id || subscription.items.data.length !== 1
    || item.price.unit_amount == null || !Number.isSafeInteger(item.current_period_end) || item.current_period_end <= 0) {
    throw new Error('Unsupported subscription terms')
  }
  const legacy = legacyOfferForPrice(item.price.id)
  return {user, customer, subscription: subscription.id, price: item.price.id, legacy_plan: legacy?.plan ?? null,
    legacy_cadence: legacy?.cadence ?? null, status: subscription.status,
    cancellation_reason: subscription.cancellation_details?.reason ?? null,
    period_end: new Date(item.current_period_end * 1000).toISOString(), cancel: subscription.cancel_at_period_end,
    currency: item.price.currency.toUpperCase(), amount: item.price.unit_amount}
}
