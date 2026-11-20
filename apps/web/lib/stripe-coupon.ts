import type Stripe from 'stripe'
import {stripeLiveMode} from './stripe-server'
import {stripeBillingUuid} from './stripe-reconciliation'

export type CouponQuote={coupon:string; revision:number; duration:'once'|'repeating'|'forever'; months:number|null;
  percent_bps:number|null; amount_off:number|null; max_redemptions:number; ends_at:string}
export const couponCodePattern=/^[A-Z0-9-]{4,40}$/
const ref=(value:string|{id:string}|null|undefined)=>typeof value==='string'?value:value?.id

export function matchesCoupon(terms:CouponQuote,coupon:Stripe.Coupon,price:Stripe.Price,currency:string) {
  if (coupon.id!==terms.coupon || coupon.livemode!==stripeLiveMode || !coupon.valid
    || coupon.duration!==terms.duration || (coupon.duration_in_months??null)!==terms.months
    || coupon.max_redemptions!==terms.max_redemptions || coupon.times_redeemed>=terms.max_redemptions
    || (coupon.redeem_by!==null && coupon.redeem_by<Math.floor(Date.parse(terms.ends_at)/1000))
    || !coupon.applies_to?.products?.includes(ref(price.product)??'')) return false
  if (terms.percent_bps!==null) return coupon.amount_off===null && coupon.percent_off===terms.percent_bps/100
  return coupon.percent_off===null && coupon.amount_off===terms.amount_off && coupon.currency?.toUpperCase()===currency
    && Object.entries(coupon.currency_options??{}).every(([code,option])=>code.toUpperCase()===currency
      && option.amount_off===terms.amount_off) && (price.unit_amount??0)>=(terms.amount_off??Infinity)
}

export function couponCheckoutSnapshot(session:Stripe.Checkout.Session) {
  const metadata=session.metadata
  const hold=metadata?.sectalk_coupon_hold
  const coupon=metadata?.sectalk_coupon
  const account=session.client_reference_id
  if (session.mode!=='subscription' || session.livemode!==stripeLiveMode || !hold || !stripeBillingUuid.test(hold)
    || !account || !stripeBillingUuid.test(account) || !coupon || !/^[A-Za-z0-9_-]{2,96}$/.test(coupon)
    || !session.currency || !Number.isSafeInteger(session.expires_at)) return null
  const line=session.line_items?.data
  const price=line?.[0]?.price?.id
  if (line?.length!==1 || session.line_items?.has_more || line[0].quantity!==1 || !price) return null
  if (session.status==='expired') return {hold,coupon,account,price,currency:session.currency.toUpperCase(),
    expires:session.expires_at,state:'expired'}
  if (session.status!=='complete' || !ref(session.subscription)?.startsWith('sub_') || !['paid','no_payment_required'].includes(session.payment_status)
    || session.discounts?.length!==1 || ref(session.discounts[0].coupon)!==coupon || session.discounts[0].promotion_code) return null
  return {hold,coupon,account,price,currency:session.currency.toUpperCase(),expires:session.expires_at,state:'redeemed'}
}
