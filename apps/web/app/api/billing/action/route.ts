import { withOperationalMetrics } from '../../../../lib/operational-metrics-server'
import { billingIdentity, billingWriter, catalogPriceId, origin, stripe, stripeLiveMode } from '../../../../lib/stripe-server'
import { launchBillingPortal } from '../../../../lib/stripe-portal'
import { readBoundedText } from '../../../../lib/request-body'
import { couponCodePattern, matchesCoupon, type CouponQuote } from '../../../../lib/stripe-coupon'
import { isBillingCurrency, isPaidPlan } from '../../../../lib/billing'

async function handlePost(request: Request) {
  const identity = await billingIdentity(request)
  if (!identity) return Response.json({ error: 'Sign in first.' }, { status: 401 })
  const { user, client } = identity
  const proof=await client.rpc('st_v7_sensitive_action_status',{p_kind:'billing'})
  if (proof.error || proof.data!=='verified') return Response.json({error:'Verify your current sign-in to continue to billing.'},{status:403})
  if (!stripe || !origin || !billingWriter) return Response.json({ error: 'Payment checkout is unavailable on this deployment.' }, { status: 503 })
  let payload
  try {
    const body=await readBoundedText(request,4096)
    if (body===undefined) return Response.json({error:'Billing request is too large.'},{status:413})
    payload=body?JSON.parse(body):null
  } catch {return Response.json({error:'Invalid billing request.'},{status:400})}
  if (payload?.action==='portal') return launchBillingPortal(identity,payload.purpose)
  const { data: subscription, error } = await client.from('st_v2_subscriptions').select('customer_id,status').eq('user_id', user.id).maybeSingle()
  if (error) return Response.json({ error: 'Could not load your subscription.' }, { status: 503 })
  try {
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
    if (payload.coupon!==undefined && typeof payload.coupon!=='string') {
      return Response.json({error:'Enter a valid coupon code.'},{status:400})
    }
    const code=payload.coupon?.trim().toUpperCase() || null
    let terms:CouponQuote|null=null
    if(code!==null) {
      if(!couponCodePattern.test(code)) return Response.json({error:'Enter a valid coupon code.'},{status:400})
      const quote=await billingWriter.rpc('st_v7_quote_coupon',{p_code:code,p_plan:payload.plan,p_currency:payload.currency})
      if(quote.error) return Response.json({error:'Coupons are temporarily unavailable.'},{status:503})
      terms=quote.data as CouponQuote|null
      if(!terms || !matchesCoupon(terms,await stripe.coupons.retrieve(terms.coupon,{expand:['applies_to']}),
        providerPrice,payload.currency)) return Response.json({error:'This coupon is unavailable for this checkout.'},{status:422})
    }
    const {data:lease,error:reserveError}=await billingWriter.rpc('st_v7_reserve_coupon_checkout',{
      p_account:user.id,p_price:selected.id,p_code:code,p_revision:terms?.revision??null,p_plan:payload.plan,p_currency:payload.currency,
    })
    if (reserveError || !lease?.id) return Response.json({ error: 'An open checkout already exists for another plan. Try again after it expires.' }, { status: 409 })
    const session = lease.session ? await stripe.checkout.sessions.retrieve(lease.session) : await stripe.checkout.sessions.create({
      mode: 'subscription',
      currency: payload.currency.toLowerCase(),
      adaptive_pricing: { enabled: false },
      client_reference_id: user.id,
      ...(subscription?.customer_id ? { customer: subscription.customer_id } : { customer_email: user.email }),
      line_items: [{ price: selected.id, quantity: 1 }],
      ...(terms ? {discounts:[{coupon:terms.coupon}],payment_method_types:['card'],
        metadata:{sectalk_coupon_hold:lease.id,sectalk_coupon:terms.coupon}} : {allow_promotion_codes:false}),
      subscription_data: { metadata: { sectalk_user: user.id } },
      success_url: origin + '/?billing=success',
      cancel_url: origin + '/?billing=cancel',
      expires_at: lease.expires_epoch,
    }, { idempotencyKey: 'sectalk-checkout-' + lease.id })
    if (!session.url || session.status==='complete' || session.status==='expired') {
      return Response.json({error:'Checkout has already closed.'},{status:409})
    }
    const destination=URL.parse(session.url)
    if (!destination || destination.origin!=='https://checkout.stripe.com' || destination.username || destination.password) {
      return Response.json({error:'The payment provider returned an invalid Checkout session.'},{status:502})
    }
    if(terms) {
      if(session.status!=='open' || session.mode!=='subscription' || session.livemode!==stripeLiveMode || session.client_reference_id!==user.id
        || session.metadata?.sectalk_coupon_hold!==lease.id
        || session.metadata?.sectalk_coupon!==terms.coupon || session.expires_at!==Number(lease.expires_epoch)) {
        return Response.json({error:'The payment provider returned an invalid coupon reservation.'},{status:502})
      }
      const attached=await billingWriter.rpc('st_v7_attach_coupon_checkout',{p_hold:lease.id,p_account:user.id,p_session:session.id})
      if (attached.error||attached.data!==true) return Response.json({error:'Could not confirm coupon reservation.'},{status:503})
    }
    return Response.json({ url: session.url })
  } catch {
    return Response.json({ error: 'The payment provider could not process this request.' }, { status: 502 })
  }
}

export async function POST(request: Request) {
  return withOperationalMetrics('billing_action', () => handlePost(request))
}
