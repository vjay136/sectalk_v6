import Stripe from 'stripe'
import { createClient } from '@supabase/supabase-js'
import { paidPlans, type BillingCurrency, type Cadence, type PaidPlan, type PlanVersion } from './billing'

export const origin = process.env.SECTALK_APP_URL
export const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET
const stripeKey = process.env.STRIPE_SECRET_KEY
const dbUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
const publishable = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY
const dbSecret = process.env.SECTALK_BILLING_SUPABASE_KEY
const options = { auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false } }
export const stripe = stripeKey && webhookSecret && dbUrl && dbSecret && origin ? new Stripe(stripeKey, { timeout: 10000, maxNetworkRetries: 1 }) : null
export const billingWriter = dbUrl && dbSecret ? createClient(dbUrl, dbSecret, options) : null
const catalogReader = dbUrl && publishable ? createClient(dbUrl, publishable, options) : null
const stripePrices = {
  basic: { monthly: process.env.STRIPE_PRICE_BASIC_MONTHLY, annual: process.env.STRIPE_PRICE_BASIC_ANNUAL },
  professional: { monthly: process.env.STRIPE_PRICE_PROFESSIONAL_MONTHLY, annual: process.env.STRIPE_PRICE_PROFESSIONAL_ANNUAL },
  business: { monthly: process.env.STRIPE_PRICE_BUSINESS_MONTHLY, annual: process.env.STRIPE_PRICE_BUSINESS_ANNUAL },
}

function legacyPriceId(plan: PaidPlan, cadence: Cadence) {
  return stripePrices[plan][cadence]
}

export function legacyOfferForPrice(price: string) {
  for (const plan of paidPlans) {
    for (const cadence of ['monthly', 'annual'] as const) {
      if (legacyPriceId(plan, cadence) === price) return { plan, cadence }
    }
  }
  return null
}

export async function catalogPriceId(plan: PaidPlan, cadence: Cadence, currency: BillingCurrency, version: number) {
  if (!billingWriter) return null
  const { data, error } = await billingWriter.rpc('st_v6_checkout_plan_price', {
    p_plan: plan, p_cadence: cadence, p_currency: currency, p_version: version,
    p_legacy_price: legacyPriceId(plan, cadence) ?? null,
  })
  if (error) throw new Error('Catalog unavailable')
  return typeof data?.id === 'string' ? data as { id: string; amount: number | null } : null
}

export async function configuredCatalog() {
  const result = await catalogReader?.rpc('st_v7_public_plan_entitlements')
  if (!result?.data || result.error) throw new Error('Catalog unavailable')
  return (result.data as PlanVersion[]).map(version => ({
    ...version,
    prices: [...version.prices, ...(version.version === 1 && stripe && paidPlans.some(plan => plan === version.plan)
      ? (['monthly', 'annual'] as const).flatMap(cadence =>
        legacyPriceId(version.plan as PaidPlan, cadence) && !version.prices.some(price => price.cadence === cadence && price.currency === 'USD')
          ? [{ currency: 'USD' as const, cadence, amount: null }] : [])
      : [])],
  }))
}

export async function billingIdentity(request: Request) {
  const token = request.headers.get('Authorization')?.match(/^Bearer (\S+)$/i)?.[1]
  if (!token || !dbUrl || !publishable) return null
  const client = createClient(dbUrl, publishable, { ...options, global: { headers: { Authorization: 'Bearer ' + token } } })
  const { data, error } = await client.auth.getUser(token)
  if (error || !data.user) return null
  return { user: data.user, client }
}
