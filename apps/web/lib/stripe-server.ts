import Stripe from 'stripe'
import { createClient } from '@supabase/supabase-js'
import { paidPlans, type Cadence, type PaidPlan } from './billing'

export const origin = process.env.SECTALK_APP_URL
export const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET
const stripeKey = process.env.STRIPE_SECRET_KEY
const dbUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
const publishable = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY
const dbSecret = process.env.SECTALK_BILLING_SUPABASE_KEY
const options = { auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false } }
export const stripe = stripeKey && webhookSecret && dbUrl && dbSecret && origin ? new Stripe(stripeKey, { timeout: 10000, maxNetworkRetries: 1 }) : null
export const billingWriter = dbUrl && dbSecret ? createClient(dbUrl, dbSecret, options) : null
const stripePrices = {
  basic: { monthly: process.env.STRIPE_PRICE_BASIC_MONTHLY, annual: process.env.STRIPE_PRICE_BASIC_ANNUAL },
  professional: { monthly: process.env.STRIPE_PRICE_PROFESSIONAL_MONTHLY, annual: process.env.STRIPE_PRICE_PROFESSIONAL_ANNUAL },
  business: { monthly: process.env.STRIPE_PRICE_BUSINESS_MONTHLY, annual: process.env.STRIPE_PRICE_BUSINESS_ANNUAL },
}

export const priceId = (plan: PaidPlan, cadence: Cadence) => stripePrices[plan][cadence]
export const planForPrice = (price: string) => paidPlans.find(plan => Object.values(stripePrices[plan]).includes(price))
export const configuredPlans = () => paidPlans.map(plan => ({
  plan, monthly: Boolean(stripe && priceId(plan, 'monthly')), annual: Boolean(stripe && priceId(plan, 'annual')),
}))

export async function billingIdentity(request: Request) {
  const token = request.headers.get('Authorization')?.match(/^Bearer (\S+)$/i)?.[1]
  if (!token || !dbUrl || !publishable) return null
  const client = createClient(dbUrl, publishable, { ...options, global: { headers: { Authorization: 'Bearer ' + token } } })
  const { data, error } = await client.auth.getUser(token)
  if (error || !data.user) return null
  return { user: data.user, client }
}
