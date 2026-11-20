export const paidPlans = ['basic', 'professional', 'business'] as const
export type PaidPlan = typeof paidPlans[number]
export type Plan = 'free' | PaidPlan | 'enterprise'
export type Cadence = 'monthly' | 'annual'
export const billingCurrencies = ['USD', 'EUR', 'GBP', 'INR', 'CAD', 'AUD', 'JPY'] as const
export type BillingCurrency = typeof billingCurrencies[number]
export type PlanOffer = { currency: BillingCurrency; cadence: Cadence; amount: number | null }
export type PlanEntitlements = {
  plan: Plan; version: number; workspace_limit: number; seat_limit: number; group_limit: number
  file_bytes: number; storage_bytes: number; task_creation: boolean; recurring_meetings: boolean; integration_api: boolean
}
export type PlanVersion = { plan: Plan; version: number; title: string; description: string; prices: PlanOffer[]; entitlements?: PlanEntitlements }

export function isBillingCurrency(value: unknown): value is BillingCurrency {
  return billingCurrencies.some(currency => currency === value)
}

export function formatBillingAmount(amount: number, currency: string) {
  const format = new Intl.NumberFormat(undefined, { style: 'currency', currency, currencyDisplay: 'code' })
  return format.format(amount / 10 ** (format.resolvedOptions().maximumFractionDigits ?? 2))
}
export const plans: { id: Plan; name: string; workspaces: number; members: number; features: string }[] = [
  { id: 'free', name: 'Free', workspaces: 1, members: 5, features: 'Direct chat, one-to-one calls, and team collaboration' },
  { id: 'basic', name: 'Basic', workspaces: 2, members: 12, features: 'More space for families and small teams' },
  { id: 'professional', name: 'Pro', workspaces: 5, members: 30, features: 'Higher limits for growing teams' },
  { id: 'business', name: 'Team', workspaces: 20, members: 100, features: 'Workspace capacity for larger teams' },
  { id: 'enterprise', name: 'Enterprise', workspaces: 100, members: 500, features: 'Contract-based limits and onboarding' },
]
export function isPaidPlan(value: unknown): value is PaidPlan {
  return paidPlans.some(plan => plan === value)
}
