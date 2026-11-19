export const paidPlans = ['basic', 'professional', 'business'] as const
export type PaidPlan = typeof paidPlans[number]
export type Plan = 'free' | PaidPlan | 'enterprise'
export type Cadence = 'monthly' | 'annual'
export const plans: { id: Plan; name: string; workspaces: number; members: number; features: string }[] = [
  { id: 'free', name: 'Free', workspaces: 1, members: 5, features: 'Direct chat, one-to-one calls, and team collaboration' },
  { id: 'basic', name: 'Basic', workspaces: 2, members: 12, features: 'More space for families and small teams' },
  { id: 'professional', name: 'Professional', workspaces: 5, members: 30, features: 'Higher limits for growing teams' },
  { id: 'business', name: 'Business', workspaces: 20, members: 100, features: 'Workspace capacity for larger teams' },
  { id: 'enterprise', name: 'Enterprise', workspaces: 100, members: 500, features: 'Contract-based limits and onboarding' },
]
export function isPaidPlan(value: unknown): value is PaidPlan {
  return paidPlans.some(plan => plan === value)
}
