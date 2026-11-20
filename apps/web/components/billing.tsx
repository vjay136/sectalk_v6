'use client'

import { useEffect, useState } from 'react'
import { ArrowRight, CreditCard } from 'lucide-react'
import { type Cadence, type PaidPlan, type Plan, isPaidPlan, plans } from '../lib/billing'
import { db } from '../lib/data'
import { SectionTabs } from './section-tabs'

type Option = { plan: PaidPlan; monthly: boolean; annual: boolean }
type Subscription = { plan: Plan; status: string; period_end: string | null; cancel_at_period_end: boolean; customer_id: string | null }
const labels: Record<string, string> = {
  active: 'Active', trialing: 'Trialing', past_due: 'Payment past due', canceled: 'Canceled', unpaid: 'Unpaid',
  paused: 'Paused', incomplete: 'Checkout incomplete', incomplete_expired: 'Checkout expired',
}

export function Billing({ user }: { user: string }) {
  const [catalog, setCatalog] = useState<Option[] | null>(null)
  const [subscription, setSubscription] = useState<Subscription | null>(null)
  const [cadence, setCadence] = useState<Cadence>('monthly')
  const [view, setView] = useState<'subscription'|'plans'>('subscription')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  useEffect(() => {
    const result = new URLSearchParams(window.location.search).get('billing')
    if (result === 'success') setNotice('Checkout returned. Your plan updates after Stripe confirms the subscription.')
    if (result === 'cancel') setNotice('Checkout was canceled.')
    const controller = new AbortController()
    fetch('/api/billing/catalog', { signal: controller.signal }).then(async res => {
      if (!res.ok) throw new Error('Catalog unavailable')
      setCatalog((await res.json()).plans)
    }).catch(() => { if (!controller.signal.aborted) setError('Could not load the billing catalog.') })
    const reload = () => void db!.from('st_v2_subscriptions').select('plan,status,period_end,cancel_at_period_end,customer_id')
      .eq('user_id', user).maybeSingle().then(({ data, error }) => {
        if (controller.signal.aborted) return
        if (error) setError('Could not load your subscription.')
        else setSubscription(data as Subscription | null)
      })
    reload()
    const poll = window.setInterval(reload, 10000)
    return () => { controller.abort(); window.clearInterval(poll) }
  }, [user])

  async function start(action: 'checkout' | 'portal', plan?: PaidPlan) {
    if (busy) return
    setBusy(true)
    setError('')
    try {
      const { data } = await db!.auth.getSession()
      const response = await fetch('/api/billing/action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + data.session?.access_token },
        body: JSON.stringify({ action, plan, cadence }),
      })
      const payload = await response.json()
      if (!response.ok || !payload.url) throw new Error(payload.error || 'The billing request failed.')
      window.location.assign(payload.url)
    } catch (error) {
      setError(error instanceof Error ? error.message : 'The billing request failed.')
      setBusy(false)
    }
  }

  const status = subscription ? labels[subscription.status] ?? subscription.status : ''
  const periodEnd = subscription?.period_end ? Date.parse(subscription.period_end) : 0
  const currentPlan = subscription && (
    ['active','trialing'].includes(subscription.status) && periodEnd > Date.now()
    || subscription.status === 'past_due' && periodEnd + 72 * 3600000 > Date.now()
  ) ? subscription.plan : 'free'
  return <section className="content-page">
    <header className="content-title"><div className="card-icon"><CreditCard size={22}/></div><div><h1>Billing</h1><p>Manage your SecTalk subscription and workspace limits.</p></div></header>
    <SectionTabs label="Billing sections" value={view} onChange={setView} options={ [['subscription','My subscription'], ['plans','Compare plans']] }/>
    {view==='subscription'&&<div className="panel release-panel billing-summary">
      <div><span className="pill">Current plan</span><h2>{plans.find(plan => plan.id === currentPlan)?.name || 'Free'}</h2>
        {status && <p>{status}{subscription?.cancel_at_period_end ? ' · Ends at the end of this billing period' : ''}</p>}
        {subscription?.period_end && <p>Period ends <time dateTime={subscription.period_end}>{new Date(subscription.period_end).toLocaleDateString()}</time></p>}</div>
      {subscription?.customer_id && <button className="secondary" disabled={busy} onClick={() => void start('portal')}>Manage billing <ArrowRight size={15}/></button>}
    </div>}
    {notice && <p role="status" className="release-info">{notice}</p>}
    {error && <p role="alert" className="error">{error}</p>}
    {view==='plans'&&<>{catalog && !catalog.some(option => option.monthly || option.annual) && <p className="release-info">Paid checkout is awaiting payment-provider configuration.</p>}
    <div className="tabs release-tabs billing-interval" aria-label="Billing interval">
      <button aria-pressed={cadence === 'monthly'} className={cadence === 'monthly' ? 'active' : ''} onClick={() => setCadence('monthly')}>Monthly</button>
      <button aria-pressed={cadence === 'annual'} className={cadence === 'annual' ? 'active' : ''} onClick={() => setCadence('annual')}>Annual</button>
    </div>
    <div className="billing-grid">
      {plans.map(plan => {
        const id = plan.id
        const available = Boolean(catalog?.find(option => option.plan === plan.id)?.[cadence])
        return <article key={plan.id} className={'panel release-panel billing-card' + (currentPlan === plan.id ? ' billing-current' : '')}>
          <h2>{plan.name}</h2><p>{plan.features}</p>
          <ul><li>{plan.workspaces} {plan.workspaces === 1 ? 'workspace' : 'workspaces'}</li><li>Up to {plan.members} members per workspace</li></ul>
          {isPaidPlan(id) && <button disabled={busy || !available || currentPlan === id || currentPlan !== 'free'} className="primary" onClick={() => void start('checkout', id)}>{currentPlan === id ? 'Current plan' : available ? 'Continue to checkout' : 'Checkout unavailable'}</button>}
          {plan.id === 'enterprise' && <span className="pill">Contract billing</span>}
        </article>
      })}
    </div></>}
  </section>
}
