'use client'

import { useEffect, useState } from 'react'
import { CreditCard } from 'lucide-react'
import { type BillingCurrency, type Cadence, type PaidPlan, type Plan, type PlanEntitlements, type PlanVersion, formatBillingAmount, isBillingCurrency, isPaidPlan, plans } from '../lib/billing'
import { db } from '../lib/data'
import { SectionTabs } from './section-tabs'
import {useSensitiveAction} from './sensitive-action'
import type {PortalPurpose} from '../lib/stripe-portal'

type Renewal = {state:'clear'|'grace'|'expired'; grace_until?:string; retry_at?:string|null}
type Catalog = { plans: PlanVersion[]; checkoutAvailable: boolean; portalConfigured: boolean }
type Subscription = {
  plan: Plan; status: string; period_end: string | null; cancel_at_period_end: boolean; customer_id: string | null
  catalog_version: number; billing_currency: string | null; billing_cadence: Cadence | null; billing_amount: number | null
}
const labels: Record<string, string> = {
  active: 'Active', trialing: 'Trialing', past_due: 'Payment past due', canceled: 'Canceled', unpaid: 'Unpaid',
  paused: 'Paused', incomplete: 'Checkout incomplete', incomplete_expired: 'Checkout expired',
}

export function Billing({ user }: { user: string }) {
  const {authorize,confirmation}=useSensitiveAction()
  const [catalog, setCatalog] = useState<Catalog | null>(null)
  const [renewal,setRenewal] = useState<Renewal | null>(null)
  const [subscription, setSubscription] = useState<Subscription | null>(null)
  const [subscriptionTitle, setSubscriptionTitle] = useState<string | null>(null)
  const [entitlements, setEntitlements] = useState<PlanEntitlements | null>(null)
  const [cadence, setCadence] = useState<Cadence>('monthly')
  const [coupon,setCoupon] = useState('')
  const [currency, setCurrency] = useState<BillingCurrency>('USD')
  const [view, setView] = useState<'subscription'|'plans'>('subscription')
  const [workspaceBilling, setWorkspaceBilling] = useState<'delegated' | 'owner' | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  useEffect(() => {
    const result = new URLSearchParams(window.location.search).get('billing')
    if (result === 'success') setNotice('Checkout returned. Your plan updates after Stripe confirms the subscription.')
    if (result === 'cancel') setNotice('Checkout was canceled.')
    if (result === 'portal-return') setNotice('Stripe changes appear after the billing provider confirms them.')
    const controller = new AbortController()
    fetch('/api/billing/catalog', { signal: controller.signal }).then(async res => {
      if (!res.ok) throw new Error('Catalog unavailable')
      const options = await res.json() as Catalog
      if (controller.signal.aborted) return
      setCatalog(options)
      const currencies = options.plans.flatMap(plan => plan.prices.map(price => price.currency))
      if (currencies[0] && !currencies.includes('USD')) setCurrency(currencies[0])
    }).catch(() => { if (!controller.signal.aborted) setError('Could not load the billing catalog.') })
    void db!.rpc('st_v7_billing_admin_view').abortSignal(controller.signal).then(result => {
      if (!controller.signal.aborted && !result.error) {
        const scopes = result.data as {delegated: boolean; manages: boolean}[]
        setWorkspaceBilling(scopes.some(scope => scope.delegated) ? 'delegated' : scopes.some(scope => scope.manages) ? 'owner' : null)
      }
    })
    const reload = () => void Promise.all([
      db!.from('st_v2_subscriptions').select('plan,status,period_end,cancel_at_period_end,customer_id,catalog_version,billing_currency,billing_cadence,billing_amount')
        .eq('user_id', user).maybeSingle(),
      db!.rpc('st_v6_my_plan_title'),
      db!.rpc('st_v7_my_entitlements'),
      db!.rpc('st_v7_renewal_status'),
    ]).then(([subscription, title, limits, payment]) => {
      if (controller.signal.aborted) return
      if (subscription.error || title.error || limits.error) setError('Could not load your subscription.')
      if (!subscription.error) setSubscription(subscription.data as Subscription | null)
      if (!title.error) setSubscriptionTitle(title.data)
      if (!limits.error) setEntitlements(limits.data as PlanEntitlements | null)
      if (!payment.error) setRenewal(payment.data as Renewal | null)
    })
    reload()
    const poll = window.setInterval(reload, 10000)
    return () => { controller.abort(); window.clearInterval(poll) }
  }, [user])

  async function start(action: 'checkout' | 'portal', plan?: PaidPlan, version?: number, purpose?:PortalPurpose) {
    if (busy) return
    setBusy(true)
    setError('')
    try {
      const { data } = await db!.auth.getSession()
      const response = await fetch('/api/billing/action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + data.session?.access_token },
        body: JSON.stringify({ action, plan, cadence, currency, version, purpose, ...(action=== 'checkout' && coupon.trim() ? {coupon:coupon.trim()} : {}) }),
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
  const currentPlan = entitlements?.plan ?? (subscription && (
    ['active','trialing'].includes(subscription.status) && periodEnd > Date.now()
    || subscription.status === 'past_due' && periodEnd + 72 * 3600000 > Date.now()
  ) ? subscription.plan : 'free')
  const activeVersion = catalog?.plans.find(plan => plan.plan === currentPlan)
  const currencies = [...new Set(catalog?.plans.flatMap(plan => plan.prices.map(price => price.currency)) ?? [])]
  const grandfathered = catalog && currentPlan !== 'free' && subscription && (!activeVersion || activeVersion.version > subscription.catalog_version)
  return <section className="content-page">
    <header className="content-title"><div className="card-icon"><CreditCard size={22}/></div><div><h1>Billing</h1><p>Manage your SecTalk subscription and workspace limits.</p></div></header>
    <SectionTabs label="Billing sections" value={view} onChange={setView} options={ [['subscription','My subscription'], ['plans','Compare plans']] }/>
    <a href="/billing/usage">Workspace usage</a>
    <a href="/billing/documents">Invoices and receipts</a>
    {workspaceBilling && <a href="/billing/workspaces">{workspaceBilling === 'delegated' ? 'Workspace billing' : 'Manage workspace billing access'}</a>}
    {confirmation}
    {view==='subscription'&&<div className="panel release-panel billing-summary">
      <div><span className="pill">Current plan</span><h2>{(currentPlan === 'free' ? null : subscriptionTitle) ?? activeVersion?.title ?? plans.find(plan => plan.id === currentPlan)?.name ?? 'Free'}</h2>
        {status && <p>{status}{subscription?.cancel_at_period_end ? ' · Ends at the end of this billing period' : ''}</p>}
        {currentPlan !== 'free' && subscription && <p>Terms version {subscription.catalog_version}{grandfathered ? ' · Grandfathered' : ''}</p>}
        {currentPlan !== 'free' && subscription?.billing_amount != null && subscription.billing_currency &&
          <p>{formatBillingAmount(subscription.billing_amount, subscription.billing_currency)} per {subscription.billing_cadence === 'annual' ? 'year' : 'month'}</p>}
        {subscription?.period_end && <p>Period ends <time dateTime={subscription.period_end}>{new Date(subscription.period_end).toLocaleDateString()}</time></p>}
        {entitlements && <PlanLimits limits={entitlements} />}</div>
      {subscription?.customer_id && catalog?.portalConfigured && <details>
        <summary>Manage billing</summary>
        <div className="actions">{([
          ['overview','Open Stripe billing portal'],['payment_method','Update payment methods'],['plan','Change plan'],
          ['invoices','View Stripe invoices'],['tax_ids','Manage tax IDs'],
          ...(subscription.cancel_at_period_end ? [['reactivate','Keep subscription active']] :
            ['active','trialing','past_due'].includes(subscription.status) ? [['cancel','Schedule cancellation']] : []),
        ] as [PortalPurpose,string][]).map(([purpose,label])=><button key={purpose} type="button" className="secondary"
          disabled={busy} onClick={()=>void authorize('billing',()=>start('portal',undefined,undefined,purpose))}>{label}</button>)}</div>
      </details>}
      {subscription?.customer_id && catalog && !catalog.portalConfigured && <p>The Stripe billing portal is awaiting configuration.</p>}
    </div>}
    {view==='subscription' && renewal && renewal.state!=='clear' && <section className="panel release-panel" aria-label="Renewal payment">
      <h2>Renewal payment needs attention</h2>
      {renewal.grace_until && <p>{renewal.state==='expired' ? 'Grace period ended ' : 'Grace period ends '}
        <time dateTime={renewal.grace_until}>{new Date(renewal.grace_until).toLocaleString()}</time>.</p>}
      {renewal.retry_at ? <p>Stripe currently schedules another attempt for{' '}
        <time dateTime={renewal.retry_at}>{new Date(renewal.retry_at).toLocaleString()}</time>.</p>
        : <p>Stripe has not reported another scheduled attempt.</p>}
    </section>}
    {notice && <p role="status" className="release-info">{notice}</p>}
    {error && <p role="alert" className="error">{error}</p>}
    {view==='plans'&&<>{!catalog && !error && <p role="status">Loading available plans…</p>}
    {catalog && !catalog.checkoutAvailable && <p className="release-info">Paid checkout is awaiting payment-provider configuration.</p>}
    {currencies.length > 0 && <label>Currency <select value={currency} onChange={event => {
      if (isBillingCurrency(event.target.value)) setCurrency(event.target.value)
    }}>{currencies.map(code => <option key={code}>{code}</option>)}</select></label>}
    {catalog?.checkoutAvailable && currentPlan==='free' && <label>Coupon code (optional)
      <input value={coupon} maxLength={40} autoComplete="off" onChange={event=>setCoupon(event.target.value)}/>
    </label>}
    <div className="tabs release-tabs billing-interval" aria-label="Billing interval">
      <button aria-pressed={cadence === 'monthly'} className={cadence === 'monthly' ? 'active' : ''} onClick={() => setCadence('monthly')}>Monthly</button>
      <button aria-pressed={cadence === 'annual'} className={cadence === 'annual' ? 'active' : ''} onClick={() => setCadence('annual')}>Annual</button>
    </div>
    <div className="billing-grid">
      {catalog?.plans.map(plan => {
        const id = plan.plan
        const limits = plan.entitlements
        const price = plan.prices.find(option => option.cadence === cadence && option.currency === currency)
        const available = Boolean(price && catalog.checkoutAvailable)
        return <article key={id} className={'panel release-panel billing-card' + (currentPlan === id ? ' billing-current' : '')}>
          <h2>{plan.title}</h2><p>{plan.description}</p>
          {price?.amount != null && <p>{formatBillingAmount(price.amount, price.currency)} per {cadence === 'annual' ? 'year' : 'month'}</p>}
          {limits && <PlanLimits limits={limits} />}
          {isPaidPlan(id) && <button disabled={busy || !available || currentPlan !== 'free'} className="primary" onClick={() => void authorize('billing',()=>start('checkout', id, plan.version))}>{currentPlan === id ? 'Current plan' : available ? 'Continue to checkout' : 'Checkout unavailable'}</button>}
          {id === 'enterprise' && <span className="pill">Contract billing</span>}
        </article>
      })}
    </div></>}
  </section>
}

function PlanLimits({ limits }: { limits: PlanEntitlements }) {
  const fileUnit=limits.file_bytes<1048576?1024:1048576
  const fileSize=new Intl.NumberFormat(undefined,{maximumFractionDigits:1}).format(limits.file_bytes/fileUnit)
  return <ul aria-label="Plan limits">
    <li>{limits.workspace_limit} {limits.workspace_limit === 1 ? 'workspace' : 'workspaces'}</li>
    <li>Up to {limits.seat_limit} members per workspace</li>
    <li>Up to {limits.group_limit} members per encrypted chat group</li>
    {limits.file_bytes > 0 && <li>Up to {fileSize} {fileUnit===1024?'KiB':'MiB'} per direct attachment</li>}
    {limits.integration_api && <li>Workspace API access</li>}
  </ul>
}
