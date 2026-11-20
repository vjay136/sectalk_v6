import type { Metadata } from 'next'
import Link from 'next/link'
import { connection } from 'next/server'
import { PublicSite } from '../../components/public-site'
import styles from '../../components/public-site.module.css'
import { formatBillingAmount, isBillingCurrency, plans, type Cadence, type PlanVersion } from '../../lib/billing'
import { configuredCatalog } from '../../lib/stripe-server'

export const metadata: Metadata = { title: 'Pricing | SecTalk' }

export default async function PricingPage({ searchParams }: { searchParams: Promise<{ cadence?: string; currency?: string }> }) {
  await connection()
  const query = await searchParams
  const cadence: Cadence = query.cadence === 'annual' ? 'annual' : 'monthly'
  const catalog = await configuredCatalog().catch(() => null)
  const versions: PlanVersion[] = catalog ?? plans.filter(plan => plan.id !== 'basic')
    .map(plan => ({ plan: plan.id, title: plan.name, description: plan.features, version: 1, prices: [] }))
  const currencies = [...new Set(versions.flatMap(plan => plan.prices.map(price => price.currency)))]
  const currency = isBillingCurrency(query.currency) && currencies.includes(query.currency)
    ? query.currency : currencies.find(code => code === 'USD') ?? currencies[0] ?? 'USD'

  return <PublicSite>
    <header className={styles.heading}><h1>SecTalk pricing</h1><p>Choose the workspace capacity and billing interval that fit your team.</p></header>
    <form className={styles.controls} action="/pricing" method="get">
      {currencies.length > 0 && <label>Currency<select name="currency" defaultValue={currency}>
        {currencies.map(code => <option key={code}>{code}</option>)}
      </select></label>}
      <label>Billing interval<select name="cadence" defaultValue={cadence}>
        <option value="monthly">Monthly</option><option value="annual">Annual</option>
      </select></label>
      <button type="submit" className="secondary">Show prices</button>
    </form>
    {!catalog && <p role="status" className={styles.notice}>Live prices are temporarily unavailable.</p>}
    <div className={styles.cards}>
      {versions.map(plan => {
        const limits = plans.find(entry => entry.id === plan.plan)
        const offer = plan.prices.find(price => price.cadence === cadence && price.currency === currency)
        return <article key={plan.plan}>
          <h2>{plan.title}</h2>
          <p>{plan.description}</p>
          <p><strong>{plan.plan === 'free' ? 'Free' : plan.plan === 'enterprise' ? 'Contract billing'
            : offer?.amount != null ? formatBillingAmount(offer.amount, currency) + (cadence === 'annual' ? ' per year' : ' per month')
              : offer ? 'Price shown in checkout' : 'Price unavailable'}</strong></p>
          {limits && <p>{limits.workspaces} {limits.workspaces === 1 ? 'workspace' : 'workspaces'} · {limits.members} members per workspace</p>}
        </article>
      })}
    </div>
    <div className="action-row"><Link className="primary" href="/?mode=signup#account">Get started</Link>
      <Link className="secondary" href="/#account">Sign in to manage billing</Link></div>
  </PublicSite>
}
