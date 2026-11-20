'use client'

import {useState} from 'react'
import {type BillingCurrency,type Cadence,type PaidPlan,formatBillingAmount} from '../lib/billing'
import {emptyTaxProfile,indiaStates,type TaxEstimate,type TaxProfile} from '../lib/billing-tax'
import {db} from '../lib/data'

type Offer={plan:PaidPlan;version:number;cadence:Cadence;currency:BillingCurrency}
type Quote={id:string;estimate:TaxEstimate}
export function BillingTaxCheckout({offer,authorize,start,cancel}:{
  offer:Offer;authorize:(scope:'billing',run:()=>Promise<void>)=>Promise<void>;
  start:(id:string)=>Promise<void>;cancel:()=>void
}) {
  const [profile,setProfile]=useState<TaxProfile>({...emptyTaxProfile,country:offer.currency==='INR'?'IN':''})
  const [quote,setQuote]=useState<Quote|null>(null)
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  function field(key:keyof TaxProfile,value:string) {
    setQuote(null)
    setProfile(previous=>key==='country'?{...previous,country:value,region:'',taxId:''}:{...previous,[key]:value})
  }
  async function call(action:string) {
    setBusy(true)
    setError('')
    try {
      const token=(await db!.auth.getSession()).data.session?.access_token
      const response=await fetch('/api/billing/action',{method:'POST',headers:{
        Authorization:'Bearer '+token,'Content-Type':'application/json',
      },body:JSON.stringify({action,profile,...offer})})
      const result=await response.json()
      if (!response.ok) throw new Error(result.error||'Billing tax is temporarily unavailable.')
      if (action==='tax_profile') {
        if (result.profile) setProfile(result.profile)
        else setError('No saved billing profile yet.')
        setQuote(null)
      } else setQuote(result)
    } catch(error) {setError(error instanceof Error?error.message:'Billing tax is temporarily unavailable.')}
    finally {setBusy(false)}
  }
  const country=profile.country.trim().toUpperCase()
  return <section className="panel release-panel" aria-label="Billing tax estimate">
    <h2>Billing address and taxes</h2>
    <button type="button" disabled={busy} onClick={()=>void authorize('billing',()=>call('tax_profile'))}>Use saved billing details</button>
    <label>Company legal name (optional) <input value={profile.company} maxLength={100} onChange={event=>field('company',event.target.value)} /></label>
    <label>Country code <input value={profile.country} maxLength={2} placeholder="IN" onChange={event=>field('country',event.target.value)} /></label>
    {country==='IN'?<label>Place of supply <select value={profile.region} onChange={event=>field('region',event.target.value)}>
      <option value="">Choose a state or territory</option>
      {Object.entries(indiaStates).sort((a,b)=>a[1].localeCompare(b[1])).map(([code,state])=><option key={code} value={code}>{state}</option>)}
    </select></label>:<label>State or territory <input value={profile.region} maxLength={40} onChange={event=>field('region',event.target.value)} /></label>}
    <label>Street address <input value={profile.address} maxLength={120} onChange={event=>field('address',event.target.value)} /></label>
    <label>City <input value={profile.city} maxLength={80} onChange={event=>field('city',event.target.value)} /></label>
    <label>Postal code <input value={profile.postal} maxLength={16} onChange={event=>field('postal',event.target.value)} /></label>
    {country==='IN'&&<label>Company GSTIN (optional) <input value={profile.taxId} maxLength={15} onChange={event=>field('taxId',event.target.value)} /></label>}
    <button type="button" disabled={busy} onClick={()=>void authorize('billing',()=>call('tax_preview'))}>Save and estimate tax</button>
    {quote&&<>
      <dl aria-label="Estimated checkout totals">
        <dt>Price {quote.estimate.behavior==='inclusive'?'including tax':'before tax'}</dt><dd>{money(quote.estimate.base,quote)}</dd>
        {quote.estimate.behavior==='inclusive'&&<><dt>Subtotal before tax</dt><dd>{money(quote.estimate.net,quote)}</dd></>}
        {quote.estimate.lines.map((line,index)=><div key={index}><dt>{line.label}</dt><dd>{money(line.amount,quote)}</dd></div>)}
        <dt>Estimated total</dt><dd>{money(quote.estimate.total,quote)}</dd>
      </dl>
      <p>Stripe confirms the final tax and total at checkout.</p>
      <button type="button" className="primary" disabled={busy} onClick={()=>void authorize('billing',()=>start(quote.id))}>Continue to Stripe checkout</button>
    </>}
    {error&&<p role="alert">{error}</p>}
    <button type="button" disabled={busy} onClick={cancel}>Choose a different plan</button>
  </section>
}

function money(value:number,quote:Quote) { return formatBillingAmount(value,quote.estimate.currency) }
