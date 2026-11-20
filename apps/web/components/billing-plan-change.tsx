'use client'

import {useState} from 'react'
import {formatBillingAmount,type PlanVersion} from '../lib/billing'
import {db} from '../lib/data'

type Terms={plan:string;version:number;amount:number;currency:string;cadence:'monthly'|'annual'}
type Command={kind:'upgrade'|'schedule'|'abort';current:Terms;requested:Terms|null;effective:number;due:number|null;replaces:boolean}
type Preview={id:string;command:Command}
type Scheduled={requested:Terms;effective:number}
type ActionResult={schedule:Scheduled|null;pending?:Preview|null;state?:string;awaitingPayment?:boolean}

export function BillingPlanChange({offers,currentPlan,authorize}:{
  offers:PlanVersion[];currentPlan:string;authorize:(kind:'billing',action:()=>Promise<void>)=>Promise<void>
}) {
  const [open,setOpen]=useState(false)
  const [selection,setSelection]=useState('')
  const [scheduled,setScheduled]=useState<Scheduled|null>(null)
  const [preview,setPreview]=useState<Preview|null>(null)
  const [pending,setPending]=useState(false)
  const [awaitingPayment,setAwaitingPayment]=useState(false)
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [notice,setNotice]=useState('')
  const options=offers.filter(offer=>['basic','professional','business'].includes(offer.plan)&&offer.plan!==currentPlan)

  async function request<T>(payload:object,onSuccess:(data:T)=>void) {
    if (busy) return
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const {data}=await db!.auth.getSession()
      const response=await fetch('/api/billing/action',{
        method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+data.session?.access_token},
        body:JSON.stringify({action:'plan_change',...payload}),
      })
      const body=await response.json()
      if (!response.ok) throw new Error(body.error || 'Could not complete the plan change.')
      onSuccess(body as T)
    } catch (error) {
      setError(error instanceof Error?error.message:'Could not complete the plan change.')
    } finally {
      setBusy(false)
    }
  }

  function load() {
    return request<ActionResult>({stage:'status'},data=>{
      setOpen(true)
      setScheduled(data.schedule)
      setPreview(data.pending??null)
      setPending(Boolean(data.pending))
      setAwaitingPayment(Boolean(data.awaitingPayment))
    })
  }

  function quote(intent:'plan'|'abort') {
    const target=options.find(offer=>offer.plan===selection)
    return request<Preview>({stage:'preview',intent,plan:target?.plan,version:target?.version},data=>{
      setPreview(data)
      setPending(false)
    })
  }

  function confirm(id:string) {
    return request<ActionResult>({stage:'confirm',id},data=>{
      setPreview(null)
      setPending(false)
      setScheduled(data.schedule)
      setAwaitingPayment(data.state==='payment_pending')
      setNotice(data.state==='payment_pending'?'Stripe is waiting for payment. Your current plan remains active pending confirmation.':
        data.state==='upgrade'?'Stripe accepted the upgrade. Your plan updates when Stripe confirms the subscription.':
        data.state==='scheduled'?'Stripe scheduled the downgrade.':'The scheduled downgrade was canceled.')
    })
  }

  return <section className="panel release-panel" aria-label="Subscription plan changes">
    <h2>Change subscription plan</h2>
    {!open && <button type="button" className="secondary" disabled={busy} onClick={()=>void authorize('billing',load)}>Manage plan changes</button>}
    {open && <>
      <button type="button" className="secondary" disabled={busy} onClick={()=>void authorize('billing',load)}>Refresh plan changes</button>
      {scheduled && <p>Scheduled downgrade to {describe(scheduled.requested)} on {date(scheduled.effective)}.</p>}
      {awaitingPayment && <p>Stripe is waiting for payment. Review the invoice in the Stripe billing portal.</p>}
      {!pending && !awaitingPayment && <div className="actions">
        <label>Requested plan <select value={selection} disabled={busy} onChange={event=>{setSelection(event.target.value);setPreview(null)}}>
          <option value="">Select a plan</option>
          {options.map(offer=><option key={offer.plan} value={offer.plan}>{offer.title}</option>)}
        </select></label>
        <button type="button" className="secondary" disabled={!selection||busy} onClick={()=>void authorize('billing',()=>quote('plan'))}>Preview change</button>
        {scheduled && <button type="button" className="secondary" disabled={busy} onClick={()=>void authorize('billing',()=>quote('abort'))}>Review cancellation</button>}
      </div>}
      {preview && <div aria-label="Plan change preview">
        <p>Current terms: {describe(preview.command.current)}</p>
        {preview.command.requested && <p>Requested terms: {describe(preview.command.requested)}</p>}
        {preview.command.kind==='upgrade'?
          <p>{preview.command.due===null?'Stripe did not return a complete proration estimate.':
            'Stripe estimates a net proration adjustment of '+formatBillingAmount(preview.command.due,preview.command.current.currency)+'.'}</p>:
          <p>{preview.command.kind==='abort'?'Keep your current plan.':
            (preview.command.replaces?'Replace the scheduled downgrade on ':'Downgrade after the current period on ')+date(preview.command.effective)+'.'}</p>}
        <button type="button" className="primary" disabled={busy} onClick={()=>void authorize('billing',()=>confirm(preview.id))}>
          {pending?'Check or retry plan change':preview.command.kind==='upgrade'?'Confirm upgrade':preview.command.kind==='abort'?'Cancel scheduled downgrade':'Confirm scheduled downgrade'}
        </button>
        {!pending && <button type="button" className="secondary" disabled={busy} onClick={()=>setPreview(null)}>Dismiss preview</button>}
      </div>}
    </>}
    {notice && <p role="status">{notice}</p>}
    {error && <p role="alert">{error}</p>}
  </section>
}

function describe(terms:Terms) {
  return terms.plan[0].toUpperCase()+terms.plan.slice(1)+' · '+formatBillingAmount(terms.amount,terms.currency)+
    ' per '+(terms.cadence==='annual'?'year':'month')+' · terms version '+terms.version
}

function date(seconds:number) {return new Date(seconds*1000).toLocaleDateString()}
