'use client'

import {useState} from 'react'
import {formatBillingAmount} from '../lib/billing'
import {db} from '../lib/data'
import {useSensitiveAction} from './sensitive-action'

type Terms={configured:boolean;quantity:number|null;occupied:number;cap:number;awaiting:number;trueUp:number;
  amount:number;currency:string;cadence:'monthly'|'annual';until:string|null;pending:number|null;intent:'manual'|'true_up'|null}
type Choice={quantity:number;intent:'manual'|'true_up'}

export function WorkspaceSeats({workspace}:{workspace:string}) {
  const {authorize,confirmation}=useSensitiveAction()
  const [terms,setTerms]=useState<Terms|null>(null)
  const [quantity,setQuantity]=useState('')
  const [choice,setChoice]=useState<Choice|null>(null)
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [notice,setNotice]=useState('')

  async function request<T>(body:object) {
    const {data}=await db!.auth.getSession()
    const response=await fetch('/api/billing/workspace',{
      method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+data.session?.access_token},
      body:JSON.stringify({workspace,...body}),
    })
    const payload=await response.json()
    if (!response.ok) throw new Error(payload.error||'Could not manage workspace seats.')
    return payload as T
  }
  async function load(saveNotice=false) {
    setBusy(true)
    setError('')
    if (!saveNotice) setNotice('')
    try {
      const result=await request<Terms>({stage:'status'})
      setTerms(result)
      setQuantity(String(result.quantity??result.occupied))
      setChoice(result.pending&&result.intent?{quantity:result.pending,intent:result.intent}:null)
    } catch (error) {setError(error instanceof Error?error.message:'Could not view workspace seats.')}
    finally {setBusy(false)}
  }
  async function confirm() {
    if (!terms||!choice) return
    setBusy(true)
    setError('')
    try {
      const updated=await request<{quantity:number}>({stage:'confirm',...choice,amount:terms.amount,currency:terms.currency,cadence:terms.cadence})
      await load(true)
      setNotice('Stripe confirmed '+updated.quantity+(updated.quantity===1?' workspace seat.':' workspace seats.'))
    } catch (error) {setError(error instanceof Error?error.message:'Could not change workspace seats.')}
    finally {setBusy(false)}
  }
  const desired=Number(quantity)
  const valid=terms&&Number.isInteger(desired)&&desired>=Math.max(1,terms.occupied)&&desired<=terms.cap&&desired!==terms.quantity
  const interval=terms?.cadence==='annual'?'year':'month'
  return <section className="panel release-panel" aria-label="Workspace seats">
    <h2>Workspace seats</h2>
    {confirmation}
    <button type="button" disabled={busy} onClick={()=>void authorize('billing',()=>load())}>{terms?'Refresh seats':'Review workspace seats'}</button>
    {terms&&!terms.configured&&<p>Paid seats are unavailable for this workspace’s billing plan.</p>}
    {terms?.configured&&<>
      <p>{terms.occupied} occupied · {terms.quantity===null?'Paid seat billing inactive':terms.quantity+' billed seats'} · Plan cap {terms.cap}</p>
      <p>{terms.awaiting} eligible pending invitations. Invitations use an available seat when accepted. Additional seats require billing approval.</p>
      <p>{formatBillingAmount(terms.amount,terms.currency)} per seat per {interval}</p>
      {!terms.pending&&<>
        <label>Total billed seats <input type="number" min={Math.max(1,terms.occupied)} max={terms.cap} value={quantity}
          disabled={busy} onChange={event=>{setQuantity(event.target.value);setChoice(null)}}/></label>
        <button type="button" disabled={busy||!valid} onClick={()=>setChoice({quantity:desired,intent:'manual'})}>Review quantity change</button>
        {terms.awaiting>0&&terms.trueUp>(terms.quantity??terms.occupied)&&
          <button type="button" disabled={busy} onClick={()=>setChoice({quantity:terms.trueUp,intent:'true_up'})}>Review seats for invitations</button>}
      </>}
      {choice&&<div aria-label="Seat change confirmation">
        <p>{terms.pending?'Retry pending change to':'Approve'} {choice.quantity} billed seats at{' '}
          {formatBillingAmount(choice.quantity*terms.amount,terms.currency)} per {interval}.</p>
        {terms.quantity!==null&&<p>Stripe applies the mid-period price adjustment when you confirm.</p>}
        <button type="button" disabled={busy} onClick={()=>void authorize('billing',confirm)}>{terms.pending?'Retry seat change':'Approve seat charge'}</button>
      </div>}
    </>}
    {error&&<p role="alert">{error}</p>}
    {notice&&<p role="status">{notice}</p>}
  </section>
}
