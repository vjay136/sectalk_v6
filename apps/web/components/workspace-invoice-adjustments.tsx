'use client'

import {useState} from 'react'
import {formatBillingAmount} from '../lib/billing'
import {db} from '../lib/data'
import {useSensitiveAction} from './sensitive-action'

type Kind='refund'|'credit'|'adjustment'
type Invoice={id:string;number:string;status:'paid'|'open';currency:string;limit:number}
type History={id:string;kind:Kind;reason:string;currency:string;amount:number;state:string;created_at:string;owned:boolean}
type Preview={id:string;number:string;kind:Kind;reason:string;currency:string;amount:number}
type Summary={invoices:Invoice[];history:History[]}
const labels={refund:'Refund to original payment',credit:'Credit the Stripe customer balance',adjustment:'Reduce amount due'}
const reasons={order_change:'Order change',duplicate:'Duplicate',product_unsatisfactory:'Product unsatisfactory',fraudulent:'Fraudulent'}
const states:Record<string,string>={issued:'Issued',void:'Voided',running:'Processing',rejected:'Rejected',
  refund_pending:'Refund pending',refund_failed:'Refund failed',refunded:'Refunded'}

export function WorkspaceInvoiceAdjustments({workspace}:{workspace:string}) {
  const {authorize,confirmation}=useSensitiveAction()
  const [summary,setSummary]=useState<Summary|null>(null)
  const [selected,setSelected]=useState('')
  const [kind,setKind]=useState<Kind>('refund')
  const [reason,setReason]=useState('order_change')
  const [amount,setAmount]=useState('')
  const [preview,setPreview]=useState<Preview|null>(null)
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [notice,setNotice]=useState('')
  const invoice=summary?.invoices.find(row=>row.id===selected)
  const minor=invoice?minorUnits(amount,invoice.currency):null

  async function action<T>(body:object) {
    const {data}=await db!.auth.getSession()
    const response=await fetch('/api/billing/workspace?section=adjustments',{
      method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+data.session?.access_token},
      body:JSON.stringify({workspace,...body}),
    })
    const payload=await response.json()
    if (!response.ok) throw new Error(payload.error || 'Could not process invoice changes.')
    return payload as T
  }
  async function run(operation:()=>Promise<void>) {
    setBusy(true)
    setError('')
    setNotice('')
    try {await operation()}
    catch(error) {setError(error instanceof Error?error.message:'Could not process invoice changes.')}
    finally {setBusy(false)}
  }
  function reload() {
    return run(async()=>{setSummary(await action<Summary>({stage:'status'}));setPreview(null)})
  }
  function review() {
    if (!invoice||!minor) return Promise.resolve()
    return run(async()=>setPreview(await action<Preview>({stage:'preview',invoice:invoice.id,kind,reason,amount:minor,currency:invoice.currency})))
  }
  function confirm(id:string) {
    return run(async()=>{
      const result=await action<{state:string}>({stage:'confirm',id})
      setPreview(null)
      setSummary(await action<Summary>({stage:'status'}))
      setNotice(states[result.state]??'Stripe processed the request.')
    })
  }

  return <section className="panel release-panel" aria-label="Invoice adjustments">
    <h2>Invoice adjustments</h2>
    {confirmation}
    <button type="button" disabled={busy} onClick={()=>void authorize('billing',reload)}>{summary?'Refresh adjustments':'Review invoice adjustments'}</button>
    {summary&&<>
      {!summary.invoices.length?<p>No eligible workspace seat invoices.</p>:<>
        <label>Workspace seat invoice <select value={selected} disabled={busy} onChange={event=>{
          const id=event.target.value
          setSelected(id)
          setKind(summary.invoices.find(row=>row.id===id)?.status==='open'?'adjustment':'refund')
          setAmount('')
          setPreview(null)
        }}><option value="">Choose an invoice</option>
          {summary.invoices.map(row=><option key={row.id} value={row.id}>{row.number} · {row.status}</option>)}
        </select></label>
        {invoice&&<>
          <label>Invoice action <select value={kind} disabled={busy} onChange={event=>{setKind(event.target.value as Kind);setPreview(null)}}>
            {(invoice.status==='open'?(['adjustment'] as const):(['refund','credit'] as const))
              .map(value=><option key={value} value={value}>{labels[value]}</option>)}
          </select></label>
          <label>Reason <select value={reason} disabled={busy} onChange={event=>{setReason(event.target.value);setPreview(null)}}>
            {Object.entries(reasons).map(([value,label])=><option key={value} value={value}>{label}</option>)}
          </select></label>
          <label>Amount in {invoice.currency} <input inputMode="decimal" value={amount} maxLength={12} disabled={busy}
            onChange={event=>{setAmount(event.target.value);setPreview(null)}}/></label>
          <p>Available to adjust {formatBillingAmount(invoice.limit,invoice.currency)}.</p>
          <button type="button" disabled={busy||!minor||minor>invoice.limit} onClick={()=>void authorize('billing',review)}>Preview invoice change</button>
        </>}
      </>}
      {preview&&<div aria-label="Review invoice adjustment">
        <p>{labels[preview.kind]} · {formatBillingAmount(preview.amount,preview.currency)} · Invoice {preview.number}.</p>
        {preview.kind==='credit'&&<p>Stripe applies the credit to future invoices for this billing customer.</p>}
        <button type="button" disabled={busy} onClick={()=>void authorize('billing',()=>confirm(preview.id))}>Confirm invoice change</button>
      </div>}
      {summary.history.length>0&&<ul aria-label="Invoice change history">
        {summary.history.map(row=><li key={row.id}>
          {labels[row.kind]} · {formatBillingAmount(row.amount,row.currency)} · {states[row.state]??row.state} ·{' '}
          <time dateTime={row.created_at}>{new Date(row.created_at).toLocaleDateString()}</time>
          {row.state==='running'&&row.owned&&<button type="button" disabled={busy} onClick={()=>void authorize('billing',()=>confirm(row.id))}>Retry invoice change</button>}
        </li>)}
      </ul>}
    </>}
    {error&&<p role="alert">{error}</p>}
    {notice&&<p role="status">{notice}</p>}
  </section>
}

function minorUnits(value:string,currency:string) {
  const digits=new Intl.NumberFormat(undefined,{style:'currency',currency}).resolvedOptions().maximumFractionDigits??2
  const match=/^(\d{1,9})(?:\.(\d{1,3}))?$/.exec(value)
  if (!match || (match[2]?.length??0)>digits) return null
  return Number(match[1])*10**digits+Number((match[2]??'').padEnd(digits,'0'))
}
