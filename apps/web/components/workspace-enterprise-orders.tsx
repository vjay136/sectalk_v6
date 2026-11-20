'use client'

import {useRef,useState,type FormEvent} from 'react'
import {billingCurrencies,formatBillingAmount,type BillingCurrency} from '../lib/billing'
import {db,formatError} from '../lib/data'
import {useSensitiveAction} from './sensitive-action'

type Order={
  id:string;reference:string;currency:BillingCurrency;annual_total:number;committed_seats:number;terms:string;
  starts_on:string;ends_on:string;expires_on:string;state:'quoted'|'accepted'|'invoiced'|'paid'|'withdrawn';
  po:string|null;invoice_number:string|null;due_on:string|null
}
type Ledger={access:'mfa'|'verified';eligible:boolean;roles?:string[];orders?:Order[]}
const states={quoted:'Awaiting acceptance',accepted:'Accepted',invoiced:'Invoice issued',paid:'Paid',withdrawn:'Withdrawn'}
const actions={
  accept:{field:'po',label:'Purchase order reference',button:'Accept annual order'},
  invoice:{field:'due',label:'Invoice due date',button:'Issue manual invoice'},
  paid:{field:'payment',label:'Payment reconciliation reference',button:'Record full offline payment'},
  withdraw:{field:'reason',label:'Withdrawal reason',button:'Withdraw quote'},
}

function download(order:Order,workspace:string,invoice:boolean) {
  const title=invoice?'Manual invoice '+order.invoice_number:'Enterprise order form '+order.reference
  const contents=[title,'Workspace: '+workspace,'Order reference: '+order.reference,
    'Status: '+states[order.state],'Annual commitment: '+order.starts_on+' to '+order.ends_on,
    'Committed seats: '+order.committed_seats,'Annual total: '+formatBillingAmount(order.annual_total,order.currency),
    order.po?'Purchase order: '+order.po:'',invoice?'Due date: '+order.due_on:'','Terms:',order.terms,
  ].filter(Boolean).join('\n')
  const url=URL.createObjectURL(new Blob([contents],{type:'text/plain;charset=utf-8'}))
  const link=document.createElement('a')
  link.href=url
  link.download=(invoice?'enterprise-invoice-':'enterprise-order-')+order.id+'.txt'
  link.click()
  window.setTimeout(()=>URL.revokeObjectURL(url),1000)
}

export function WorkspaceEnterpriseOrders({workspace,name}:{workspace:string;name:string}) {
  const {authorize,confirmation}=useSensitiveAction()
  const [ledger,setLedger]=useState<Ledger>()
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)
  const [status,setStatus]=useState('')
  const quote=useRef<{key:string;id:string}|null>(null)
  const isCommercial=ledger?.roles?.includes('commercial')
  const isOwner=ledger?.roles?.includes('owner')

  async function load() {
    const response=await db!.rpc('st_v8_enterprise_billing_view',{p_workspace:workspace})
    if(response.error)throw response.error
    if(response.data?.access!=='verified')throw new Error('Verify this billing session to open enterprise orders.')
    setLedger(response.data)
    return response.data as Ledger
  }
  function run(operation:()=>Promise<void>) {
    return authorize('billing',async()=>{
      if(busy)return
      setBusy(true);setError('');setStatus('')
      try {await operation()}
      catch(cause) {
        if(cause&&typeof cause==='object'&&'code' in cause&&cause.code==='42501')setLedger(undefined)
        setError(formatError(cause,'Could not update enterprise orders.'))
      }
      finally {setBusy(false)}
    })
  }
  async function command(id:string,action:string,payload:Record<string,string>) {
    const response=await db!.rpc('st_v8_enterprise_billing_command',
      {p_workspace:workspace,p_order:id,p_action:action,p_data:payload})
    if(response.error)throw response.error
    await load()
    setStatus('Enterprise order updated.')
  }
  function submitQuote(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form=event.currentTarget
    const data=Object.fromEntries(new FormData(form)) as Record<string,string>
    const digits=new Intl.NumberFormat(undefined,{style:'currency',currency:data.currency})
      .resolvedOptions().maximumFractionDigits??2
    const amount=/^(\d{1,10})(?:\.(\d{1,2}))?$/.exec(data.total.trim())
    const fraction=amount?.[2]||''
    if(!amount||fraction.length>digits) {setError('Enter a valid annual total for the selected currency.');return}
    const minor=Number(amount[1])*10**digits+Number(fraction.padEnd(digits,'0'))
    if(minor<1||minor>1000000000) {setError('Enter an annual total within the allowed range.');return}
    data.total=String(minor)
    const key=JSON.stringify(data)
    if(quote.current?.key!==key)quote.current={key,id:crypto.randomUUID()}
    const id=quote.current.id
    void run(async()=>{await command(id,'quote',data);quote.current=null;form.reset()})
  }
  function orderAction(order:Order,action:keyof typeof actions) {
    const {field,label,button}=actions[action]
    return <form key={action} className="release-form" onSubmit={event=>{
      event.preventDefault()
      const fieldValue=String(new FormData(event.currentTarget).get(field)??'')
      void run(()=>command(order.id,action,{[field]:fieldValue}))
    }}>
      <label>{label}<input name={field} type={action==='invoice'?'date':'text'} required maxLength={action==='withdraw'?300:100}/></label>
      <button className="secondary" disabled={busy}>{button}</button>
    </form>
  }
  async function retrieve(orderId:string,invoice:boolean) {
    const current=(await load()).orders?.find(order=>order.id===orderId)
    if(!current||(invoice&&!current.invoice_number))throw new Error('This document is unavailable.')
    download(current,name,invoice)
  }

  return <section className="panel release-panel" aria-label="Enterprise contracts">
    <h2>Enterprise contracts</h2>
    {confirmation}
    <button type="button" className="secondary" disabled={busy} onClick={()=>void run(async()=>{await load()})}>
      {ledger?'Refresh enterprise orders':'Open enterprise orders'}
    </button>
    {error&&<p role="alert">{error}</p>}
    {status&&<p role="status">{status}</p>}
    {ledger&&<>
      {!ledger.eligible&&<p>New orders require an existing Enterprise plan.</p>}
      {ledger.eligible&&isCommercial&&<details className="release-create">
        <summary>Prepare annual order form</summary>
        <form className="release-form" onSubmit={submitQuote}>
          <label>Order reference<input name="reference" minLength={3} maxLength={80} required/></label>
          <label>Annual total<input name="total" inputMode="decimal" maxLength={13} required/></label>
          <label>Currency<select name="currency">{billingCurrencies.map(currency=><option key={currency}>{currency}</option>)}</select></label>
          <label>Committed seats<input name="seats" type="number" min={1} max={100000} required/></label>
          <label>Commitment start date<input name="starts" type="date" required/></label>
          <label>Quote expiry date<input name="expires" type="date" required/></label>
          <label>Order terms<textarea name="terms" minLength={12} maxLength={1500} required/></label>
          <button className="primary" disabled={busy}>Save annual quote</button>
        </form>
      </details>}
      {!ledger.orders?.length&&<p>No enterprise orders.</p>}
      {ledger.orders?.map(order=><article key={order.id} className="release-card" aria-label={order.reference}>
        <h3>{order.reference}</h3>
        <p>{states[order.state]} · {formatBillingAmount(order.annual_total,order.currency)} per year · {order.committed_seats} seats</p>
        <p>{order.starts_on} to {order.ends_on}</p>
        {order.state==='quoted'&&<p>Quote expires {order.expires_on}</p>}
        <p>{order.terms}</p>
        {order.po&&<p>Purchase order {order.po}</p>}
        {order.invoice_number&&<p>Invoice {order.invoice_number} · Due {order.due_on}</p>}
        <button type="button" className="secondary" disabled={busy} onClick={()=>void run(()=>retrieve(order.id,false))}>Download order form</button>
        {order.invoice_number&&<button type="button" className="secondary" disabled={busy} onClick={()=>void run(()=>retrieve(order.id,true))}>Download manual invoice</button>}
        {order.state==='quoted'&&isOwner&&orderAction(order,'accept')}
        {order.state==='quoted'&&isCommercial&&orderAction(order,'withdraw')}
        {order.state==='accepted'&&isCommercial&&orderAction(order,'invoice')}
        {order.state==='invoiced'&&isCommercial&&orderAction(order,'paid')}
      </article>)}
    </>}
  </section>
}
