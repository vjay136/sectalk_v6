'use client'

import {useEffect,useState} from 'react'
import {db} from '../../../lib/data'
import {formatBillingAmount,isBillingCurrency} from '../../../lib/billing'
import type {InvoiceDocument} from '../../../lib/stripe-invoice-documents'
import {useWorkspaceBillingAccess} from '../../../components/workspace-billing-access'
import {workspaceBillingSsoMessage} from '../../../lib/workspace-billing-access'

type Invoice = Omit<InvoiceDocument,'id'> & {invoice_ticket:string; receipt_ticket:string|null}
type Listing = {invoices:Invoice[];next:string|null}
type Scope = {id:string;name:string;delegated:boolean}
const amount = (minor: number, currency: string) => isBillingCurrency(currency)
  ? formatBillingAmount(minor,currency) : currency+' '+minor+' minor units'

async function billingRequest(workspace:string, name?:'ticket'|'cursor', value?:string, signal?:AbortSignal) {
  const token = (await db?.auth.getSession())?.data.session?.access_token
  if (!token) throw new Error('Sign in to view billing documents.')
  const query = new URLSearchParams()
  if (workspace) query.set('workspace',workspace)
  if (name && value) query.set(name,value)
  const result = await fetch('/api/billing/invoices?'+query,{signal,headers:{Authorization:'Bearer '+token,...(name==='ticket'?{Accept:'application/octet-stream'}:{})}})
  if (result.status===404) throw new Error('This link may have expired. Refresh documents and try again.')
  if (result.status===403) throw new Error('Billing document access is unavailable for this scope.')
  if (!result.ok) throw new Error('Billing documents are temporarily unavailable.')
  return result
}

export default function BillingDocuments() {
  const [workspaces,setWorkspaces] = useState<Scope[]>([])
  const [workspace,setWorkspace] = useState('')
  const [initialized,setInitialized] = useState(false)
  const [listing,setListing] = useState<Listing|null>(null)
  const [revision,setRevision] = useState(0)
  const [busy,setBusy] = useState(false)
  const [error,setError] = useState('')
  const billingAccess=useWorkspaceBillingAccess(workspace||undefined)
  const canRead=!workspace||billingAccess==='allowed'

  useEffect(()=>{
    if (!db) {setInitialized(true);return}
    const controller=new AbortController()
    void db.rpc('st_v7_billing_admin_view').abortSignal(controller.signal).then(result=>{
      if (controller.signal.aborted) return
      const options=(result.error ? [] : result.data as Scope[]).filter(scope=>scope.delegated)
      const initial=new URLSearchParams(window.location.search).get('workspace')
      setWorkspaces(options)
      if(initial) setWorkspace(initial)
      setInitialized(true)
    })
    return ()=>controller.abort()
  },[])

  useEffect(()=>{
    if(!initialized||!canRead) return
    const controller=new AbortController()
    void billingRequest(workspace,undefined,undefined,controller.signal).then(response=>response.json()).then(result=>{
      if(!controller.signal.aborted) setListing(result)
    }).catch(error=>{
      if(!controller.signal.aborted) setError((error as Error).message)
    })
    return ()=>controller.abort()
  },[canRead,initialized,workspace,revision])

  async function older() {
    if (!listing?.next) return
    setBusy(true)
    setError('')
    try {
      const result=await billingRequest(workspace,'cursor',listing.next).then(response=>response.json()) as Listing
      setListing({invoices:[...listing.invoices,...result.invoices],next:result.next})
    } catch(error) {setError((error as Error).message)}
    finally {setBusy(false)}
  }

  async function download(ticket:string,invoice:string,label:'invoice'|'receipt') {
    setBusy(true)
    setError('')
    try {
      const response=await billingRequest(workspace,'ticket',ticket)
      const bytes=await response.arrayBuffer()
      if(new TextDecoder().decode(bytes.slice(0,5))!=='%PDF-') throw new Error('The downloaded document is unavailable.')
      const url=URL.createObjectURL(new Blob([bytes],{type:'application/pdf'}))
      const link=document.createElement('a')
      link.href=url
      link.download='sectalk-'+label+'-'+invoice+'.pdf'
      link.click()
      window.setTimeout(()=>URL.revokeObjectURL(url),1000)
    } catch(error) {setError((error as Error).message)}
    finally {setBusy(false)}
  }

  return <main className="content-page">
    <a href="/?billing=documents">Back to Billing</a>
    <h1>Invoices and receipts</h1>
    <p>Download SecTalk copies of finalized Stripe invoices and paid-invoice receipts.</p>
    {(workspaces.length>0 || Boolean(workspace)) && <>
      <label htmlFor="invoice-scope">Billing scope</label>
      <select id="invoice-scope" value={workspace} disabled={busy} onChange={event=>{
        setWorkspace(event.target.value)
        setListing(null)
        setError('')
      }}>
        <option value="">My account</option>
        {workspace && !workspaces.some(scope=>scope.id===workspace) && <option value={workspace}>Unavailable workspace</option>}
        {workspaces.map(scope=><option key={scope.id} value={scope.id}>{scope.name}</option>)}
      </select>
    </>}
    <button type="button" disabled={!initialized||!canRead||busy} onClick={()=>{setError('');setListing(null);setRevision(value=>value+1)}}>
      Refresh documents
    </button>
    {workspace&&billingAccess==='required'&&<p role="status">{workspaceBillingSsoMessage}</p>}
    {workspace&&billingAccess==='unavailable'&&<p role="alert">Billing document access is unavailable for this scope.</p>}
    {(workspace&&billingAccess===undefined||canRead&&!listing&&!error)&&<p role="status">Loading billing documents…</p>}
    {canRead&&error&&<p role="alert">{error}</p>}
    {canRead&&listing?.invoices.length===0&&<p>No finalized invoices for this subscription.</p>}
    {canRead&&listing?.invoices.map(invoice=><article key={invoice.number} className="panel release-panel">
      <h2>Invoice {invoice.number}</h2>
      <p>Stripe · {invoice.issued_at.slice(0,10)} UTC · {invoice.status.replaceAll('_',' ')}</p>
      <dl>
        <dt>Total</dt><dd>{amount(invoice.total,invoice.currency)}</dd>
        <dt>Amount paid</dt><dd>{amount(invoice.amount_paid,invoice.currency)}</dd>
        <dt>Amount due</dt><dd>{amount(invoice.amount_due,invoice.currency)}</dd>
        {invoice.company&&<><dt>Legal name</dt><dd>{invoice.company}</dd></>}
        {invoice.gstin&&<><dt>GSTIN</dt><dd>{invoice.gstin}</dd></>}
      </dl>
      <details>
        <summary>Tax breakdown</summary>
        {invoice.taxes===null ? <p>Stripe did not supply a tax breakdown.</p> :
          invoice.taxes.length===0 ? <p>Stripe reported no tax lines.</p> :
          <ul>{invoice.taxes.map((tax,index)=><li key={index}>{tax.label&&tax.label+' · '}{amount(tax.amount,invoice.currency)} · {tax.behavior} · {tax.reason}
            {tax.taxable===null ? '' : ' · Taxable amount '+amount(tax.taxable,invoice.currency)}</li>)}</ul>}
      </details>
      <div className="actions">
        <button type="button" disabled={busy} onClick={()=>void download(invoice.invoice_ticket,invoice.number,'invoice')}>Download invoice PDF</button>
        {invoice.receipt_ticket&&<button type="button" disabled={busy}
          onClick={()=>void download(invoice.receipt_ticket!,invoice.number,'receipt')}>Download receipt PDF</button>}
      </div>
    </article>)}
    {canRead&&listing?.next&&<button type="button" disabled={busy} onClick={()=>void older()}>Load older invoices</button>}
  </main>
}
