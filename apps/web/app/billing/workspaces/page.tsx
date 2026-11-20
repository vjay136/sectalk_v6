'use client'

import {useEffect, useState} from 'react'
import {db} from '../../../lib/data'
import {useSensitiveAction} from '../../../components/sensitive-action'
import {WorkspaceSeats} from '../../../components/workspace-seats'
import {WorkspaceInvoiceAdjustments} from '../../../components/workspace-invoice-adjustments'
import {WorkspaceEnterpriseOrders} from '../../../components/workspace-enterprise-orders'
import {formatBillingAmount, isBillingCurrency} from '../../../lib/billing'

type Scope = {id: string; name: string; manages: boolean; delegated: boolean}
type Member = {id: string; name: string; handle: string; granted: boolean; eligible: boolean}
type Summary = {plan: string; plan_version: number; seats: number; seat_limit: number; recording_ms: number;
  transcription_samples: number; storage_byte_hours: number; storage_bytes: number; storage_quota_bytes: number;
  file_inspections: number}
type Invoice = {number: string | null; status: string | null; currency: string; total: number;
  amount_due: number; created: number}
type Provider = {provider: 'linked'; invoices: Invoice[]; more: boolean;
  payment: {status: string; collection: string; subscription_method_set: boolean}}
  | {provider: 'unavailable' | 'unlinked'}

const decimal = new Intl.NumberFormat(undefined, {maximumFractionDigits: 4})
const money = (amount: number, currency: string) => isBillingCurrency(currency.toUpperCase())
  ? formatBillingAmount(amount, currency.toUpperCase() as Parameters<typeof formatBillingAmount>[1])
  : decimal.format(amount) + ' minor units (' + currency.toUpperCase() + ')'

export default function WorkspaceBilling() {
  const [scopes, setScopes] = useState<Scope[] | null>(null)
  const [workspace, setWorkspace] = useState('')
  const [access, setAccess] = useState<{workspace: string; members: Member[] | null} | null>(null)
  const [selectedMember, setSelectedMember] = useState('')
  const [summary, setSummary] = useState<{workspace: string; data: Summary} | null>(null)
  const [provider, setProvider] = useState<{workspace: string; data: Provider} | null>(null)
  const [error, setError] = useState('')
  const [status, setStatus] = useState('')
  const [busy, setBusy] = useState(false)
  const {authorize, confirmation} = useSensitiveAction()
  const selected = scopes?.find(scope => scope.id === workspace)

  useEffect(() => {
    if (!db) {setScopes([]); return}
    const controller = new AbortController()
    void Promise.all([
      db.rpc('st_v7_billing_admin_view').abortSignal(controller.signal),
      db.rpc('st_v8_enterprise_billing_workspaces').abortSignal(controller.signal),
    ]).then(([billing,commercial]) => {
      if (controller.signal.aborted) return
      const merged=new Map<string,Scope>()
      for(const scope of (billing.data||[]) as Scope[])merged.set(scope.id,scope)
      for(const scope of (commercial.data||[]) as {id:string;name:string}[]) {
        if(!merged.has(scope.id))merged.set(scope.id,{...scope,manages:false,delegated:false})
      }
      setScopes([...merged.values()].sort((a,b)=>a.name.localeCompare(b.name)))
    })
    return () => controller.abort()
  }, [])

  useEffect(() => {
    if (!selected?.delegated || !db) return
    const controller = new AbortController()
    const supabase = db
    void supabase.rpc('st_v7_billing_admin_view', {p_workspace: selected.id})
      .abortSignal(controller.signal).then(result => {
        if (controller.signal.aborted) return
        if (result.error) setError('Billing access is unavailable for this workspace.')
        else setSummary({workspace: selected.id, data: result.data})
      })
    void supabase.auth.getSession().then(async result => {
      const token = result.data.session?.access_token
      if (!token || controller.signal.aborted) return
      const response = await fetch('/api/billing/workspace?workspace=' + selected.id,
        {signal: controller.signal, headers: {Authorization: 'Bearer ' + token}})
      if (!response.ok) throw new Error()
      const data = await response.json() as Provider
      if (!controller.signal.aborted) setProvider({workspace: selected.id, data})
    }).catch(() => {
      if (!controller.signal.aborted) setProvider({workspace: selected.id, data: {provider: 'unavailable'}})
    })
    return () => controller.abort()
  }, [selected])

  async function manage(enabled?: boolean) {
    if (!selected?.manages || !db) return
    const id = selected.id
    const target = selectedMember
    const supabase = db
    await authorize('billing', async () => {
      setBusy(true)
      setError('')
      setStatus('')
      try {
        const result = await supabase.rpc('st_v7_billing_admin_manage', {p_workspace: id,
          ...(enabled !== undefined ? {p_account: target, p_enabled: enabled} : {})})
        if (result.error) throw new Error()
        setAccess({workspace: id, members: result.data?.access === 'verified' ? result.data.members : null})
        if (result.data?.access !== 'verified') setError('Verify your current sign-in and try again.')
        else if (enabled !== undefined) setStatus(enabled ? 'Billing access granted.' : 'Billing access revoked.')
      } catch {setError('Could not update billing access.')}
      finally {setBusy(false)}
    })
  }

  const current = summary?.workspace === workspace ? summary.data : null
  const billingProvider = provider?.workspace === workspace ? provider.data : null
  const members = access?.workspace === workspace ? access.members : null
  const member = members?.find(row => row.id === selectedMember)
  return <main className="content-page">
    <a href="/?billing=workspace">Back to Billing</a>
    <h1>Workspace billing</h1>
    {scopes === null && <p role="status">Loading workspaces…</p>}
    {scopes?.length === 0 && <p role="status">Sign in as a workspace owner, billing administrator, or commercial operator.</p>}
    {Boolean(scopes?.length) && <>
      <label htmlFor="billing-scope">Workspace</label>
      <select id="billing-scope" value={workspace} disabled={busy} onChange={event => {
        setWorkspace(event.target.value)
        setSelectedMember('')
        setError('')
        setStatus('')
      }}>
        <option value="">Choose a workspace</option>
        {scopes?.map(scope => <option key={scope.id} value={scope.id}>{scope.name}</option>)}
      </select>
    </>}
    {selected&&(selected.manages||selected.delegated)&&<WorkspaceSeats key={selected.id} workspace={selected.id}/>}
    {selected&&<WorkspaceEnterpriseOrders key={'enterprise-'+selected.id} workspace={selected.id} name={selected.name}/>}
    {selected?.delegated&&<WorkspaceInvoiceAdjustments key={'adjustments-'+selected.id} workspace={selected.id}/>}
    {selected?.manages && <section aria-label="Billing administrator access" className="panel release-panel">
      <h2>Billing administrator access</h2>
      <p>A billing administrator can see this workspace’s plan, seats and usage, and a summary of invoices from your linked subscription.</p>
      {!members && <button type="button" disabled={busy} onClick={() => void manage()}>Manage billing access</button>}
      {members && <>
        <label htmlFor="billing-member">Workspace member</label>
        <select id="billing-member" value={selectedMember} disabled={busy} onChange={event => setSelectedMember(event.target.value)}>
          <option value="">Choose a member</option>
          {members.map(row => <option key={row.id} value={row.id}>{row.name} (@{row.handle}){row.granted ? ' · Billing administrator' : ''}</option>)}
        </select>
        {member && <button type="button" disabled={busy || (!member.granted && !member.eligible)}
          onClick={() => void manage(!member.granted)}>{member.granted ? 'Revoke billing access' : 'Grant billing access'}</button>}
      </>}
      {confirmation}
    </section>}
    {selected?.delegated && !current && !error && <p role="status">Loading billing details…</p>}
    {current && <section aria-label="Plan, seats and usage" className="panel release-panel">
      <h2>Plan, seats and usage</h2>
      <dl>
        <dt>Plan</dt><dd>{current.plan} (version {current.plan_version})</dd>
        <dt>Occupied seats</dt><dd>{current.seats} of {current.seat_limit}</dd>
        <dt>Recording minutes this month</dt><dd>{decimal.format(current.recording_ms / 60000)}</dd>
        <dt>Transcription minutes this month</dt><dd>{decimal.format(current.transcription_samples / 960000)}</dd>
        <dt>Storage used</dt><dd>{decimal.format(current.storage_bytes / 1e9)} of {decimal.format(current.storage_quota_bytes / 1e9)} GB</dd>
        <dt>Storage this month</dt><dd>{decimal.format(current.storage_byte_hours / 1e9)} GB-hours</dd>
        <dt>File inspections this month</dt><dd>{decimal.format(current.file_inspections)}</dd>
      </dl>
    </section>}
    {current && <section aria-label="Invoices and payment" className="panel release-panel">
      <h2>Invoices and payment</h2>
      <a href={'/billing/documents?workspace='+workspace}>Invoices and receipts</a>
      {!billingProvider && <p role="status">Loading payment status…</p>}
      {billingProvider?.provider === 'unlinked' && <p>This workspace has no linked paid subscription.</p>}
      {billingProvider?.provider === 'unavailable' && <p>Stripe billing details are currently unavailable.</p>}
      {billingProvider?.provider === 'linked' && <>
        <dl>
          <dt>Subscription status</dt><dd>{billingProvider.payment.status.replaceAll('_', ' ')}</dd>
          <dt>Payment collection</dt><dd>{billingProvider.payment.collection === 'charge_automatically' ? 'Automatic' : 'By invoice'}</dd>
          <dt>Subscription payment method</dt><dd>{billingProvider.payment.subscription_method_set ? 'Configured' : 'No dedicated method shown'}</dd>
        </dl>
        {billingProvider.invoices.length === 0 ? <p>No invoices for this subscription.</p> :
          <table>
            <caption>Recent subscription invoices</caption>
            <thead><tr><th>Invoice</th><th>Date</th><th>Status</th><th>Total</th><th>Amount due</th></tr></thead>
            <tbody>{billingProvider.invoices.map((invoice, index) => <tr key={invoice.number ?? index}>
              <td>{invoice.number ?? 'Pending number'}</td><td>{new Date(invoice.created * 1000).toLocaleDateString()}</td>
              <td>{invoice.status ?? 'Pending'}</td><td>{money(invoice.total, invoice.currency)}</td>
              <td>{money(invoice.amount_due, invoice.currency)}</td>
            </tr>)}</tbody>
          </table>}
        {billingProvider.more && <p>Showing the most recent invoices.</p>}
      </>}
    </section>}
    {error && <p role="alert">{error}</p>}
    {status && <p role="status">{status}</p>}
  </main>
}
