'use client'

import {useEffect, useState} from 'react'
import {db} from '../../../lib/data'
import {useWorkspaceBillingAccess} from '../../../components/workspace-billing-access'
import {workspaceBillingSsoMessage} from '../../../lib/workspace-billing-access'

type Workspace = {id: string; name: string}
type Usage = {
  period_start: string; plan: string; plan_version: number
  recording_ms: number; transcription_samples: number
  storage_bytes: number; storage_quota_bytes: number; storage_byte_hours: number
  ai_scans: number; ai_scan_allowance: number | null; ai_scan_overage: number | null
}

const decimal = new Intl.NumberFormat(undefined, {maximumFractionDigits: 4})
const date = new Intl.DateTimeFormat(undefined, {month: 'long', year: 'numeric', timeZone: 'UTC'})

export default function WorkspaceUsage() {
  const [workspaces, setWorkspaces] = useState<Workspace[] | null>(null)
  const [selected, setSelected] = useState('')
  const [result, setResult] = useState<{id: string; usage: Usage | null} | null>(null)
  const [revision, setRevision] = useState(0)
  const billingAccess=useWorkspaceBillingAccess(selected||undefined)

  useEffect(() => {
    if (!db) { setWorkspaces([]); return }
    const controller = new AbortController()
    void db.rpc('st_v7_workspace_usage').abortSignal(controller.signal).then(({data, error}) => {
      if (!controller.signal.aborted) setWorkspaces(error ? [] : data)
    })
    return () => controller.abort()
  }, [])

  useEffect(() => {
    if (!selected || billingAccess!=='allowed' || !db) return
    const controller = new AbortController()
    void db.rpc('st_v7_workspace_usage', {p_workspace: selected}).abortSignal(controller.signal).then(({data, error}) => {
      if (!controller.signal.aborted) setResult({id: selected, usage: error ? null : data})
    })
    return () => controller.abort()
  }, [billingAccess, revision, selected])

  const current = billingAccess==='allowed' && result?.id === selected ? result : null
  const usage = current?.usage
  return <main className="content-page">
    <a href="/?billing=usage">Back to Billing</a>
    <h1>Workspace usage</h1>
    {workspaces === null && <p role="status">Loading workspaces…</p>}
    {workspaces?.length === 0 && <p role="status">Sign in as a workspace owner to view its usage.</p>}
    {Boolean(workspaces?.length) && <>
      <label htmlFor="billing-usage-workspace">Workspace</label>
      <select id="billing-usage-workspace" value={selected} onChange={event => setSelected(event.target.value)}>
        <option value="">Choose a workspace</option>
        {workspaces?.map(workspace => <option key={workspace.id} value={workspace.id}>{workspace.name}</option>)}
      </select>
      <button type="button" disabled={!selected} onClick={() => setRevision(value => value + 1)}>Refresh usage</button>
    </>}
    {selected && billingAccess==='required' && <p role="status">{workspaceBillingSsoMessage}</p>}
    {selected && billingAccess==='unavailable' && <p role="alert">Usage is unavailable for this workspace.</p>}
    {selected && (billingAccess===undefined || billingAccess==='allowed' && !current) && <p role="status">Loading usage…</p>}
    {current && !usage && <p role="alert">Usage is unavailable for this workspace.</p>}
    {usage && <section aria-label="Metered usage" className="panel release-panel">
      <h2>{date.format(new Date(usage.period_start))} usage (UTC)</h2>
      <p>Current plan {usage.plan}, version {usage.plan_version}</p>
      <dl>
        <dt>Recording minutes</dt><dd>{decimal.format(usage.recording_ms / 60000)}</dd>
        <dt>Transcription minutes</dt><dd>{decimal.format(usage.transcription_samples / 960000)}</dd>
        <dt>Current stored data</dt><dd>{decimal.format(usage.storage_bytes / 1e9)} GB</dd>
        <dt>Plan storage allowance</dt><dd>{decimal.format(usage.storage_quota_bytes / 1e9)} GB</dd>
        <dt>Storage over time</dt><dd>{decimal.format(usage.storage_byte_hours / 1e9)} GB-hours</dd>
        <dt>Completed file inspections</dt><dd>{decimal.format(usage.ai_scans)}</dd>
        <dt>Included file inspections on current plan</dt><dd>{usage.ai_scan_allowance ?? 'Allowance pending'}</dd>
        <dt>File inspection overage</dt><dd>{usage.ai_scan_overage ?? 'Allowance pending'}</dd>
      </dl>
      <p>Storage over time uses hourly samples of workspace files, room files, and recordings.</p>
    </section>}
  </main>
}
