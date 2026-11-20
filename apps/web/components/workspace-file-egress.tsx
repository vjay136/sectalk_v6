'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'
import { StaffMfa } from './staff-mfa'

type Policy = {
  mode: 'inherit' | 'require' | 'block'
  device?: string
  risk_max?: number
  network?: string
  utc_start?: number
  utc_end?: number
  classification_max?: string
  tenant_type?: string
}
type Operator = { access: 'none' } | { access: 'mfa' } | { access: 'verified'; revision: number; policy: Policy }
const reasons: Record<string, string> = {
  access_unavailable: 'File access is unavailable.',
  inherited_access: 'Existing file permissions allow this action.',
  custom_role_required: 'This file requires a matching custom role.',
  tenant_block: 'The workspace blocks file sharing and downloads.',
  requirements_met: 'Your session and this file meet the workspace policy.',
  device_trust: 'This session does not meet the device trust requirement.',
  session_risk: 'This session does not meet the risk requirement.',
  session_network: 'This session does not meet the network requirement.',
  utc_window: 'The current time is outside the UTC access window.',
  classification: 'The file exceeds the allowed classification.',
  tenant_type: 'The workspace does not match the required type.',
}
const optional = (fields: FormData, key: string) => String(fields.get(key) ?? '').trim()
const numeric = (fields: FormData, key: string) => optional(fields, key) === '' ? undefined : Number(fields.get(key))

export function WorkspaceFileEgress({ workspace }: { workspace: string }) {
  const [operator, setOperator] = useState<Operator | null>(null)
  const [policy, setPolicy] = useState<Policy>({ mode: 'inherit' })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [templates, setTemplates] = useState<{ id: string; label: string }[]>([])
  const load = useCallback(async () => {
    const result = await db!.rpc('st_v7_file_egress_policy', { p_workspace: workspace })
    if (result.error) {
      setError('Could not load the workspace file policy.')
      return
    }
    const state = result.data as Operator
    setOperator(state)
    if (state.access === 'verified') setPolicy(state.policy)
  }, [workspace])
  useEffect(() => { void load() }, [load])
  useEffect(() => {
    void db!.from('st_v6_workspace_templates').select('id,label').order('sort_order').then(result => {
      if (result.data) setTemplates(result.data)
    })
  }, [])

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (operator?.access !== 'verified' || busy) return
    const fields = new FormData(event.currentTarget)
    const next: Policy = policy.mode === 'require' ? {
      mode: policy.mode,
      device: optional(fields, 'device') || undefined,
      risk_max: numeric(fields, 'risk_max'),
      network: optional(fields, 'network') || undefined,
      utc_start: numeric(fields, 'utc_start'),
      utc_end: numeric(fields, 'utc_end'),
      classification_max: optional(fields, 'classification_max') || undefined,
      tenant_type: optional(fields, 'tenant_type') || undefined,
    } : { mode: policy.mode }
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const result = await db!.rpc('st_v7_save_file_egress_policy', {
        p_workspace: workspace, p_revision: operator.revision, p_policy: next,
      })
      if (result.error) throw result.error
      await load()
      setNotice('File policy saved.')
    } catch (failure) {
      setError(formatError(failure, 'Could not save the workspace file policy.'))
    } finally {
      setBusy(false)
    }
  }

  return <section className="release-section" aria-label="Workspace file policy">
    <h2>Workspace file policy</h2>
    <p>Set extra requirements for workspace and room file downloads and for copying workspace file links.</p>
    {error && <p className="error" role="alert">{error}</p>}
    {notice && <p role="status">{notice}</p>}
    {!operator && !error && <p role="status">Loading file policy…</p>}
    {operator?.access === 'none' && <p>Access requires workspace ownership and an active session.</p>}
    {operator?.access === 'mfa' && <StaffMfa refresh={load} explanation="Verify your authenticator to manage the workspace file policy."/>}
    {operator?.access === 'verified' && <form key={operator.revision} className="release-form" onSubmit={save}>
      <label>File policy<select value={policy.mode} onChange={event => setPolicy({ ...policy, mode: event.target.value as Policy['mode'] })}>
        <option value="inherit">Use existing permissions</option><option value="require">Require all selected attributes</option>
        <option value="block">Block sharing and downloads</option>
      </select></label>
      {policy.mode === 'require' && <>
        <label>Device trust<select name="device" defaultValue={policy.device ?? ''}>
          <option value="">Any device</option><option value="trusted">Trusted or managed</option><option value="managed">Managed only</option>
        </select></label>
        <label>Maximum session risk score<input name="risk_max" type="number" min={0} max={100} defaultValue={policy.risk_max}/></label>
        <label>Session network (CIDR)<input name="network" maxLength={49} defaultValue={policy.network}/></label>
        <label>UTC start hour<input name="utc_start" type="number" min={0} max={23} defaultValue={policy.utc_start}/></label>
        <label>UTC end hour, exclusive<input name="utc_end" type="number" min={0} max={23} defaultValue={policy.utc_end}/></label>
        <label>Highest allowed classification<select name="classification_max" defaultValue={policy.classification_max ?? ''}>
          <option value="">Any classification</option><option value="public">Public</option><option value="internal">Internal</option>
          <option value="confidential">Confidential</option><option value="restricted">Restricted</option>
        </select></label>
        <label>Required workspace type<select name="tenant_type" defaultValue={policy.tenant_type ?? ''}>
          <option value="">Any workspace type</option>{templates.map(type => <option key={type.id} value={type.id}>{type.label}</option>)}
        </select></label>
        <p className="muted">Network uses the address recorded for the signed-in session. A missing score, device record or network address cannot satisfy that requirement.</p>
      </>}
      <button type="submit" disabled={busy}>Save file policy</button>
    </form>}
  </section>
}

export function FileEgressExplanation({ scope, file, room = false }: { scope: string; file: string; room?: boolean }) {
  const [busy, setBusy] = useState(false)
  const [explanation, setExplanation] = useState<string[]>([])
  async function explain() {
    setBusy(true)
    try {
      const result = await db!.rpc('st_v7_explain_file_egress', {
        p_scope_type: room ? 'room' : 'workspace', p_scope: scope, p_file: file, p_operation: 'download',
      })
      const codes: string[] = result.data?.reasons ?? []
      setExplanation(codes.length ? codes.map(code => reasons[code] ?? 'File access could not be evaluated.') :
        ['File access could not be evaluated.'])
    } catch {
      setExplanation(['File access could not be evaluated.'])
    } finally {
      setBusy(false)
    }
  }
  return <div>
    <button className="secondary" type="button" disabled={busy} onClick={() => void explain()}>Check download access</button>
    <div aria-live="polite">{explanation.map(line => <p key={line}>{line}</p>)}</div>
  </div>
}
