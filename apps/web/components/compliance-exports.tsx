'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db } from '../lib/data'
import { StaffMfa } from './staff-mfa'
import { TenantArtifactKeys } from './tenant-artifact-keys'
import { WorkspaceOffboarding } from './workspace-offboarding'

type Access = 'none' | 'mfa' | 'sso' | 'admin' | 'owner'
type Kind = 'audit' | 'room_report' | 'managed_channel_report' | 'managed_room_report' | 'offboarding_inventory'
type Source = { kind: Kind; id: string; label: string; occurred_at: string }
type Decision = 'approved' | 'denied' | 'revoked' | 'withdrawn'
type State = Decision | 'pending' | 'expired'
type Audit = { action: State | 'requested' | 'built' | 'downloaded'; reason: string | null; occurred_at: string }
type Case = {
  id: string; reference: string; reason: string; state: State; expires_at: string
  sources: Omit<Source, 'occurred_at'>[]; history: Audit[]
  manifest_sha256: string | null; bundle_sha256: string | null; has_artifact: boolean
}
const sourceLabels: Record<Kind,string> = {
  audit: 'Workspace audit event',
  room_report: 'Shared room report',
  managed_channel_report: 'Consented managed channel report under legal hold',
  managed_room_report: 'Consented managed room report under legal hold',
  offboarding_inventory: 'Workspace offboarding inventory',
}
const decisions: Record<Decision,string> = {
  approved: 'Approve exact records', denied: 'Deny request', revoked: 'Revoke export', withdrawn: 'Withdraw request',
}
const sourceKey = (source: Pick<Source,'kind' | 'id'>) => source.kind + ':' + source.id

export function ComplianceExports({ workspace }: { workspace: string }) {
  const [access, setAccess] = useState<Access | null>(null)
  const refresh = useCallback(async () => {
    const { data, error } = await db!.rpc('st_v7_compliance_access', { p_workspace: workspace })
    setAccess(!error && (data === 'mfa' || data === 'sso' || data === 'admin' || data === 'owner') ? data : 'none')
  }, [workspace])
  useEffect(() => {
    void refresh()
    const timer = window.setInterval(refresh, 15000)
    return () => window.clearInterval(timer)
  }, [refresh])

  return <section className="release-section" aria-label="Compliance exports">
    <h2>Compliance exports</h2>
    <p>Workspace admins can request an export of selected audit events and room reports shared with the workspace. The workspace owner approves the exact records.</p>
    {access === null ? <p role="status">Checking export access…</p> :
      access === 'none' ? <p>Compliance export access is unavailable.</p> :
        access === 'mfa' ? <StaffMfa refresh={refresh} explanation="Enter a current authenticator code to review or create a compliance export."/> :
          access === 'sso' ? <p>Sign in with workspace single sign-on to manage compliance exports.</p> :
            <ExportCases workspace={workspace} access={access} onAccessChanged={refresh}/>}
    {(access === 'admin' || access === 'owner' || access === 'sso') && <TenantArtifactKeys workspace={workspace}/>}
    <WorkspaceOffboarding key={workspace} workspace={workspace} reviewOnly/>
  </section>
}

function ExportCases({ workspace, access, onAccessChanged }: {
  workspace: string; access: 'admin' | 'owner'; onAccessChanged: () => Promise<void>
}) {
  const [sources, setSources] = useState<Source[]>([])
  const [selected, setSelected] = useState<string[]>([])
  const [cases, setCases] = useState<Case[] | null>(null)
  const [review, setReview] = useState<{ id: string; decision: Decision } | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const load = useCallback(async () => {
    const { data, error } = await db!.rpc('st_v7_compliance_cases', { p_workspace: workspace })
    if (error) {
      setCases(null)
      setError('Could not load export cases.')
      if (error.code === '42501') await onAccessChanged()
    } else setCases((data as Case[]).filter(item=>item.sources.every(source=>source.kind!=='offboarding_inventory')))
  }, [workspace, onAccessChanged])
  useEffect(() => { void load() }, [load])
  useEffect(() => {
    if (access !== 'admin') return
    let current = true
    void db!.rpc('st_v7_compliance_sources', { p_workspace: workspace }).then(({ data, error }) => {
      if (!current) return
      if (error) setError('Could not load eligible sources.')
      else setSources(data as Source[])
    })
    return () => { current = false }
  }, [workspace, access])

  async function request(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!selected.length || busy) return
    const form = event.currentTarget
    const fields = new FormData(form)
    setBusy(true)
    setError('')
    setMessage('')
    const result = await db!.rpc('st_v7_request_compliance_export', {
      p_workspace: workspace, p_reference: String(fields.get('reference') ?? ''), p_reason: String(fields.get('reason') ?? ''),
      p_sources: sources.filter(source => selected.includes(sourceKey(source))).map(({ kind, id }) => ({ kind, id })),
    })
    if (result.error) setError(result.error.message)
    else {
      form.reset()
      setSelected([])
      setMessage('Export request submitted.')
      await load()
    }
    setBusy(false)
  }

  async function decide(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!review || busy) return
    const reason = String(new FormData(event.currentTarget).get('reason') ?? '')
    setBusy(true)
    setError('')
    setMessage('')
    const { error } = await db!.rpc('st_v7_review_compliance_export', {
      p_case: review.id, p_action: review.decision, p_reason: reason,
    })
    if (error) setError(error.message)
    else {
      setReview(null)
      setMessage('Case decision recorded.')
      await load()
    }
    setBusy(false)
  }

  async function useExport(item: Case) {
    if (busy) return
    setBusy(true)
    setError('')
    setMessage('')
    try {
      const session = await db!.auth.getSession()
      const token = session.data.session?.access_token
      if (!token) throw new Error('Sign in again to access the export.')
      const response = await fetch('/api/compliance-exports/' + item.id, {
        method: item.has_artifact ? 'GET' : 'POST', headers: { Authorization: 'Bearer ' + token }, cache: 'no-store',
      })
      if (!response.ok) {
        const failure = await response.json().catch(() => null)
        throw new Error(failure?.error ?? 'The approved export is unavailable.')
      }
      if (item.has_artifact) {
        const link = document.createElement('a')
        const url = URL.createObjectURL(await response.blob())
        link.href = url
        link.download = 'sectalk-compliance-export.json'
        link.click()
        window.setTimeout(() => URL.revokeObjectURL(url), 1000)
        setMessage('Approved export downloaded.')
      } else setMessage('Private export built.')
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'The approved export is unavailable.')
    } finally {
      setBusy(false)
      await Promise.all([load(), onAccessChanged()])
    }
  }

  return <>
    {access === 'admin' && <details className="release-create">
      <summary>Request an export</summary>
      <form className="release-form" onSubmit={request}>
        <label>Case reference<input name="reference" required minLength={3} maxLength={80}/></label>
        <label>Case purpose<textarea name="reason" required minLength={15} maxLength={500}/></label>
        <fieldset><legend>Exact records to export</legend>
          {sources.length === 0 && <p>No eligible records are available.</p>}
          {sources.map(source => {
            const key = sourceKey(source)
            const checked = selected.includes(key)
            return <label key={key}><input type="checkbox" checked={checked} disabled={busy || !checked && selected.length>=25}
              onChange={() => setSelected(previous => checked ? previous.filter(value => value !== key) : [...previous,key])}/>
              {sourceLabels[source.kind]} · {source.label} · {source.id}
              <time dateTime={source.occurred_at}>{new Date(source.occurred_at).toLocaleString()}</time>
            </label>
          })}
        </fieldset>
        <button className="primary" disabled={busy || !selected.length}>Submit export request</button>
      </form>
    </details>}
    <button type="button" className="secondary" disabled={busy} onClick={() => void load()}>Refresh export cases</button>
    {cases === null && !error && <p role="status">Loading export cases…</p>}
    {cases?.length === 0 && <p>No export cases.</p>}
    {cases?.map(item => <article className="release-board-item" key={item.id}>
      <h3>{item.reference}</h3>
      <p><span className="pill">{item.state}</span> · Expires <time dateTime={item.expires_at}>{new Date(item.expires_at).toLocaleString()}</time></p>
      <p>{item.reason}</p>
      <ul>{item.sources.map(source => <li key={sourceKey(source)}>{sourceLabels[source.kind]} · {source.label} · <code>{source.id}</code></li>)}</ul>
      {item.manifest_sha256 && <details><summary>Approved SHA-256 hashes</summary>
        <p>Manifest <code>{item.manifest_sha256}</code></p><p>Bundle <code>{item.bundle_sha256}</code></p>
        {item.sources.some(source=>source.kind==='managed_room_report')&&
          <p>The bundle hash covers the approved encrypted records. Authorized downloads include the readable room messages and the original bundle hash.</p>}
      </details>}
      <div className="actions">
        {access === 'owner' && item.state === 'pending' && (['approved','denied'] as const).map(decision =>
          <button className="secondary" type="button" key={decision} disabled={busy} onClick={() => setReview({ id: item.id, decision })}>{decisions[decision]}</button>)}
        {access === 'owner' && item.state === 'approved' &&
          <button className="secondary" type="button" disabled={busy} onClick={() => setReview({ id: item.id, decision: 'revoked' })}>{decisions.revoked}</button>}
        {access === 'admin' && item.state === 'pending' &&
          <button className="secondary" type="button" disabled={busy} onClick={() => setReview({ id: item.id, decision: 'withdrawn' })}>{decisions.withdrawn}</button>}
        {access === 'admin' && item.state === 'approved' && <button className="primary" type="button" disabled={busy}
          onClick={() => void useExport(item)}>{item.has_artifact ? 'Download approved bundle' : 'Build private bundle'}</button>}
      </div>
      {review?.id === item.id && <form className="release-form" key={review.decision} onSubmit={decide}>
        <label>Decision reason<textarea name="reason" required minLength={15} maxLength={500}/></label>
        <button className="primary" disabled={busy}>Confirm {decisions[review.decision].toLowerCase()}</button>
        <button className="secondary" type="button" disabled={busy} onClick={() => setReview(null)}>Cancel</button>
      </form>}
      <details><summary>Case audit history</summary>
        <ul className="audit">{item.history.map(event => <li key={event.action + event.occurred_at}>
          {event.action} · <time dateTime={event.occurred_at}>{new Date(event.occurred_at).toLocaleString()}</time>
          {event.reason && <p>{event.reason}</p>}
        </li>)}</ul>
      </details>
    </article>)}
    {message && <p role="status">{message}</p>}
    {error && <p className="error" role="alert">{error}</p>}
  </>
}
