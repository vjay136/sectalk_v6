'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db } from '../lib/data'
import { StaffMfa } from './staff-mfa'

type Option = { case_id: string; case_reference: string; report_id: string; hold_id: string; hold_reason: string }
type Custody = { sequence: number; previous_sha256: string; sha256: string; payload: string }
type Snapshot = {
  id: string; case_reference: string | null; report_id: string; hold_id: string; sha256: string
  captured_at: string; held: boolean; can_download: boolean; custody: Custody[]
}
type Data = { access: 'none' | 'mfa' | 'sso' } | { access: 'owner' | 'admin'; options: Option[]; snapshots: Snapshot[] }
const labels: Record<string,string> = { captured: 'Preserved', downloaded: 'Downloaded',
  hold_released: 'Hold released', hold_removed: 'Hold removed' }
const optionKey = (option: Option) => [option.case_id,option.report_id,option.hold_id].join(':')

export function EvidenceVault({ workspace }: { workspace: string }) {
  const [open, setOpen] = useState(false)
  return <details className="release-create" onToggle={event => setOpen(event.currentTarget.open)}>
    <summary>Evidence vault</summary>
    {open && <Vault workspace={workspace}/>}
  </details>
}

function Vault({ workspace }: { workspace: string }) {
  const [data, setData] = useState<Data | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const refresh = useCallback(async () => {
    const { data, error } = await db!.rpc('st_v7_evidence_vault', { p_workspace: workspace })
    if (error) setError('Could not load the evidence vault.')
    else setData(data as Data)
  }, [workspace])
  useEffect(() => { void refresh() }, [refresh])

  async function operation(snapshot: string | null, selection?: Option, reason?: string) {
    if (busy) return
    setBusy(true)
    setError('')
    setMessage('')
    try {
      const session = await db!.auth.getSession()
      const token = session.data.session?.access_token
      if (!token) throw new Error('Sign in again to access the vault.')
      const response = await fetch('/api/evidence-vault' + (snapshot ? '?snapshot=' + snapshot : ''), {
        method: snapshot ? 'GET' : 'POST', cache: 'no-store',
        headers: { Authorization: 'Bearer ' + token, ...(snapshot ? {} : { 'Content-Type': 'application/json' }) },
        body: selection ? JSON.stringify({ caseId: selection.case_id, report: selection.report_id, hold: selection.hold_id, reason }) : undefined,
      })
      if (!response.ok) {
        const failure = await response.json().catch(() => null)
        throw new Error(failure?.error ?? 'The evidence operation is unavailable.')
      }
      if (snapshot) {
        const url = URL.createObjectURL(await response.blob())
        const link = document.createElement('a')
        link.href = url
        link.download = 'sectalk-evidence-snapshot.json'
        link.click()
        window.setTimeout(() => URL.revokeObjectURL(url), 1000)
        setMessage('Evidence snapshot downloaded.')
      } else setMessage('Evidence snapshot preserved.')
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'The evidence operation is unavailable.')
    } finally {
      await refresh()
      setBusy(false)
    }
  }

  function capture(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (data?.access !== 'admin') return
    const fields = new FormData(event.currentTarget)
    const selection = data.options.find(option => optionKey(option) === fields.get('selection'))
    if (selection) void operation(null,selection,String(fields.get('reason') ?? ''))
  }

  return <section className="release-section" aria-label="Evidence vault">
    <h3>Evidence vault</h3>
    <p>Preserve an exact room report approved in a compliance case and covered by an active legal hold. The case and continuing report consent govern downloads.</p>
    {!data && !error && <p role="status">Loading evidence vault…</p>}
    {data?.access === 'none' && <p>Evidence vault access is unavailable.</p>}
    {data?.access === 'sso' && <p>Sign in with workspace single sign-on to access evidence custody.</p>}
    {data?.access === 'mfa' && <StaffMfa refresh={refresh} explanation="Enter a current authenticator code to review evidence custody or preserve a report."/>}
    {data?.access === 'admin' && (data.options.length ? <form className="release-form" onSubmit={capture}>
      <label>Approved report and matching hold<select name="selection" aria-label="Approved report and matching hold" defaultValue="" required>
        <option value="" disabled>Choose approved evidence</option>
        {data.options.map(option => <option key={optionKey(option)} value={optionKey(option)}>
          {option.case_reference} · Report {option.report_id} · {option.hold_reason}
        </option>)}
      </select></label>
      <label>Preservation reason<textarea name="reason" required minLength={12} maxLength={300}/></label>
      <button className="primary" disabled={busy}>Preserve snapshot</button>
    </form> : <p>No approved reports have a matching active hold.</p>)}
    {(data?.access === 'admin' || data?.access === 'owner') && <>
      <button className="secondary" type="button" disabled={busy} onClick={() => void refresh()}>Refresh evidence vault</button>
      {data.snapshots.length === 0 && <p>No evidence snapshots.</p>}
      {data.snapshots.map(snapshot => <article className="release-board-item" key={snapshot.id}>
        <h4>{snapshot.case_reference || 'Saved evidence snapshot'}</h4>
        <p>{snapshot.held ? 'Active hold' : 'Hold ended'} · Preserved <time dateTime={snapshot.captured_at}>{new Date(snapshot.captured_at).toLocaleString()}</time></p>
        <p>Report <code>{snapshot.report_id}</code></p><p>Legal hold <code>{snapshot.hold_id}</code></p>
        <p>SHA-256 <code>{snapshot.sha256}</code></p>
        {snapshot.can_download && <button className="secondary" type="button" disabled={busy}
          onClick={() => void operation(snapshot.id)}>Download evidence snapshot</button>}
        <details><summary>Chain of custody</summary><ol className="audit">
          {snapshot.custody.map(entry => {
            const event = JSON.parse(entry.payload) as { event: string; at: string; reason?: string; actor?: string }
            return <li key={entry.sequence} value={entry.sequence}>
              <strong>{labels[event.event]}</strong> · <time dateTime={event.at}>{new Date(event.at).toLocaleString()}</time>
              {event.reason && <p>{event.reason}</p>}
              <details><summary>Custody entry {entry.sequence}</summary>
                <p>Previous SHA-256 <code>{entry.previous_sha256}</code></p><p>Entry SHA-256 <code>{entry.sha256}</code></p>
                <p><code>{entry.payload}</code></p>
              </details>
            </li>
          })}
        </ol></details>
      </article>)}
    </>}
    {message && <p role="status">{message}</p>}
    {error && <p className="error" role="alert">{error}</p>}
  </section>
}
