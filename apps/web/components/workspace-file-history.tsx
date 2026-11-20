'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { db } from '../lib/data'

type Subject = { id: string; filename: string; removed_at: string | null }
type Access = { event: 'published' | 'view' | 'download' | 'share'; actor: string; self: boolean; occurred_at: string }
type History = { filename: string; removed_at: string | null; events: Access[] }
type Policy = { enabled: boolean; can_manage: boolean }
const labels: Record<Access['event'], string> = {
  published: 'Shared in workspace', view: 'File details viewed', download: 'File downloaded', share: 'Workspace link generated',
}
const time = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' })

export function WorkspaceFileHistory({ workspace, owner }: { workspace: string; owner: boolean }) {
  const [open, setOpen] = useState(false)
  const [subjects, setSubjects] = useState<Subject[] | null>(null)
  const [selected, setSelected] = useState<string | null>(null)
  const [history, setHistory] = useState<History | null>(null)
  const [policy, setPolicy] = useState<Policy | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const version = useRef(0)

  const load = useCallback(async (signal?: AbortSignal) => {
    const expected = ++version.current
    const abortable = <T extends { abortSignal: (value: AbortSignal) => T }>(request: T) =>
      signal ? request.abortSignal(signal) : request
    const [catalog, setting, file] = await Promise.all([
      abortable(db!.rpc('st_v6_workspace_file_history_list', { p_workspace: workspace })),
      owner ? abortable(db!.rpc('st_v6_workspace_file_history_policy_status', { p_workspace: workspace })) : null,
      selected ? abortable(db!.rpc('st_v6_workspace_file_access_history', { p_workspace: workspace, p_file: selected })) : null,
    ])
    if (signal?.aborted || version.current !== expected) return
    const records = catalog.error ? [] : catalog.data as Subject[]
    setSubjects(records)
    setPolicy(setting && !setting.error ? setting.data as Policy : null)
    setHistory(file && !file.error && records.some(row => row.id === selected) ? file.data as History | null : null)
    if (catalog.error || setting?.error || file?.error) setError('Could not load workspace file history.')
  }, [owner, selected, workspace])

  useEffect(() => {
    if (!open) return
    const controller = new AbortController()
    void load(controller.signal)
    const timer = window.setInterval(() => void load(controller.signal), 5000)
    return () => {
      controller.abort()
      window.clearInterval(timer)
    }
  }, [load, open])

  async function togglePolicy() {
    if (busy || !policy?.can_manage) return
    setBusy(true)
    setError('')
    try {
      const result = await db!.rpc('st_v6_set_workspace_file_history_policy', {
        p_workspace: workspace, p_enabled: !policy.enabled,
      })
      if (result.error) throw result.error
      await load()
    } catch {
      setError('Could not update the workspace history policy.')
    } finally {
      setBusy(false)
    }
  }

  return <details className="release-section" onToggle={event => {
    setOpen(event.currentTarget.open)
    if (!event.currentTarget.open) {
      ++version.current
      setHistory(null)
      setSubjects(null)
      setPolicy(null)
      setSelected(null)
      setError('')
    }
  }}>
    <summary>Workspace file access history</summary>
    {open && <>
      <p>Uploaders can view activity for their files. The owner can allow verified workspace administrators to see all workspace file activity.</p>
      {owner && policy && <p>Administrator access is {policy.enabled ? 'enabled' : 'off'}.</p>}
      {owner && policy && (policy.can_manage
        ? <button className="secondary" type="button" disabled={busy} onClick={() => void togglePolicy()}>
          {policy.enabled ? 'Disable administrator file history' : 'Enable administrator file history'}
        </button>
        : <p>Verify an authenticator in Profile → Security to change this policy.</p>)}
      <button className="secondary" type="button" onClick={() => { setError(''); void load() }}>Refresh file history</button>
      {error && <p role="alert" className="error">{error}</p>}
      {subjects === null && !error && <p role="status">Loading workspace file history…</p>}
      {subjects?.length === 0 && <p>No file history is available to this account.</p>}
      {!!subjects?.length && <ul>{subjects.map(entry => <li key={entry.id}>
        <button type="button" className="secondary" aria-pressed={selected === entry.id} onClick={() => {
          setSelected(entry.id)
          setHistory(null)
        }}>{entry.filename}{entry.removed_at ? ' (removed)' : ''}</button>
      </li>)}</ul>}
      {selected && history && <section aria-label="Selected file activity">
        <h3>{history.filename}</h3>
        {history.events.length === 0 && <p>No recorded activity in the last 90 days.</p>}
        {history.events.length > 0 && <ol className="audit">{history.events.map((entry, index) => <li key={entry.occurred_at + index}>
          <strong>{labels[entry.event]}</strong>
          <small>{entry.self ? 'You' : entry.actor} · <time dateTime={entry.occurred_at}>{time.format(new Date(entry.occurred_at))}</time></small>
        </li>)}</ol>}
      </section>}
    </>}
  </details>
}
