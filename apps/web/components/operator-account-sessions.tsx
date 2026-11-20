'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db } from '../lib/data'
import { signalLabels } from './device-sessions'

type Session = {
  id: string; browser: string; started_at: string; last_active_at: string; expires_at: string
  assurance: string; risk: string; signals: string[]
}

export function OperatorAccountSessions({ user, canEnd, changed, accessChanged }: {
  user: string; canEnd: boolean; changed: () => void; accessChanged: () => Promise<void>
}) {
  const [rows, setRows] = useState<Session[] | null>(null)
  const [selected, setSelected] = useState<Session | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const refresh = useCallback(async (signal?: AbortSignal) => {
    const query = db!.rpc('st_v7_account_admin_sessions', { p_user: user })
    const response = await (signal ? query.abortSignal(signal) : query)
    if (signal?.aborted) return
    if (response.error) {
      setRows(null)
      setError('Could not load the active sessions.')
      if (response.error.code === '42501') await accessChanged()
      return
    }
    setRows(response.data as Session[])
    setError('')
  }, [user, accessChanged])

  useEffect(() => {
    const controller = new AbortController()
    void refresh(controller.signal)
    const timer = window.setInterval(() => void refresh(controller.signal), 15000)
    return () => { controller.abort(); window.clearInterval(timer) }
  }, [refresh])

  async function end(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!selected || !canEnd || busy) return
    const reason = String(new FormData(event.currentTarget).get('reason') ?? '').trim()
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const { data, error } = await db!.rpc('st_v7_account_admin_revoke_session', {
        p_user: user, p_session: selected.id, p_reason: reason,
      })
      if (error) {
        setError(error.code === '22023' ? error.message : 'This session could not be ended.')
        if (error.code === '42501') await accessChanged()
        return
      }
      setRows(current => current?.filter(row => row.id !== selected.id) ?? null)
      setSelected(null)
      setNotice(data ? 'Session ended.' : 'That session has already ended.')
      changed()
    } finally {
      setBusy(false)
    }
  }

  return <section aria-label="Account sessions" className="release-section">
    <div className="panel-header"><h4>Active sessions</h4>
      <button type="button" className="secondary" disabled={busy} onClick={() => void refresh()}>Refresh sessions</button>
    </div>
    {rows === null && !error && <p role="status">Loading active sessions…</p>}
    {rows?.length === 0 && <p>No active sessions.</p>}
    {!!rows?.length && <ul className="audit">{rows.slice(0, 100).map(row => <li key={row.id}>
      <p><strong>{row.browser}</strong> · {row.assurance} · {row.risk} risk</p>
      <p>Last active <time dateTime={row.last_active_at}>{new Date(row.last_active_at).toLocaleString()}</time>
        {' · '}Expires <time dateTime={row.expires_at}>{new Date(row.expires_at).toLocaleString()}</time></p>
      {row.signals.some(signal => signalLabels[signal]) && <p>{row.signals.map(signal => signalLabels[signal]).filter(Boolean).join(' · ')}</p>}
      {canEnd && <button type="button" className="secondary" disabled={busy} onClick={() => setSelected(row)}>End session</button>}
    </li>)}</ul>}
    {rows && rows.length > 100 && <p>Showing the 100 most recently active sessions.</p>}
    {selected && <form className="release-form" key={selected.id} onSubmit={end}>
      <h5>End {selected.browser} session</h5>
      <label>Session case reference and reason<textarea name="reason" required minLength={10} maxLength={240}/></label>
      <div className="actions">
        <button className="primary" disabled={busy}>Confirm end session</button>
        <button type="button" className="secondary" disabled={busy} onClick={() => setSelected(null)}>Cancel</button>
      </div>
    </form>}
    {notice && <p role="status">{notice}</p>}
    {error && <p className="error" role="alert">{error}</p>}
  </section>
}
