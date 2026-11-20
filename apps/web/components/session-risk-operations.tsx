'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db } from '../lib/data'
import { signalLabels } from './device-sessions'

type RiskSession = {
  account_id: string; handle: string; display_name: string; session_id: string; browser: string
  last_active_at: string; assessed_at: string; signals: string[]
  step_up_state: 'available' | 'pending' | 'verified' | 'unavailable'
}
type Action = 'require' | 'end'

const states: Record<RiskSession['step_up_state'], string> = {
  available: 'Authenticator verification available', pending: 'Waiting for authenticator verification',
  verified: 'Authenticator verified', unavailable: 'No authenticator enrolled',
}

export function SessionRiskOperations({ canManage, refreshAccess }: { canManage: boolean; refreshAccess: () => Promise<void> }) {
  const [travelOnly, setTravelOnly] = useState(false)
  const [sessions, setSessions] = useState<RiskSession[] | null>(null)
  const [selected, setSelected] = useState<{ session: RiskSession; action: Action } | null>(null)
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const load = useCallback(async (signal?: AbortSignal) => {
    const query = db!.rpc('st_v7_security_risk_sessions', { p_impossible_travel: travelOnly })
    const result = await (signal ? query.abortSignal(signal) : query)
    if (signal?.aborted) return
    if (result.error) {
      setSessions(null)
      setError('Could not load high-risk sessions.')
      if (result.error.code === '42501') await refreshAccess()
    } else setSessions(result.data as RiskSession[])
  }, [travelOnly, refreshAccess])

  useEffect(() => {
    const controller = new AbortController()
    setSessions(null)
    setError('')
    setSelected(null)
    void load(controller.signal)
    const timer = window.setInterval(() => void load(controller.signal), 15000)
    return () => { controller.abort(); window.clearInterval(timer) }
  }, [load])

  async function confirm(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!selected || busy || !canManage) return
    const { session, action } = selected
    const reason = String(new FormData(event.currentTarget).get('reason') ?? '').trim()
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const result = await db!.rpc(action === 'require' ? 'st_v7_require_risk_session_totp' : 'st_v7_account_admin_revoke_session', {
        p_user: session.account_id, p_session: session.session_id, p_reason: reason,
      })
      if (result.error) {
        setError(result.error.code === '22023' ? result.error.message : 'This action could not be completed.')
        if (result.error.code === '42501') await refreshAccess()
        return
      }
      setNotice(result.data ? (action === 'require' ? 'Authenticator verification requested.' : 'Session ended.') : 'This session action is no longer available.')
      setSelected(null)
      await load()
    } finally { setBusy(false) }
  }

  return <section className="panel release-panel" aria-label="High-risk sessions">
    <div className="panel-header"><h2>High-risk sessions</h2>
      <button type="button" className="secondary" disabled={busy} onClick={() => { setError(''); void load() }}>Refresh risk sessions</button>
    </div>
    <p>Review active native sessions flagged by sign-in risk checks. Require fresh proof when the account has an authenticator.</p>
    <label><input type="checkbox" checked={travelOnly} disabled={busy} onChange={event => setTravelOnly(event.target.checked)} /> Unusually fast location changes only</label>
    {sessions === null && !error && <p role="status">Loading high-risk sessions…</p>}
    {sessions?.length === 0 && <p>No active sessions match this filter.</p>}
    {!!sessions?.length && <ul className="audit">{sessions.map(session => <li key={session.session_id}>
      <strong>{session.display_name} (@{session.handle})</strong>
      <p>{session.browser} · Last active <time dateTime={session.last_active_at}>{new Date(session.last_active_at).toLocaleString()}</time></p>
      <p>{session.signals.map(signal => signalLabels[signal]).filter(Boolean).join(' · ')}</p>
      <p>{states[session.step_up_state]}</p>
      {canManage && <div className="actions">
        {['available', 'verified'].includes(session.step_up_state) &&
          <button type="button" className="secondary" disabled={busy} onClick={() => setSelected({ session, action: 'require' })}>Require authenticator</button>}
        <button type="button" className="secondary" disabled={busy} onClick={() => setSelected({ session, action: 'end' })}>End risk session</button>
      </div>}
    </li>)}</ul>}
    {selected && <form className="release-form" onSubmit={confirm} key={selected.session.session_id + selected.action}>
      <h3>{selected.action === 'require' ? 'Require an authenticator code' : 'End this session'}</h3>
      <p>{selected.session.display_name} (@{selected.session.handle})</p>
      <label>Risk case reference and reason<textarea name="reason" required minLength={10} maxLength={240}/></label>
      <div className="actions">
        <button type="submit" className="primary" disabled={busy}>{selected.action === 'require' ? 'Confirm authenticator request' : 'Confirm end risk session'}</button>
        <button type="button" className="secondary" disabled={busy} onClick={() => setSelected(null)}>Cancel</button>
      </div>
    </form>}
    {notice && <p role="status">{notice}</p>}
    {error && <p role="alert" className="error">{error}</p>}
  </section>
}
