'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db } from '../lib/data'
import { verifyAccountCredential } from '../lib/account-credential'
import { enrollCurrentDevice } from '../lib/device-identity'

type Kind = 'email' | 'authenticator' | 'recovery'
type Pending = {kind: Kind; ready_at: string; expires_at: string; provider_pending: boolean; support_requested?: boolean}
type SecurityEvent = {id: string; kind: Kind | 'password' | 'sessions'; action: 'requested' | 'cancelled' | 'completed'; occurred_at: string}
const changes = {email: 'Email change', authenticator: 'Authenticator reset', recovery: 'Authenticator recovery', password: 'Password change', sessions: 'Account session revocation'}
const actions = {requested: 'requested', cancelled: 'cancelled', completed: 'completed'}

export function AccountSecurityChanges({hasAuthenticator, staff, hints}: {
  hasAuthenticator: boolean; staff: boolean; hints: EventTarget
}) {
  const [pending, setPending] = useState<Pending | null>(null)
  const [events, setEvents] = useState<SecurityEvent[]>([])
  const [kind, setKind] = useState<'email' | 'authenticator' | null>(null)
  const [busy, setBusy] = useState(false)
  const [loaded, setLoaded] = useState(false)
  const [error, setError] = useState('')
  const [feedback, setFeedback] = useState('')
  const [clock, setClock] = useState(Date.now)
  const [deviceRequest, setDeviceRequest] = useState<string|null>(null)

  const load = useCallback(async () => {
    const [status, history, approval] = await Promise.all([
      db!.rpc('st_v7_account_security_status'), db!.rpc('st_v7_account_security_events'),
      db!.rpc('st_v7_device_recovery_to_approve'),
    ])
    setDeviceRequest(approval.error ? null : approval.data)
    if (status.error || !status.data || history.error) {
      setError('Account security changes are unavailable.')
      return
    }
    setPending(status.data.pending as Pending | null)
    setEvents(history.data as SecurityEvent[])
    setClock(Date.now())
    setLoaded(true)
  }, [])

  useEffect(() => {
    void load()
    const refresh = () => { void load() }
    const tick = window.setInterval(() => setClock(Date.now()), 30000)
    hints.addEventListener('account_security_lifecycle', refresh)
    return () => {
      window.clearInterval(tick)
      hints.removeEventListener('account_security_lifecycle', refresh)
    }
  }, [hints, load])

  async function request(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!kind || busy) return
    const form = event.currentTarget
    const values = new FormData(form)
    const target = kind === 'email' ? String(values.get('new-email') ?? '').trim().toLowerCase() : null
    const stage = pending ? 'continue' : 'request'
    setBusy(true)
    setError('')
    setFeedback('')
    try {
      await verifyAccountCredential(String(values.get('current-credential') ?? ''),hasAuthenticator)
      const result = await db!.rpc('st_v7_account_security_change', {p_action: stage, p_kind: kind, p_value: target})
      if (result.error) throw new Error()
      if (result.data === 'send_confirmation') {
        const provider = await db!.auth.updateUser({email: target!}, {emailRedirectTo: window.location.origin})
        if (provider.error) throw new Error()
        setFeedback('Check your current and new email addresses. Confirm the change from both.')
      } else if (result.data === 'confirmation_sent') {
        setFeedback('Check your current and new email addresses for confirmation.')
      } else if (result.data === 'completed') {
        await db!.auth.signOut({scope: 'local'})
        return
      } else setFeedback('Security change requested. The cooling-off period is 24 hours.')
      setKind(null)
      await load()
    } catch {
      setError('The security change could not continue. Check your credentials, request and email address.')
    } finally {
      form.reset()
      setBusy(false)
    }
  }

  async function cancel() {
    if (busy) return
    setBusy(true)
    setError('')
    setFeedback('')
    const result = await db!.rpc('st_v7_account_security_change', {p_action: 'cancel'})
    if (result.error) setError('Could not cancel the security request.')
    else {
      setKind(null)
      setFeedback('Security request cancelled.')
      await load()
    }
    setBusy(false)
  }

  async function approveDeviceRecovery() {
    if (!deviceRequest || busy) return
    setBusy(true)
    setError('')
    setFeedback('')
    try {
      await enrollCurrentDevice({recoveryRequest:deviceRequest})
      setFeedback('Recovery approved. The 24-hour cooling-off period still applies.')
      await load()
    } catch {
      setError('Approval requires the browser keys of the previously trusted, verified device.')
    } finally {
      setBusy(false)
    }
  }

  const ready = pending && Date.parse(pending.ready_at)<=clock && Date.parse(pending.expires_at)>clock
  return <section className="panel mfa-panel" aria-label="Account security changes">
    <h2>Account security changes</h2>
    <p>Email changes and authenticator resets have a 24-hour cooling-off period.</p>
    {!loaded && !error && <p role="status">Loading account security changes…</p>}
    {loaded && !pending && !kind && <div className="actions">
      <button className="secondary" type="button" onClick={() => {setKind('email');setFeedback('')}}>Change email address</button>
      {hasAuthenticator && !staff && <button className="secondary" type="button" onClick={() => {setKind('authenticator');setFeedback('')}}>
        Request authenticator reset
      </button>}
    </div>}
    {pending && <article className="release-board-item">
      <strong>{changes[pending.kind]}</strong>
      {pending.support_requested ? <p>An account operator requested this reset. A separate reviewer can approve it after{' '}
        <time dateTime={pending.ready_at}>{new Date(pending.ready_at).toLocaleString()}</time>. Cancel it if you did not ask for help.</p>
        : pending.provider_pending ? <p>Waiting for confirmation from both email addresses.</p> : <>
        <p>Available to continue at <time dateTime={pending.ready_at}>{new Date(pending.ready_at).toLocaleString()}</time>.</p>
        {ready && !kind && pending.kind !== 'recovery' && <button className="primary" type="button" onClick={() => {
          if (pending.kind !== 'recovery') setKind(pending.kind)
        }}>Continue security change</button>}
        {ready && pending.kind === 'recovery' && <p>Sign in with your password and continue with the same recovery method.</p>}
      </>}
      {deviceRequest && <>
        <p>Approve only if you started recovery on another device. You can still cancel during the cooling-off period.</p>
        <button type="button" className="secondary" disabled={busy} onClick={()=>void approveDeviceRecovery()}>Approve recovery from this device</button>
      </>}
      <button className="secondary" type="button" onClick={() => void cancel()} disabled={busy}>Cancel security request</button>
    </article>}
    {kind && <form className="release-form" onSubmit={request}>
      {kind === 'email' && <label>New email address<input type="email" name="new-email" maxLength={254} required/></label>}
      <label>{hasAuthenticator ? 'Current authenticator code' : 'Current password'}<input name="current-credential" required
        type={hasAuthenticator ? 'text' : 'password'} autoComplete={hasAuthenticator ? 'one-time-code' : 'current-password'}
        inputMode={hasAuthenticator ? 'numeric' : undefined} pattern={hasAuthenticator ? '[0-9]{6}' : undefined}/></label>
      {kind === 'authenticator' && <p>Finishing the reset removes verified factors and recovery codes and ends existing sessions.</p>}
      <div className="actions">
        <button className="primary" disabled={busy}>{pending ? 'Verify and continue' : 'Verify and request change'}</button>
        <button className="secondary" type="button" disabled={busy} onClick={() => setKind(null)}>Close request form</button>
      </div>
    </form>}
    {error && <p className="error" role="alert">{error}</p>}
    {feedback && <p role="status">{feedback}</p>}
    {events.length > 0 && <>
      <h3>Recent security activity</h3>
      <ol className="audit">{events.map(event => <li key={event.id}>
        {changes[event.kind]} {actions[event.action]}{' '}
        <time dateTime={event.occurred_at}>{new Date(event.occurred_at).toLocaleString()}</time>
      </li>)}</ol>
    </>}
  </section>
}
