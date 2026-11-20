'use client'

import { useCallback, useEffect, useState } from 'react'
import { db } from '../lib/data'

type Session = {
  id: string
  device: string
  started_at: string
  refreshed_at: string
  expires_at: string
  current_device: boolean
}

const signalLabels: Record<string, string> = {
  unfamiliar_device: 'Unfamiliar browser',
  impossible_travel: 'Unusually fast location change',
  asn_reputation: 'Network reputation warning',
  tor: 'Tor network',
  vpn: 'VPN detected',
  sign_in_velocity: 'Several recent sign-ins',
  failed_sign_ins: 'Several recent failed attempts',
}
type Risk = {session_id: string; band: 'high'|'elevated'|'low'; signals: string[]; provider: 'matched'|'unavailable'}

function SessionDate({value}: {value: string}) {
  return <time dateTime={value}>{new Date(value).toLocaleString()}</time>
}

export function DeviceSessions({hints}: {hints: EventTarget}) {
  const [rows, setRows] = useState<Session[] | null>(null)
  const [risks, setRisks] = useState<Risk[]>([])
  const [selected, setSelected] = useState<Session | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [feedback, setFeedback] = useState('')
  const load = useCallback(async () => {
    const [{data, error}, risk] = await Promise.all([db!.rpc('st_v7_list_sessions'), db!.rpc('st_v7_list_session_risk')])
    setRows(error ? null : data as Session[])
    setRisks(risk.error ? [] : risk.data as Risk[])
    setError(error ? 'Could not load your signed-in devices.' : '')
  }, [])

  useEffect(() => {
    void load()
    const refresh = () => { void load() }
    hints.addEventListener('session_lifecycle', refresh)
    return () => hints.removeEventListener('session_lifecycle', refresh)
  }, [hints,load])

  async function revoke(session: Session) {
    if (busy) return
    setBusy(true)
    setError('')
    setFeedback('')
    try {
      const result = await db!.rpc('st_v7_revoke_session',{p_session:session.id})
      if (result.error) throw result.error
      if (session.current_device && result.data) {
        await db!.auth.signOut({scope:'local'})
        return
      }
      setSelected(null)
      await load()
      setFeedback(result.data ? 'Device session ended.' : 'That device session has already ended.')
    } catch {
      setError('Could not end that device session.')
    } finally {
      setBusy(false)
    }
  }

  return <section className="panel release-panel" aria-label="Devices and sessions">
    <div className="panel-header"><h2>Devices and sessions</h2>
      <button type="button" className="secondary" disabled={busy} onClick={()=>void load()}>Refresh devices</button>
    </div>
    <p>Sessions expire after 7 days without a token refresh or 30 days after sign-in, whichever comes first.</p>
    {!rows && !error && <p role="status">Loading devices…</p>}
    {error && <p className="error" role="alert">{error}</p>}
    {feedback && <p role="status">{feedback}</p>}
    {rows?.length === 0 && <p>No active devices.</p>}
    {rows?.map(session=><article className="release-board-item" key={session.id}>
      <div className="release-row"><strong>{session.device}</strong>
        {session.current_device && <span>This device</span>}
        <button className="secondary" type="button" disabled={busy} onClick={()=>setSelected(session)}>
          {session.current_device ? 'Sign out this device' : 'End device session'}
        </button>
      </div>
      <dl className="profile-stats">
        <div><dt>Signed in</dt><dd><SessionDate value={session.started_at}/></dd></div>
        <div><dt>Last token refresh</dt><dd><SessionDate value={session.refreshed_at}/></dd></div>
        <div><dt>Expires</dt><dd><SessionDate value={session.expires_at}/></dd></div>
      </dl>
      {risks.filter(risk => risk.session_id===session.id).map(risk => <div key={risk.session_id}>
        <p>Sign-in risk: {risk.band}{risk.provider==='unavailable' && ' · Network reputation unavailable'}</p>
        {risk.signals.length>0 && <p>{risk.signals.map(signal=>signalLabels[signal]).filter(Boolean).join(' · ')}</p>}
      </div>)}
      {selected?.id===session.id && <div className="actions">
        <button className="danger" type="button" disabled={busy} onClick={()=>void revoke(session)}>Confirm sign-out</button>
        <button className="secondary" type="button" disabled={busy} onClick={()=>setSelected(null)}>Cancel</button>
      </div>}
    </article>)}
  </section>
}
