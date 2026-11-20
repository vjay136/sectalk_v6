'use client'

import { useEffect, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'

type Retirement = {
  retention_days: number
  can_manage: boolean
  verified: boolean
  held: boolean
  requested_at: string | null
  eligible_at: string | null
}

export function RoomRetirement({ room }: { room: string }) {
  const [state, setState] = useState<Retirement | null>(null)
  const [confirm, setConfirm] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    let live = true
    void db!.rpc('st_v6_room_retirement', { p_room: room }).then(result => {
      if (!live) return
      if (result.error) setError('Could not load room deletion settings.')
      else setState(result.data)
    })
    return () => { live = false }
  }, [room])

  async function update(action: 'schedule' | 'cancel') {
    setBusy(true)
    setError('')
    try {
      const result = await db!.rpc('st_v6_room_retirement', { p_room: room, p_action: action })
      if (result.error) throw result.error
      setState(result.data)
      setConfirm(false)
    } catch (cause) {
      setError(formatError(cause, 'Could not update room deletion.'))
    } finally {
      setBusy(false)
    }
  }

  return <section className="release-section" aria-label="Archived room deletion">
    {error && <p className="error" role="alert">{error}</p>}
    {state?.eligible_at ? <>
      <p role="status">Deletion scheduled. Eligible after <time dateTime={state.eligible_at}>{new Date(state.eligible_at).toLocaleString()}</time>.</p>
      {state.held && <p>A preservation hold is delaying deletion.</p>}
      {state.can_manage && state.verified && <button className="secondary" type="button" disabled={busy}
        onClick={() => void update('cancel')}>Cancel scheduled deletion</button>}
    </> : state?.can_manage && (state.verified
      ? <>{confirm ? <>
        <p>This room will become eligible for permanent deletion after {state.retention_days} days, subject to active preservation holds.</p>
        <div className="action-row">
          <button className="primary" type="button" disabled={busy} onClick={() => void update('schedule')}>Confirm scheduled deletion</button>
          <button className="secondary" type="button" disabled={busy} onClick={() => setConfirm(false)}>Cancel</button>
        </div>
      </> : <button className="secondary" type="button" onClick={() => setConfirm(true)}>Schedule room deletion</button>}</>
      : <p>Verify your authenticator in Profile → Security to schedule deletion.</p>)}
  </section>
}

export function RoomRetentionPolicy({ workspace, onSaved }: { workspace: string; onSaved: () => void }) {
  const [days, setDays] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  useEffect(() => {
    let live = true
    void db!.rpc('st_v6_room_retention_policy', { p_workspace: workspace }).then(result => {
      if (!live) return
      if (result.error) setError('Could not load the room retention policy.')
      else setDays(String(result.data))
    })
    return () => { live = false }
  }, [workspace])

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setError('')
    setMessage('')
    try {
      const result = await db!.rpc('st_v6_room_retention_policy', { p_workspace: workspace, p_days: Number(days) })
      if (result.error) throw result.error
      setDays(String(result.data))
      setMessage('Room retention policy saved.')
      onSaved()
    } catch (cause) {
      setError(formatError(cause, 'Could not save the room retention policy.'))
    } finally {
      setBusy(false)
    }
  }

  return <section className="release-section" aria-labelledby="room-retention-heading">
    <h2 id="room-retention-heading">Room retention</h2>
    {error && <p className="error" role="alert">{error}</p>}
    {message && <p role="status">{message}</p>}
    {days !== null && <form className="release-form" onSubmit={event => void save(event)}>
      <label>Minimum days before scheduled room deletion<input type="number" min="7" max="3650" required value={days}
        onChange={event => setDays(event.target.value)} /></label>
      <p>This applies to scheduled deletions across the workspace. Preservation holds take priority.</p>
      <button className="secondary" disabled={busy}>Save room retention</button>
    </form>}
  </section>
}
