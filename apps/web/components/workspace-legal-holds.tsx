'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'
import { RoomRetentionPolicy } from './room-retirement'
import { WorkspacePolicyVersions } from './workspace-policy-versions'
import { EmergencyAccess } from './emergency-access'

type Hold = {
  id: string
  room_id: string | null
  member_id: string | null
  from_at: string | null
  until_at: string | null
  reason: string
  released_at: string | null
  release_reason: string | null
}
type Access = { access: 'mfa' } | { access: 'verified'; holds: Hold[] }
type Choice = { id: string; name: string }

function iso(value: FormDataEntryValue | null) {
  return value ? new Date(String(value)).toISOString() : null
}

export function WorkspaceLegalHolds({ workspace, members, owner }: { workspace: string; members: Choice[]; owner: boolean }) {
  const [state, setState] = useState<Access | null>(null)
  const [rooms, setRooms] = useState<Choice[]>([])
  const [factor, setFactor] = useState<string | null>(null)
  const [release, setRelease] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [retentionRevision, setRetentionRevision] = useState(0)
  const [historyRevision, setHistoryRevision] = useState(0)
  const [showEmergency, setShowEmergency] = useState(false)
  const request = useRef<{ id: string; key: string } | null>(null)
  const current = useRef(0)

  const load = useCallback(async () => {
    const version = ++current.current
    const result = await db!.rpc('st_v6_workspace_hold_state', { p_workspace: workspace })
    if (version !== current.current) return
    if (result.error) {
      setError('Could not load your workspace governance settings.')
      setState(null)
      return
    }
    setError('')
    const access = result.data as Access
    setState(access)
    if (access.access === 'mfa') {
      const factors = await db!.auth.mfa.listFactors()
      if (version !== current.current) return
      if (factors.error) setError('Could not read your authenticator settings.')
      else setFactor(factors.data.totp.find(item => item.status === 'verified')?.id || '')
    } else {
      const list = await db!.from('st_v6_rooms').select('id,name').eq('workspace_id', workspace).order('name').limit(200)
      if (version !== current.current) return
      if (list.error) setError('Could not load rooms for preservation.')
      else setRooms(list.data)
    }
  }, [workspace])

  useEffect(() => {
    void load()
    let queued: number | undefined
    const { data: { subscription } } = db!.auth.onAuthStateChange(() => {
      window.clearTimeout(queued)
      queued = window.setTimeout(() => void load(), 0)
    })
    return () => {
      ++current.current
      window.clearTimeout(queued)
      subscription.unsubscribe()
    }
  }, [load])

  async function submit(event: FormEvent<HTMLFormElement>, action: 'verify' | 'place' | 'release') {
    event.preventDefault()
    if (busy) return
    const form = event.currentTarget
    const values = new FormData(form)
    setBusy(true)
    setError('')
    setMessage('')
    try {
      if (action === 'verify' && factor) {
        const result = await db!.auth.mfa.challengeAndVerify({ factorId: factor, code: String(values.get('code')) })
        if (result.error) throw new Error('Enter a current authenticator code.')
      } else if (action === 'place') {
        const fields = {
          p_workspace: workspace, p_room: values.get('room') || null, p_member: values.get('member') || null,
          p_from: iso(values.get('from')), p_until: iso(values.get('until')), p_reason: String(values.get('reason')).trim(),
        }
        if (!fields.p_room && !fields.p_member && !fields.p_from && !fields.p_until) throw new Error('Choose a room, member or date boundary.')
        const key = JSON.stringify(fields)
        if (request.current?.key !== key) request.current = { key, id: crypto.randomUUID() }
        const result = await db!.rpc('st_v6_place_workspace_hold', { ...fields, p_id: request.current.id })
        if (result.error) throw result.error
        request.current = null
        form.reset()
        setMessage('Preservation hold placed.')
      } else if (action === 'release' && release) {
        const result = await db!.rpc('st_v6_release_workspace_hold', {
          p_workspace: workspace, p_id: release, p_reason: String(values.get('reason')).trim(),
        })
        if (result.error) throw result.error
        setRelease(null)
        setMessage('Preservation hold released.')
      }
      await load()
    } catch (cause) {
      setError(formatError(cause, 'Could not update the preservation hold.'))
    } finally {
      setBusy(false)
    }
  }

  return <section className="release-section" aria-labelledby="workspace-holds-heading">
    <h2 id="workspace-holds-heading">Legal holds</h2>
    {error && <p className="error" role="alert">{error}</p>}
    {message && <p role="status">{message}</p>}
    {!state && !error && <p role="status">Loading workspace governance…</p>}
    {state?.access === 'mfa' && (factor
      ? <form className="release-form" onSubmit={event => void submit(event, 'verify')}>
        <label>Authenticator code<input name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required /></label>
        <button className="primary" disabled={busy}>Verify governance access</button>
      </form>
      : <p>{factor === null ? 'Checking your authenticator…' : 'Set up an authenticator in Profile → Security to manage legal holds.'}</p>)}
    {state?.access === 'verified' && <>
      <RoomRetentionPolicy key={retentionRevision} workspace={workspace} onSaved={() => setHistoryRevision(value => value + 1)} />
      <details className="release-create">
        <summary>Policy changes and rollback</summary>
        <WorkspacePolicyVersions key={historyRevision} workspace={workspace} onChanged={() => setRetentionRevision(value => value + 1)} />
      </details>
      {owner && <details className="release-create" onToggle={event => setShowEmergency(event.currentTarget.open)}>
        <summary>Emergency access approvals</summary>
        {showEmergency && <EmergencyAccess workspace={workspace}/>}
      </details>}
      <p>Preserve matching workspace posts and protected versions during edits or removal. Date boundaries use your device’s time zone.</p>
      <details className="release-create">
        <summary>Place a preservation hold</summary>
        <form className="release-form" onSubmit={event => void submit(event, 'place')}>
          <label>Room scope<select name="room"><option value="">Any workspace room or channel</option>
            {rooms.map(room => <option value={room.id} key={room.id}>{room.name}</option>)}</select></label>
          <label>Member scope<select name="member"><option value="">Any workspace member</option>
            {members.map(member => <option value={member.id} key={member.id}>{member.name}</option>)}</select></label>
          <label>On or after<input type="datetime-local" name="from" /></label>
          <label>Before<input type="datetime-local" name="until" /></label>
          <label>Preservation reason<textarea name="reason" minLength={12} maxLength={300} required /></label>
          <button className="primary" disabled={busy}>Place hold</button>
        </form>
      </details>
      {state.holds.length === 0 && <p>No preservation holds.</p>}
      {state.holds.map(hold => <article key={hold.id} className="panel release-panel">
        <h3>{hold.released_at ? 'Released hold' : 'Active hold'}</h3>
        <p>{hold.reason}</p>
        <p>{hold.room_id ? rooms.find(room => room.id === hold.room_id)?.name || 'Selected room' : 'Workspace rooms and channels'}
          {hold.member_id && ' · ' + (members.find(member => member.id === hold.member_id)?.name || 'Selected member')}</p>
        {(hold.from_at || hold.until_at) && <p>
          {hold.from_at && 'From ' + new Date(hold.from_at).toLocaleString()}
          {hold.from_at && hold.until_at && ' · '}
          {hold.until_at && 'Before ' + new Date(hold.until_at).toLocaleString()}
        </p>}
        {hold.release_reason && <p>{hold.release_reason}</p>}
        {!hold.released_at && (release === hold.id
          ? <form className="release-form" onSubmit={event => void submit(event, 'release')}>
            <label>Release reason<textarea name="reason" minLength={12} maxLength={300} required /></label>
            <div className="action-row">
              <button className="primary" disabled={busy}>Confirm release</button>
              <button className="secondary" type="button" disabled={busy} onClick={() => setRelease(null)}>Cancel</button>
            </div>
          </form>
          : <button className="secondary" type="button" onClick={() => setRelease(hold.id)} disabled={busy}>Release hold</button>)}
      </article>)}
    </>}
  </section>
}
