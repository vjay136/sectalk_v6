'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'
import { useSensitiveAction } from './sensitive-action'

type Relationship = {
  id: string; supervisor: string; participant: string; state: 'pending' | 'active' | 'ended' | 'expired'
  restrictContacts: boolean; changedAt: string; verifiedDevices: number | null
}
type Snapshot = { kind: 'family' | 'school'; relationships: Relationship[] }
type Person = { id: string; name: string }

export function ManagedAccounts({ workspace, kind, actor, canOffer, members, names, onChange }: {
  workspace: string; kind: 'family' | 'school'; actor: string; canOffer: boolean; members: Person[]; names: Record<string, string>; onChange?: () => void
}) {
  const [state, setState] = useState<Snapshot>()
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  const [includeFileProtection, setIncludeFileProtection] = useState(true)
  const { authorize, confirmation } = useSensitiveAction()
  const load = useCallback(async (signal?: AbortSignal) => {
    const request = db!.rpc('st_v7_managed_account', { p_workspace: workspace })
    const result = await (signal ? request.abortSignal(signal) : request)
    if (signal?.aborted) return
    if (result.error) setError('Managed account settings are unavailable.')
    else setState(result.data as Snapshot)
  }, [workspace])
  useEffect(() => {
    const controller = new AbortController()
    void load(controller.signal)
    return () => controller.abort()
  }, [load])
  const supervisorRole = kind === 'family' ? 'Family guardian' : 'Teacher supervisor'

  function action(name: 'offer' | 'accept' | 'restrict' | 'end', params: Record<string, unknown>) {
    if (busy) return
    setError('')
    setNotice('')
    void authorize('room_role', async () => {
      setBusy(true)
      try {
        const result = await db!.rpc('st_v7_managed_account', { p_workspace: workspace, p_action: name, ...params })
        if (result.error) throw result.error
        setState(result.data as Snapshot)
        onChange?.()
        setNotice({ offer: 'Oversight proposal sent.', accept: 'Managed oversight is active.',
          restrict: 'Contact restriction updated.', end: 'Managed oversight ended.' }[name])
      } catch (cause) { setError(formatError(cause, 'Could not change the managed account relationship.')) }
      finally { setBusy(false) }
    })
  }
  function propose(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    action('offer', { p_target: new FormData(event.currentTarget).get('member') })
  }

  return <section className="release-section" aria-label="Managed accounts">
    <h3>Managed accounts</h3>
    <p>Oversight is voluntary and starts only after both existing accounts agree. SecTalk verifies the sign-in and workspace roles.
      This flow does not verify anyone’s age, guardianship, or real-world teaching identity.</p>
    <p>A supervisor can see the count of trusted devices and limit new direct contact requests to active members of this workspace.
      Oversight does not reveal messages, encryption keys, device identities, or active sessions. Existing accepted contacts remain available.</p>
    {canOffer && members.length > 0 && <form className="release-form" onSubmit={propose}>
      <label>Workspace member<select name="member" required defaultValue="">
        <option value="">Choose a member</option>
        {members.map(member => <option value={member.id} key={member.id}>{member.name}</option>)}
      </select></label>
      <button className="primary" disabled={busy}>Propose managed oversight</button>
    </form>}
    <button type="button" className="secondary" disabled={busy} onClick={() => { void load(); onChange?.() }}>Refresh managed accounts</button>
    {state?.relationships.map(entry => {
      const supervises = entry.supervisor === actor
      const stateLabel = { pending: 'Pending consent', active: 'Active', ended: 'Ended', expired: 'Expired' }[entry.state]
      return <article className="release-board-item" key={entry.id}>
        <h4>{supervises ? 'Managed member' : supervisorRole} {names[supervises ? entry.participant : entry.supervisor] ?? 'Workspace account'}</h4>
        <p>{stateLabel} · <time dateTime={entry.changedAt}>{new Date(entry.changedAt).toLocaleDateString()}</time></p>
        {entry.state === 'pending' && !supervises && <>
          {kind === 'family' && <label><input type="checkbox" checked={includeFileProtection}
            onChange={event => setIncludeFileProtection(event.target.checked)}/> Include public attachment-link protection</label>}
          <button type="button" className="primary" disabled={busy}
            onClick={() => action('accept', { p_link: entry.id, p_restrict: kind === 'family' && includeFileProtection })}>
            Accept oversight and contact restriction</button>
        </>}
        {entry.state === 'active' && <>
          <p>{entry.restrictContacts ? 'New outside contacts are restricted.' : 'New outside contacts are allowed.'}</p>
          {entry.verifiedDevices !== null && <p>Trusted devices {entry.verifiedDevices}</p>}
          {supervises && <button type="button" className="secondary" disabled={busy}
            onClick={() => action('restrict', { p_link: entry.id, p_restrict: !entry.restrictContacts })}>
            {entry.restrictContacts ? 'Allow new outside contacts' : 'Restrict new outside contacts'}</button>}
        </>}
        {(entry.state === 'pending' || entry.state === 'active') && <button type="button" className="secondary" disabled={busy}
          onClick={() => action('end', { p_link: entry.id })}>
          {entry.state === 'active' ? 'End managed oversight' : supervises ? 'Withdraw proposal' : 'Decline oversight'}</button>}
      </article>
    })}
    {state?.relationships.length === 0 && <p>No managed account relationships.</p>}
    {confirmation}
    {notice && <p role="status">{notice}</p>}
    {error && <p role="alert">{error}</p>}
  </section>
}
