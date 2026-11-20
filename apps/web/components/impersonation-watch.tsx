'use client'

import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from 'react'
import { db, onReconnect, type Profile } from '../lib/data'
import { findImpersonationSignals } from '../lib/impersonation.mjs'

type Tier = 'executive' | 'vip'
type Watch = { member_id: string; tier: Tier }
const tiers = { executive: 'Executive', vip: 'VIP' }
const signalNames = {
  same_name: 'Same display name',
  lookalike_name: 'Similar-looking display name',
  lookalike_handle: 'Similar-looking username',
}

export function ImpersonationWatch({ workspace, accounts }: { workspace: string; accounts: Profile[] }) {
  const [watch, setWatch] = useState<Watch[] | null>(null)
  const [member, setMember] = useState('')
  const [tier, setTier] = useState<Tier>('executive')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const version = useRef(0)

  const load = useCallback(async () => {
    const request = ++version.current
    const result = await db!.rpc('st_v6_impersonation_watch_list', { p_workspace: workspace })
    if (request !== version.current) return
    if (result.error) { setWatch(null); setError('Could not load the impersonation watch list.'); return }
    setWatch(result.data as Watch[])
    setError('')
  }, [workspace])
  useEffect(() => {
    void load()
    const reconnect = onReconnect(load)
    const timer = window.setInterval(() => {
      if (document.visibilityState === 'visible') void load()
    }, 10000)
    return () => { version.current++; reconnect(); window.clearInterval(timer) }
  }, [load])

  const byId = useMemo(() => new Map(accounts.map(account => [account.id, account])), [accounts])
  const matches = useMemo(() => watch ? findImpersonationSignals(accounts, watch.map(entry => entry.member_id)) : [], [accounts, watch])
  async function change(memberId: string, value: Tier | null) {
    setBusy(true)
    setError('')
    const { error } = await db!.rpc('st_v6_set_impersonation_watch', {
      p_workspace: workspace, p_member: memberId, p_tier: value,
    })
    if (error) setError('Could not save the watch list. Choose an active workspace member.')
    else {
      await load()
      if (value) setMember('')
    }
    setBusy(false)
  }
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (member && !busy) void change(member, tier)
  }

  return <section className="release-section" aria-labelledby="impersonation-watch-title">
    <div className="panel-header">
      <h2 id="impersonation-watch-title">Impersonation watch</h2>
      <button type="button" className="secondary" disabled={busy} onClick={() => void load()}>Refresh watch list</button>
    </div>
    <p>Watch executive and VIP accounts for similar names or usernames in this workspace. Review each match before taking action.</p>
    {error && <p role="alert" className="error">{error}</p>}
    {!watch && !error && <p role="status">Loading watch list…</p>}
    {watch && <>
      <form className="release-form" onSubmit={submit}>
        <label>Protected member<select aria-label="Protected member" required value={member} disabled={busy}
          onChange={event => {
            setMember(event.target.value)
            setTier(watch.find(row => row.member_id === event.target.value)?.tier ?? 'executive')
          }}>
          <option value="">Choose an active member</option>
          {accounts.map(account => <option key={account.id} value={account.id}>{account.name} (@{account.handle})</option>)}
        </select></label>
        <label>Watch category<select aria-label="Watch category" value={tier} disabled={busy}
          onChange={event => setTier(event.target.value as Tier)}>
          <option value="executive">Executive</option><option value="vip">VIP</option>
        </select></label>
        <button className="primary" type="submit" disabled={!member || busy}>Save protected member</button>
      </form>
      <h3>Protected members</h3>
      {!watch.length && <p>No protected members yet.</p>}
      {watch.map(row => <div key={row.member_id} className="release-row">
        <strong>{byId.get(row.member_id)?.name ?? 'Inactive member'}</strong>
        <span>{tiers[row.tier]}</span>
        <button type="button" className="secondary" disabled={busy}
          onClick={() => void change(row.member_id, null)}>Remove from watch list</button>
      </div>)}
      <h3>Possible matches</h3>
      {!matches.length && <p>No similar profiles found in the active workspace roster.</p>}
      {matches.map(match => <article className="release-board-item" key={match.protectedAccount.id + ':' + match.candidate.id}>
        <h4><bdi>{match.candidate.name}</bdi> <small>@{match.candidate.handle}</small></h4>
        <p>Compared with <bdi>{match.protectedAccount.name}</bdi> (@{match.protectedAccount.handle})</p>
        <ul>{match.reasons.map(reason => <li key={reason}>{signalNames[reason]}</li>)}</ul>
      </article>)}
    </>}
  </section>
}
