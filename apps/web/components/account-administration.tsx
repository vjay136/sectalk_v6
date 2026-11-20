'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db } from '../lib/data'
import { StaffMfa } from './staff-mfa'
import { OperatorAccountDevices } from './operator-account-devices'
import { OperatorAccountSessions } from './operator-account-sessions'
import { SessionRiskOperations } from './session-risk-operations'
import { SectionTabs } from './section-tabs'

export type AccountOperatorAccess = 'none' | 'mfa' | 'operator' | 'reviewer'
type Account = { id: string; handle: string; name: string; status: 'active' | 'restricted' }
type Action = 'force_logout' | 'reset_requested' | 'reset_completed'
type HistoryAction = Action | 'session_revoked' | 'session_step_up'
type Profile = {
  id: string; handle: string; name: string; created_at: string
  eligible: boolean; has_authenticator: boolean; restricted: boolean
  reset: { ready_at: string; expires_at: string } | null
  history: { action: HistoryAction; occurred_at: string; actor: string; reason: string }[]
}
const actions: Record<Action,string> = {
  force_logout: 'End all sessions',
  reset_requested: 'Request authenticator reset',
  reset_completed: 'Approve authenticator reset',
}
const historyLabels: Record<HistoryAction,string> = {
  force_logout: 'All sessions ended', reset_requested: 'Authenticator reset requested', reset_completed: 'Authenticator reset approved',
  session_revoked: 'Individual session ended', session_step_up: 'Fresh authenticator verification requested',
}

export function useAccountOperator() {
  const [access, setAccess] = useState<AccountOperatorAccess>('none')
  const refresh = useCallback(async () => {
    const { data, error } = await db!.rpc('st_v7_account_operator_access')
    setAccess(!error && (data === 'mfa' || data === 'operator' || data === 'reviewer') ? data : 'none')
  }, [])
  useEffect(() => {
    void refresh()
    const timer = window.setInterval(refresh, 15000)
    return () => window.clearInterval(timer)
  }, [refresh])
  return { access, refresh }
}

export function AccountAdministration({ access, refresh }: {
  access: AccountOperatorAccess; refresh: () => Promise<void>
}) {
  const [section, setSection] = useState<'directory' | 'risks'>('directory')
  if (access === 'none') return null
  if (access === 'mfa') return <StaffMfa refresh={refresh}
    explanation="Enter a current authenticator code to manage native account sessions and authenticator recovery."/>
  return <>
    <SectionTabs label="Account administration sections" value={section} onChange={setSection}
      options={ [['directory', 'Account directory'], ['risks', 'High-risk sessions']] }/>
    {section === 'directory' ? <AccountDirectory access={access} onAccessChanged={refresh}/>
      : <SessionRiskOperations canManage={access === 'operator'} refreshAccess={refresh}/>}
  </>
}

function AccountDirectory({ access, onAccessChanged }: {
  access: 'operator' | 'reviewer'; onAccessChanged: () => Promise<void>
}) {
  const [query, setQuery] = useState({ search: '', status: 'all' })
  const [cursor, setCursor] = useState('')
  const [accounts, setAccounts] = useState<Account[]>([])
  const [selected, setSelected] = useState<string | null>(null)
  const [profile, setProfile] = useState<Profile | null>(null)
  const [action, setAction] = useState<Action | null>(null)
  const [revision, setRevision] = useState(0)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState('')
  const refreshProfile = useCallback(() => setRevision(value => value + 1), [])

  useEffect(() => {
    let current = true
    setLoading(true)
    setAccounts([])
    void db!.rpc('st_v7_account_admin_directory', {
      p_search: query.search, p_status: query.status, p_after: cursor,
    }).then(async ({ data, error }) => {
      if (!current) return
      if (error) { setError('Could not load the account directory.'); await onAccessChanged() }
      else setAccounts(data as Account[])
      if (current) setLoading(false)
    })
    return () => { current = false }
  }, [query, cursor, onAccessChanged])

  useEffect(() => {
    if (!selected) { setProfile(null); return }
    setProfile(current => current?.id === selected ? current : null)
    let current = true
    void db!.rpc('st_v7_account_admin_profile', { p_user: selected }).then(async ({ data, error }) => {
      if (!current) return
      if (error || !data) { setError('Could not load the account profile.'); await onAccessChanged() }
      else setProfile(data as Profile)
    })
    return () => { current = false }
  }, [selected, revision, onAccessChanged])

  function search(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const fields = new FormData(event.currentTarget)
    setSelected(null)
    setAction(null)
    setError('')
    setResult('')
    setCursor('')
    setQuery({ search: String(fields.get('search') ?? ''), status: String(fields.get('status') ?? 'all') })
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!profile || !action || busy) return
    const reason = String(new FormData(event.currentTarget).get('reason') ?? '').trim()
    setBusy(true)
    setResult('')
    setError('')
    const response = await db!.rpc('st_v7_account_admin_action', {
      p_user: profile.id, p_action: action, p_reason: reason,
    })
    setBusy(false)
    if (response.error) {
      setError(response.error.code === '22023' ? response.error.message : 'This account action is unavailable.')
      await onAccessChanged()
      return
    }
    setAction(null)
    setRevision(value => value + 1)
    setResult(historyLabels[action] + '.')
  }

  return <section className="panel release-panel" aria-label="Account administration">
    <h2>Account administration</h2>
    <p>Manage eligible native SecTalk sessions and authenticator recovery. Manage membership and workspace access from Workspaces → People.</p>
    <form className="release-form" onSubmit={search}>
      <label>Name or handle<input name="search" maxLength={50}/></label>
      <label>Account status<select name="status" aria-label="Account status">
        <option value="all">All accounts</option><option value="active">Active</option><option value="restricted">Restricted</option>
      </select></label>
      <button className="secondary" disabled={busy}>Search accounts</button>
    </form>
    {loading ? <p role="status">Loading accounts…</p> : !accounts.length ? <p>No accounts match these filters.</p> :
      <ul className="release-section">{accounts.slice(0,40).map(account => <li className="release-row" key={account.id}>
        <button className="text-button" type="button" disabled={busy} onClick={() => {
          if (selected === account.id) setRevision(value => value + 1)
          setSelected(account.id); setAction(null); setResult(''); setError('')
        }}>{account.name} (@{account.handle})</button><span className="pill">{account.status}</span>
      </li>)}</ul>}
    <div className="actions">
      {cursor && <button className="secondary" type="button" disabled={busy} onClick={() => setCursor('')}>First page</button>}
      {accounts.length > 40 && <button className="secondary" type="button" disabled={busy} onClick={() => setCursor(accounts[39].handle)}>Next page</button>}
    </div>
    {profile && <article className="release-board-item">
      <h3>{profile.name}</h3>
      <p>@{profile.handle} · {profile.restricted ? 'Restricted' : 'Active'} · Joined {new Date(profile.created_at).toLocaleDateString()}</p>
      {profile.reset && <p>Authenticator reset available for review from{' '}
        <time dateTime={profile.reset.ready_at}>{new Date(profile.reset.ready_at).toLocaleString()}</time>.</p>}
      {profile.eligible && <div className="actions">
        {access === 'operator' && <button className="secondary" type="button" disabled={busy} onClick={() => setAction('force_logout')}>{actions.force_logout}</button>}
        {access === 'operator' && !profile.reset && profile.has_authenticator && <button className="secondary" type="button" disabled={busy}
          onClick={() => setAction('reset_requested')}>{actions.reset_requested}</button>}
        {access === 'reviewer' && profile.reset && Date.parse(profile.reset.ready_at) <= Date.now() &&
          <button className="secondary" type="button" disabled={busy} onClick={() => setAction('reset_completed')}>{actions.reset_completed}</button>}
      </div>}
      {!profile.eligible && <p>Account-wide actions are unavailable for this profile.</p>}
      {profile.eligible && <OperatorAccountSessions key={profile.id + '-sessions'} user={profile.id} canEnd={access === 'operator'}
        changed={refreshProfile} accessChanged={onAccessChanged}/>}
      {access === 'operator' && profile.eligible && <OperatorAccountDevices key={profile.id + '-devices'} accountId={profile.id}
        onAccessChanged={onAccessChanged}/>}
      {action && <form className="release-form" key={action} onSubmit={submit}>
        <h4>{actions[action]}</h4>
        <p>{action === 'force_logout' ? 'This ends all current sessions. The user can sign in again.'
          : action === 'reset_requested' ? 'The user can cancel during the 24-hour wait. A separate reviewer must approve the reset.'
          : 'This removes the current authenticators and recovery codes, and ends all current sessions.'}</p>
        <label>Case reference and reason<textarea name="reason" required minLength={10} maxLength={240}/></label>
        <div className="actions">
          <button className="primary" disabled={busy}>Confirm {actions[action].toLowerCase()}</button>
          <button className="secondary" type="button" disabled={busy} onClick={() => setAction(null)}>Cancel</button>
        </div>
      </form>}
      {!!profile.history.length && <><h4>Account administration history</h4><ul className="audit">
        {profile.history.map((event, index) => <li key={event.occurred_at + index}>
          <strong>{historyLabels[event.action]}</strong> · <time dateTime={event.occurred_at}>{new Date(event.occurred_at).toLocaleString()}</time>
          <p>{event.reason}</p>
        </li>)}
      </ul></>}
    </article>}
    {result && <p role="status">{result}</p>}
    {error && <p className="error" role="alert">{error}</p>}
  </section>
}
