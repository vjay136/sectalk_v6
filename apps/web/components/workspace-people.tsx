'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db } from '../lib/data'
import { StaffMfa } from './staff-mfa'

type Role = 'owner' | 'admin' | 'member'
type Person = { id: string; name: string; handle: string; role: Role; joined_at: string; suspended_at: string | null }
type Filter = { search: string; role: string; status: string }

export function WorkspacePeople({ workspace, role, user, onChanged }: {
  workspace: string; role: 'owner' | 'admin'; user: string; onChanged: () => Promise<void>
}) {
  const [verified, setVerified] = useState<boolean | undefined>()
  const [prompt, setPrompt] = useState(false)
  const refresh = useCallback(async () => {
    const { data, error } = await db!.rpc('st_v7_workspace_people_verified', { p_workspace: workspace })
    setVerified(!error && data === true)
  }, [workspace])
  useEffect(() => {
    void refresh()
    const timer = window.setInterval(refresh, 15000)
    return () => window.clearInterval(timer)
  }, [refresh])

  return <section aria-label="Manage workspace members">
    <h2>Members</h2>
    {verified === undefined ? <p role="status">Checking member management access…</p>
      : verified ? <WorkspaceDirectory workspace={workspace} role={role} user={user} onChanged={onChanged} onVerificationChanged={refresh}/>
        : prompt ? <StaffMfa refresh={refresh} explanation="Enter a current authenticator code to manage workspace member roles and access."/>
          : <button className="secondary" type="button" onClick={() => setPrompt(true)}>Verify to manage members</button>}
  </section>
}

function WorkspaceDirectory({ workspace, role, user, onChanged, onVerificationChanged }: {
  workspace: string; role: 'owner' | 'admin'; user: string; onChanged: () => Promise<void>; onVerificationChanged: () => Promise<void>
}) {
  const [filter, setFilter] = useState<Filter>({ search: '', role: 'all', status: 'all' })
  const [cursor, setCursor] = useState('')
  const [people, setPeople] = useState<Person[]>([])
  const [selected, setSelected] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState('')
  const [revision, setRevision] = useState(0)

  useEffect(() => {
    let current = true
    setLoading(true)
    void db!.rpc('st_v7_workspace_people', {
      p_workspace: workspace, p_search: filter.search, p_role: filter.role, p_status: filter.status, p_after: cursor,
    }).then(async ({ data, error }) => {
      if (!current) return
      if (error) { setPeople([]); setError('Could not load workspace members.'); await onVerificationChanged() }
      else setPeople(data as Person[])
      if (current) setLoading(false)
    })
    return () => { current = false }
  }, [workspace, filter, cursor, onVerificationChanged, revision])

  function search(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const fields = new FormData(event.currentTarget)
    setCursor('')
    setSelected(null)
    setResult('')
    setError('')
    setFilter({
      search: String(fields.get('search') ?? ''),
      role: String(fields.get('role') ?? 'all'),
      status: String(fields.get('status') ?? 'all'),
    })
  }

  async function update(person: Person, action: string) {
    if (busy) return
    setBusy(true)
    setError('')
    setResult('')
    const { error } = await db!.rpc('st_v2_set_member', { p_workspace: workspace, p_member: person.id, p_role: action })
    if (error) { setError('Could not change workspace member access.'); await onVerificationChanged() }
    else {
      setResult('Workspace member access updated.')
      setRevision(value => value + 1)
      await onChanged()
    }
    setBusy(false)
  }

  const person = people.find(person => person.id === selected)
  const manageable = person && person.id !== user && person.role !== 'owner' && (role === 'owner' || person.role === 'member')
  return <>
    <form className="release-form" onSubmit={search}>
      <label>Name or handle<input name="search" maxLength={50}/></label>
      <label>Workspace role<select name="role" aria-label="Workspace role">
        <option value="all">All roles</option><option value="owner">Owner</option><option value="admin">Admin</option><option value="member">Member</option>
      </select></label>
      <label>Workspace access<select name="status" aria-label="Workspace access">
        <option value="all">All access states</option><option value="active">Active</option><option value="suspended">Suspended</option>
      </select></label>
      <button className="secondary" disabled={busy}>Search members</button>
    </form>
    {loading ? <p role="status">Loading members…</p> : !people.length ? <p>No members match these filters.</p> :
      <ul className="release-section">{people.slice(0,40).map(person => <li className="release-row" key={person.id}>
        <button className="text-button" type="button" disabled={busy} onClick={() => {
          setSelected(person.id);setError('');setResult('')
        }}>{person.name} (@{person.handle})</button><span className="pill">{person.role}</span>
        {person.suspended_at && <span className="pill">Suspended</span>}
      </li>)}</ul>}
    <div className="actions">
      {cursor && <button className="secondary" type="button" disabled={busy} onClick={() => { setCursor('');setSelected(null) }}>First page</button>}
      {people.length > 40 && <button className="secondary" type="button" disabled={busy} onClick={() => { setCursor(people[39].handle);setSelected(null) }}>Next page</button>}
    </div>
    {!loading && person && <article className="release-board-item">
      <h3>{person.name}</h3>
      <p>@{person.handle} · {person.role} · {person.suspended_at ? 'Suspended' : 'Active'} · Joined {new Date(person.joined_at).toLocaleDateString()}</p>
      {manageable && <>
        {role === 'owner' && <form className="release-form" key={person.id + person.role} onSubmit={event => {
          event.preventDefault()
          void update(person, String(new FormData(event.currentTarget).get('change-role') ?? ''))
        }}>
          <label>Change access<select name="change-role" aria-label="Change access" defaultValue={person.role}>
            <option value="member">Member</option><option value="admin">Admin</option><option value="remove">Remove access</option>
          </select></label><button className="secondary" disabled={busy}>Apply access change</button>
        </form>}
        <button className="secondary" type="button" disabled={busy}
          onClick={() => void update(person, person.suspended_at ? 'restore' : 'suspend')}>
          {person.suspended_at ? 'Restore access' : 'Suspend access'}
        </button>
      </>}
    </article>}
    {result && <p role="status">{result}</p>}
    {error && <p className="error" role="alert">{error}</p>}
  </>
}
