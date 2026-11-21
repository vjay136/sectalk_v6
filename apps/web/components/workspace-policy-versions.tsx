'use client'

import { useEffect, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'
import { SectionTabs } from './section-tabs'

type Policy = 'retention' | 'notifications'
type Settings = { days?: number; categories?: string[]; quiet_minutes?: number | null }
type Snapshot = {
  version: number; current: Settings; entries: { version: number; settings: Settings; recorded_at?: string }[]
}
type Proposal = {
  proposed: Settings; queued?: number; eligible_under_proposal?: number; active_members?: number; new_mandatory?: string[]
}
const categories: Record<string, string> = {
  mention: 'Room mentions', thread: 'Followed thread replies', task: 'Room task updates', admin: 'Admin room updates',
}
const ssoRequired = 'Sign in with workspace single sign-on to manage policies.'

function describe(policy: Policy, settings: Settings) {
  if (policy === 'retention') return settings.days + ' retention days'
  const required = settings.categories?.map(id => categories[id]).join(', ') || 'No mandatory categories'
  return required + ' · ' + (settings.quiet_minutes === null ? 'No quiet-hour limit' : settings.quiet_minutes + ' quiet minutes')
}

export function WorkspacePolicyVersions({ workspace, onChanged }: { workspace: string; onChanged: () => void }) {
  const [policy, setPolicy] = useState<Policy>('retention')
  return <section className="release-section" aria-labelledby="policy-versions-heading">
    <h2 id="policy-versions-heading">Policy versions</h2>
    <SectionTabs label="Workspace policy types" value={policy} onChange={setPolicy}
      options={[['retention', 'Room retention'], ['notifications', 'Notifications']]} />
    <PolicyEditor key={workspace + policy} workspace={workspace} policy={policy} onChanged={onChanged} />
  </section>
}

function PolicyEditor({ workspace, policy, onChanged }: { workspace: string; policy: Policy; onChanged: () => void }) {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null)
  const [review, setReview] = useState<{ proposal: Proposal; target: number | null } | null>(null)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const [revision, setRevision] = useState(0)

  useEffect(() => {
    let active = true
    setBusy(true)
    void db!.rpc('st_v6_workspace_policy_versions', { p_workspace: workspace, p_policy: policy }).then(result => {
      if (!active) return
      setBusy(false)
      if (result.error) {
        setError(result.error.message === ssoRequired ? ssoRequired : 'Could not load policy versions.')
        setSnapshot(null)
      }
      else { setSnapshot(result.data as Snapshot); setError('') }
    })
    return () => { active = false }
  }, [workspace, policy, revision])

  async function update(action: 'preview' | 'apply' | 'rollback', settings: Settings | null, target: number | null) {
    if (busy || !snapshot) return
    setBusy(true); setError(''); setMessage('')
    try {
      const result = await db!.rpc('st_v6_change_workspace_policy', {
        p_workspace: workspace, p_policy: policy, p_action: action, p_settings: settings,
        p_version: snapshot.version, p_target: target,
      })
      if (result.error) throw result.error
      if (action === 'preview') setReview({ proposal: result.data as Proposal, target })
      else {
        setSnapshot(result.data as Snapshot)
        setReview(null)
        setMessage(action === 'rollback' ? 'Previous policy restored as a new version.' : 'Policy version applied.')
        onChanged()
      }
    } catch (cause) {
      const failure = formatError(cause, 'Could not complete the policy action.')
      setError(failure)
      if (failure === ssoRequired) setSnapshot(null)
      setReview(null)
    } finally {
      setBusy(false)
    }
  }

  function simulate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const values = new FormData(event.currentTarget)
    const quiet = String(values.get('quiet') ?? '')
    const settings = policy === 'retention' ? { days: Number(values.get('days')) }
      : { categories: values.getAll('category').map(String), quiet_minutes: quiet ? Number(quiet) : null }
    void update('preview', settings, null)
  }

  return <div className="release-section">
    {error && <p role="alert" className="error">{error}</p>}
    {message && <p role="status">{message}</p>}
    <button className="secondary" type="button" disabled={busy} onClick={() => {
      setReview(null); setRevision(value => value + 1)
    }}>Refresh policy versions</button>
    {snapshot && <>
      <form className="release-form" key={snapshot.version} onSubmit={simulate} onChange={() => setReview(null)}>
        {policy === 'retention' ?
          <label>Proposed retention days<input name="days" type="number" min="7" max="3650" defaultValue={snapshot.current.days} required /></label> :
          <>
            <fieldset><legend>Mandatory notifications</legend>
              {Object.entries(categories).map(([id, label]) => <label key={id}>
                <input name="category" type="checkbox" value={id} defaultChecked={snapshot.current.categories?.includes(id)} /> {label}
              </label>)}
            </fieldset>
            <label>Proposed quiet-hour limit in minutes<input name="quiet" type="number" min="0" max="1440"
              defaultValue={snapshot.current.quiet_minutes ?? ''} placeholder="No limit" /></label>
          </>}
        <button className="secondary" disabled={busy}>Preview policy impact</button>
      </form>
      {review && <section className="panel release-panel" aria-label="Policy impact preview">
        <h3>{review.target === null ? 'Proposed change' : 'Rollback preview for version ' + review.target}</h3>
        <p>{describe(policy, review.proposal.proposed)}</p>
        {policy === 'retention' ? <p>{review.proposal.queued} rooms scheduled for deletion. {review.proposal.eligible_under_proposal}
          {' '}would be eligible now with this policy.</p> : <>
          <p>{review.proposal.active_members} active workspace members in scope.</p>
          {Boolean(review.proposal.new_mandatory?.length) && <p>Newly mandatory categories
            {' '}{review.proposal.new_mandatory?.map(id => categories[id]).join(', ')}.</p>}
        </>}
        <button className="primary" type="button" disabled={busy} onClick={() =>
          void update(review.target === null ? 'apply' : 'rollback', review.proposal.proposed, review.target)}>
          {review.target === null ? 'Apply previewed policy' : 'Restore this version'}
        </button>
      </section>}
      <h3>Version history</h3>
      <ol className="audit">{snapshot.entries.map(entry => <li key={entry.version}>
        <strong>Version {entry.version}{entry.version === snapshot.version ? ' · Current' : ''}</strong>
        <p>{describe(policy, entry.settings)}</p>
        {entry.recorded_at && <time dateTime={entry.recorded_at}>{new Date(entry.recorded_at).toLocaleString()}</time>}
        {entry.version !== snapshot.version && <button className="secondary" type="button" disabled={busy}
          onClick={() => void update('preview', null, entry.version)}>Preview rollback to version {entry.version}</button>}
      </li>)}</ol>
    </>}
  </div>
}
