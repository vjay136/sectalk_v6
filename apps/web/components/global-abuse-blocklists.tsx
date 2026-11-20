'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db } from '../lib/data'
import { StaffMfa } from './staff-mfa'

type Access = 'none' | 'mfa' | 'verified'
type Kind = 'domain' | 'sha256' | 'cidr'
type Rule = {
  id: string; kind: Kind; value: string; reason: string; created_at: string; expires_at: string
  revoked_at: string | null; revocation_reason: string | null
}
const names: Record<Kind,string> = { domain: 'Domain', sha256: 'SHA-256', cidr: 'IP range' }
const placeholders: Record<Kind,string> = { domain: 'example.invalid', sha256: '64 hexadecimal characters', cidr: '192.0.2.0/24' }

export function useAbuseBlocklistAccess() {
  const [access, setAccess] = useState<Access>('none')
  const refresh = useCallback(async () => {
    const { data, error } = await db!.rpc('st_v7_abuse_blocklist_access')
    setAccess(!error && (data === 'mfa' || data === 'verified') ? data : 'none')
  }, [])
  useEffect(() => {
    void refresh()
    const timer = window.setInterval(refresh, 15000)
    return () => window.clearInterval(timer)
  }, [refresh])
  return { access, refresh }
}

export function GlobalAbuseBlocklists({ access, refresh }: { access: Access; refresh: () => Promise<void> }) {
  if (access === 'none') return null
  if (access === 'mfa') return <StaffMfa refresh={refresh}
    explanation="Enter a current authenticator code to manage global abuse blocklists."/>
  return <Directory onAccessChanged={refresh}/>
}

function Directory({ onAccessChanged }: { onAccessChanged: () => Promise<void> }) {
  const [kind, setKind] = useState<Kind>('domain')
  const [filter, setFilter] = useState({ kind: 'all', state: 'active' })
  const [cursor, setCursor] = useState<{ timestamp: string; id: string } | null>(null)
  const [rules, setRules] = useState<Rule[]>([])
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [revision, setRevision] = useState(0)
  const [selected, setSelected] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    setLoading(true)
    void db!.rpc('st_v7_abuse_blocks', {
      p_kind: filter.kind, p_state: filter.state, p_before: cursor?.timestamp ?? null, p_before_id: cursor?.id ?? null,
    }).then(async ({ data, error }) => {
      if (!live) return
      if (error) { setRules([]); setError('Could not load the abuse blocklists.'); await onAccessChanged() }
      else setRules(data as Rule[])
      if (live) setLoading(false)
    })
    return () => { live = false }
  }, [filter, cursor, revision, onAccessChanged])

  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const fields = new FormData(event.currentTarget)
    setSelected(null)
    setError('')
    setCursor(null)
    setFilter({ kind: String(fields.get('kind')), state: String(fields.get('state')) })
  }

  async function change(event: FormEvent<HTMLFormElement>, id?: string) {
    event.preventDefault()
    if (busy) return
    const form = event.currentTarget
    const fields = new FormData(form)
    const reason = String(fields.get('reason') ?? '').trim()
    setBusy(true)
    setError('')
    setMessage('')
    const { data, error } = id
      ? await db!.rpc('st_v7_revoke_abuse_block', { p_id: id, p_reason: reason })
      : await db!.rpc('st_v7_add_abuse_block', {
        p_kind: kind, p_value: String(fields.get('indicator') ?? '').trim(),
        p_reason: reason, p_days: Number(fields.get('duration')),
      })
    setBusy(false)
    if (error) {
      setError(error.code === '22023' || error.code === 'PT409' ? error.message : 'Could not change the blocklist.')
      await onAccessChanged()
      return
    }
    form.reset()
    setMessage(id ? (data === true ? 'Block released.' : 'This block has already closed.') : 'Block added.')
    setSelected(null)
    if (!id) setCursor(null)
    setRevision(value => value + 1)
  }

  return <section className="panel release-panel" aria-label="Global abuse blocklists">
    <h2>Global abuse blocklists</h2>
    <p>Domains cover matching webhooks and email invitations, including subdomains. SHA-256 digests block new chat and workspace file uploads. IP ranges block new sessions and refreshes for native sign-in.</p>
    <details className="release-create">
      <summary>Add a block</summary>
      <form className="release-form" onSubmit={change}>
        <label>Indicator type<select aria-label="Indicator type" value={kind} onChange={event => setKind(event.target.value as Kind)}>
          {Object.entries(names).map(([value, name]) => <option key={value} value={value}>{name}</option>)}
        </select></label>
        <label>Indicator<input key={kind} name="indicator" placeholder={placeholders[kind]} required maxLength={255} /></label>
        <label>Duration in days<input type="number" name="duration" min={1} max={30} defaultValue={7} required /></label>
        <label>Case reference and reason<textarea name="reason" required minLength={10} maxLength={240} /></label>
        <button className="primary" disabled={busy}>Add block</button>
      </form>
    </details>
    <form className="release-form" onSubmit={applyFilters}>
      <label>Filter indicator type<select name="kind" aria-label="Filter indicator type">
        <option value="all">All types</option>
        {Object.entries(names).map(([value, name]) => <option key={value} value={value}>{name}</option>)}
      </select></label>
      <label>Block status<select name="state" aria-label="Block status">
        <option value="active">Active</option><option value="closed">Closed</option><option value="all">All statuses</option>
      </select></label>
      <button className="secondary" disabled={busy}>Apply filters</button>
    </form>
    {loading ? <p role="status">Loading blocks…</p> : !rules.length ? <p>No blocks match these filters.</p> :
      <ul className="release-section">{rules.slice(0,40).map(rule => {
        const active = !rule.revoked_at && Date.parse(rule.expires_at)>Date.now()
        return <li className="release-board-item" key={rule.id}>
          <p><span className="pill">{names[rule.kind]}</span> <strong>{rule.value}</strong></p>
          <p>{rule.reason}</p>
          <p>Added <time dateTime={rule.created_at}>{new Date(rule.created_at).toLocaleString()}</time></p>
          {rule.revoked_at ? <p>Released <time dateTime={rule.revoked_at}>{new Date(rule.revoked_at).toLocaleString()}</time> · {rule.revocation_reason}</p>
            : <p>{active ? 'Expires' : 'Expired'} <time dateTime={rule.expires_at}>{new Date(rule.expires_at).toLocaleString()}</time></p>}
          {active && (selected === rule.id
            ? <form className="release-form" onSubmit={event => void change(event, rule.id)}>
                <label>Release reason<textarea name="reason" required minLength={10} maxLength={240}/></label>
                <button className="primary" disabled={busy}>Confirm release</button>
                <button className="secondary" disabled={busy} type="button" onClick={() => setSelected(null)}>Cancel</button>
              </form>
            : <button className="secondary" type="button" disabled={busy} onClick={() => setSelected(rule.id)}>Release block</button>)}
        </li>
      })}</ul>}
    <div className="actions">
      {cursor && <button className="secondary" type="button" disabled={busy} onClick={() => setCursor(null)}>First page</button>}
      {rules.length>40 && <button className="secondary" type="button" disabled={busy}
        onClick={() => setCursor({ timestamp: rules[39].created_at, id: rules[39].id })}>Next page</button>}
    </div>
    {message && <p role="status">{message}</p>}
    {error && <p role="alert" className="error">{error}</p>}
  </section>
}
