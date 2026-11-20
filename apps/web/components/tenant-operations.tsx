'use client'

import { useState, type FormEvent } from 'react'
import { db } from '../lib/data'
import { SectionTabs } from './section-tabs'
import { EmergencyAccess } from './emergency-access'

type WorkspaceMetadata = { id: string; name: string; created_at: string }
type WorkspaceDetails = WorkspaceMetadata & { member_count: number }

const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' })

export function TenantOperations({ onAccessChanged }: { onAccessChanged: () => Promise<void> }) {
  const [tab, setTab] = useState<'workspaces' | 'emergency'>('workspaces')
  const [results, setResults] = useState<WorkspaceMetadata[] | null>(null)
  const [selected, setSelected] = useState<WorkspaceDetails | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function search(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    const query = String(new FormData(event.currentTarget).get('query')).trim()
    setSelected(null)
    setResults(null)
    setError('')
    if (query.length < 2) {
      setError('Enter a workspace ID or at least two characters of its name.')
      return
    }
    setBusy(true)
    try {
      const { data, error } = await db!.rpc('st_v6_tenant_search', { p_query: query })
      if (error) {
        setError('Could not search for workspaces.')
        if (error.code === '42501') await onAccessChanged()
        return
      }
      setResults(data as WorkspaceMetadata[])
    } finally {
      setBusy(false)
    }
  }

  async function view(id: string) {
    if (busy) return
    setBusy(true)
    setError('')
    try {
      const { data, error } = await db!.rpc('st_v6_tenant_view', { p_workspace: id }).maybeSingle()
      if (error) {
        setError('Could not load workspace metadata.')
        if (error.code === '42501') {
          setResults(null)
          await onAccessChanged()
        }
      } else if (!data) setError('The workspace is no longer available.')
      else setSelected(data as WorkspaceDetails)
    } finally {
      setBusy(false)
    }
  }

  return <div className="panel">
    <div className="panel-header"><h2>Tenant operations</h2></div>
    <SectionTabs label="Tenant operations sections" value={tab} onChange={setTab}
      options={ [['workspaces','Workspace lookup'], ['emergency','Emergency access']] }/>
    {tab === 'emergency' ? <EmergencyAccess/> : <>
    <form onSubmit={search}>
      <label>Workspace ID or start of name<input type="search" name="query" minLength={2} maxLength={64} required disabled={busy}/></label>
      <button className="primary" disabled={busy}>Search workspaces</button>
    </form>
    {busy && <p role="status">Loading workspace metadata…</p>}
    {error && <p role="alert" className="error">{error}</p>}
    {selected ? <div className="case">
      <div className="panel-header"><h3>{selected.name}</h3>
        <button type="button" className="secondary" onClick={() => setSelected(null)}>Back to results</button>
      </div>
      <dl>
        <dt>Workspace ID</dt><dd><code>{selected.id}</code></dd>
        <dt>Created</dt><dd><time dateTime={selected.created_at}>{dateFormat.format(new Date(selected.created_at))}</time></dd>
        <dt>Members</dt><dd>{selected.member_count}</dd>
      </dl>
    </div> : results && <>
      <p role="status">{results.length === 25 ? 'Showing up to 25 matches. Enter more of the workspace name to narrow your search.'
        : results.length ? `${results.length} workspace${results.length === 1 ? '' : 's'} found.` : 'No matching workspaces.'}</p>
      {results.map(workspace => <button type="button" className="report-row" key={workspace.id}
        disabled={busy} onClick={() => void view(workspace.id)}>
        <span><strong>{workspace.name}</strong><small>{workspace.id}</small></span>
      </button>)}
    </>}
    </>}
  </div>
}
