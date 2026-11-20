'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { db, formatError, onReconnect } from '../lib/data'

const severities = { low: 'Low', moderate: 'Moderate', high: 'High', critical: 'Critical' }
const states = { open: 'Open', investigating: 'Investigating', contained: 'Contained', resolved: 'Resolved' }
const events: Record<string, string> = {
  'incident.created': 'Incident created', 'incident.assigned': 'Responder assigned',
  'incident.updated': 'Status or severity updated', 'incident.note': 'Timeline note added',
  'incident.report_linked': 'Report linked', 'incident.postmortem_saved': 'Postmortem saved',
}
type Status = keyof typeof states
type Severity = keyof typeof severities
type Incident = {
  id: string; title: string; severity: Severity; status: Status; created_by: string
  assigned_to: string; updated_at: string; postmortem: string | null
}
type Entry = { id: number; actor_name: string; event: string; occurred_at: string; note: string | null; subject: string | null }
type Detail = { role: string; incident: Incident; roster: { id: string; name: string }[] | null; reports: string[]; timeline: Entry[] }
type Action = 'create' | 'assign' | 'update' | 'note' | 'link' | 'postmortem'

export function SecurityIncidents({ report, onLinked }: { report: string | null; onLinked: () => void }) {
  const [incidents, setIncidents] = useState<Incident[] | null>(null)
  const [selected, setSelected] = useState<string | null>(null)
  const [detail, setDetail] = useState<Detail | null>(null)
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const version = useRef(0)
  const pending = useRef<{ id: string; key: string } | null>(null)

  const load = useCallback(async (id: string | null) => {
    const sequence = ++version.current
    const result = await db!.rpc('st_v6_incident_dashboard', { p_incident: id })
    if (sequence !== version.current) return
    if (result.error) {
      setDetail(null); setIncidents(null)
      setError('Could not load incident operations.')
    } else if (id) {
      setDetail(result.data as Detail)
    } else {
      setIncidents(result.data.incidents as Incident[])
    }
  }, [])
  useEffect(() => {
    const refresh = () => void load(selected)
    refresh()
    const timer = window.setInterval(() => { if (document.visibilityState === 'visible') refresh() }, 10000)
    const reconnect = onReconnect(refresh)
    return () => { ++version.current; window.clearInterval(timer); reconnect() }
  }, [load, selected])

  function choose(id: string | null) {
    setSelected(id); setDetail(null); setNotice(''); setError('')
  }

  async function submit(event: FormEvent<HTMLFormElement>, action: Action) {
    event.preventDefault()
    if (busy) return
    const form = event.currentTarget
    const fields = Object.fromEntries(new FormData(form))
    let id = selected
    setBusy(true); setNotice(''); setError('')
    try {
      if (action === 'create') {
        const key = JSON.stringify(fields)
        if (pending.current?.key !== key) pending.current = { id: crypto.randomUUID(), key }
        id = pending.current.id
      }
      const result = await db!.rpc('st_v6_write_incident', { p_id: id, p_action: action, p_fields: fields })
      if (result.error) throw result.error
      if (action === 'create') {
        pending.current = null
        setSelected(result.data)
      } else {
        if (action === 'link') onLinked()
        if (action !== 'postmortem') form.reset()
        await load(id)
      }
      setNotice(action === 'link' ? 'Report linked.' : action === 'create' ? 'Incident created.' : 'Incident updated.')
    } catch (cause) {
      setError(formatError(cause, 'Could not update the incident.'))
    } finally {
      setBusy(false)
    }
  }

  const item = detail?.incident
  const transitions: Status[] = !item ? [] : item.status === 'open' ? ['open', 'investigating'] :
    item.status === 'investigating' ? ['investigating', 'contained', 'resolved'] :
      item.status === 'contained' ? ['contained', 'investigating', 'resolved'] :
        detail?.role === 'lead' ? ['resolved', 'investigating'] : ['resolved']

  return <section className="release-section" aria-label="Security incidents">
    <h2>Security incidents</h2>
    {notice && <p role="status">{notice}</p>}
    {error && <p role="alert" className="error">{error}</p>}
    {selected ? <button className="secondary" type="button" disabled={busy} onClick={() => choose(null)}>Back to incidents</button> : <>
      {report && <p>Select an incident or create one to link the selected report.</p>}
      <details className="release-create">
        <summary>Create an incident</summary>
        <form className="release-form" aria-label="New security incident" onSubmit={event => void submit(event, 'create')}>
          <label>Incident title<input name="title" minLength={5} maxLength={100} required /></label>
          <label>Incident severity<select name="severity" defaultValue="moderate">
            {Object.entries(severities).map(([id, name]) => <option value={id} key={id}>{name}</option>)}
          </select></label>
          <button className="primary" disabled={busy}>Create incident</button>
        </form>
      </details>
      {incidents?.length === 0 && <p>No incidents in your queue.</p>}
      {incidents?.map(incident => <button key={incident.id} type="button" className="report-row"
        onClick={() => choose(incident.id)}><strong>{incident.title}</strong>
        <span>{severities[incident.severity]} · {states[incident.status]}</span></button>)}
    </>}
    {selected && !detail && !error && <p role="status">Loading incident…</p>}
    {item && detail && <div className="panel release-panel">
      <h3>{item.title}</h3>
      <p>{severities[item.severity]} severity · {states[item.status]}</p>
      <form className="release-form" aria-label="Incident status" key={item.id + item.status + item.severity}
        onSubmit={event => void submit(event, 'update')}>
        <label>Status<select name="status" defaultValue={item.status}>
          {transitions.map(id => <option value={id} key={id}>{states[id]}</option>)}
        </select></label>
        <label>Severity<select name="severity" defaultValue={item.severity}>
          {Object.entries(severities).map(([id, name]) => <option value={id} key={id}>{name}</option>)}
        </select></label>
        <label>Update reason<input name="note" minLength={5} maxLength={1000} required /></label>
        <button className="primary" disabled={busy}>Save incident status</button>
      </form>
      {detail.roster && <details className="release-create">
        <summary>Assignment</summary>
        <form className="release-form" key={item.assigned_to} onSubmit={event => void submit(event, 'assign')}>
          <label>Assigned responder<select name="entity" defaultValue={item.assigned_to} required>
            <option value="">Choose a responder</option>
            {detail.roster.map(person => <option value={person.id} key={person.id}>{person.name}</option>)}
          </select></label>
          <label>Assignment reason<input name="note" minLength={5} maxLength={1000} required /></label>
          <button className="secondary" disabled={busy}>Assign responder</button>
        </form>
      </details>}
      <details className="release-create" open={Boolean(report) || undefined}>
        <summary>Linked reports</summary>
        {detail.reports.length > 0 && <ul>{detail.reports.map(id => <li key={id}><code>{id}</code></li>)}</ul>}
        <form className="release-form" onSubmit={event => void submit(event, 'link')}>
          <label>Report ID<input name="entity" defaultValue={report ?? ''} required pattern="[0-9a-fA-F\-]{36}" maxLength={36} /></label>
          <label>Link reason<input name="note" minLength={5} maxLength={1000} required /></label>
          <button className="secondary" disabled={busy}>Link report</button>
        </form>
      </details>
      <details className="release-create">
        <summary>Add timeline note</summary>
        <form className="release-form" onSubmit={event => void submit(event, 'note')}>
          <label>Timeline note<textarea name="note" minLength={5} maxLength={1000} rows={3} required /></label>
          <button className="secondary" disabled={busy}>Save note</button>
        </form>
      </details>
      {item.status === 'resolved' && <details className="release-create">
        <summary>Postmortem</summary>
        <form className="release-form" key={item.postmortem} onSubmit={event => void submit(event, 'postmortem')}>
          <label>Postmortem<textarea name="note" defaultValue={item.postmortem ?? ''} minLength={5} maxLength={4000} rows={5} required /></label>
          <button className="secondary" disabled={busy}>Save postmortem</button>
        </form>
      </details>}
      <h3>Timeline</h3>
      <ol className="audit">{detail.timeline.map(entry => <li key={entry.id}>
        <strong>{events[entry.event]}</strong>
        <small>{entry.actor_name} · <time dateTime={entry.occurred_at}>{new Date(entry.occurred_at).toLocaleString()}</time></small>
        {entry.subject && <code>{entry.subject}</code>}
        {entry.note && <p>{entry.note}</p>}
      </li>)}</ol>
    </div>}
  </section>
}
