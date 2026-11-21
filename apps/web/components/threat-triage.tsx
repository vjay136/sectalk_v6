'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db } from '../lib/data'
import { StaffMfa } from './staff-mfa'
import { ThreatPlaybooks } from './threat-playbooks'
import { SocResponseActions } from './soc-response-actions'

type Signal = 'detection' | 'attachment_inspection' | 'malware'
export type ThreatTriageAccess = { status: 'none' } | { status: 'mfa' } | { status: 'verified'; scopes: Signal[] }
type QueueItem = {
  id: string; signal_type: Signal; severity: 'low' | 'medium' | 'high'
  confidence: 'heuristic' | 'supported' | 'confirmed'; state: 'open' | 'reviewing' | 'confirmed' | 'dismissed'
  details: { source?: string; scope?: string; metric?: string; version?: number; threshold?: number; observed?: number; signal?: string }
  detected_at: string; revision: number
}
type Filter = { state: string; type: string; severity: string; confidence: string }
type Selection = Pick<QueueItem,'id' | 'revision'>
type HistoryEvent = { id: number; action: string; actor: string | null; reason: string | null; occurred_at: string }
const signalLabels: Record<Signal,string> = {
  detection: 'Detection rule', attachment_inspection: 'Attachment inspection', malware: 'Malware verdict',
}
const detailNames: Record<string,string> = {
  file_upload: 'Upload attachment', file_publish: 'Publish attachment', file_download_grant: 'Authorize attachment download',
  file_download: 'Download attachment', call_ice: 'Direct call networking', meeting_token: 'Meeting media token',
  billing_action: 'Billing action', billing_webhook: 'Billing webhook', requests: 'Requests',
  client_errors: 'Client errors (4xx)', server_errors: 'Server errors (5xx)', throttled: 'Throttled requests (429)',
  unavailable: 'Unavailable responses (503)', anomalies: 'Native login anomalies', scanner_verdict: 'Matched malware scan or reputation',
  document_macro_marker: 'Macro marker', script_marker: 'Script marker', embedded_document_marker: 'Embedded document marker',
  embedded_link_marker: 'Embedded link marker', suspicious_link_format: 'Suspicious link format',
}
const states = { open:'Open',reviewing:'Reviewing',confirmed:'Confirmed',dismissed:'Dismissed' }
const decisions = { reviewing:'Mark reviewing',confirmed:'Confirm signal',dismissed:'Dismiss signal',reopened:'Reopen signal' }
const confidenceLabels = { heuristic:'Heuristic',supported:'Supported',confirmed:'Confirmed' }
const severityLabels = { low:'Low',medium:'Medium',high:'High' }
const events: Record<string,string> = { received:'Signal received',reviewing:'Marked for review',
  confirmed:'Confirmed by reviewer',dismissed:'Dismissed by reviewer',reopened:'Reopened by reviewer' }
const initialFilters = { state:'open',type:'all',severity:'all',confidence:'all' }

export function useThreatTriageAccess() {
  const [access,setAccess] = useState<ThreatTriageAccess>({ status:'none' })
  const refresh = useCallback(async () => {
    const { data,error } = await db!.rpc('st_v7_threat_triage_access')
    setAccess(!error && (data?.status==='verified' || data?.status==='mfa') ? data as ThreatTriageAccess : { status:'none' })
  },[])
  useEffect(() => {
    void refresh()
    const timer = window.setInterval(refresh,15000)
    return () => window.clearInterval(timer)
  },[refresh])
  return { access,refresh }
}

export function ThreatTriage({ access,refresh,showResponseActions=true }: {
  access: ThreatTriageAccess; refresh: () => Promise<void>; showResponseActions?: boolean
}) {
  if (access.status==='none') return null
  if (access.status==='mfa') return <StaffMfa refresh={refresh} explanation="Enter a current authenticator code to review your assigned signal types."/>
  return <Queue scopes={access.scopes} onAccessChanged={refresh} showResponseActions={showResponseActions}/>
}

function Queue({ scopes,onAccessChanged,showResponseActions }: { scopes: Signal[]; onAccessChanged: () => Promise<void>;
  showResponseActions: boolean }) {
  const [filter,setFilter] = useState<Filter>(initialFilters)
  const [rows,setRows] = useState<QueueItem[] | null>(null)
  const [cursor,setCursor] = useState<{ at: string; id: string } | null>(null)
  const [picked,setPicked] = useState<Selection[]>([])
  const [busy,setBusy] = useState(false)
  const [error,setError] = useState('')
  const [message,setMessage] = useState('')

  const load = useCallback(async (signal?: AbortSignal) => {
    const query = db!.rpc('st_v7_threat_queue',{
      p_state:filter.state,p_type:filter.type,p_severity:filter.severity,p_confidence:filter.confidence,
      p_before:cursor?.at ?? null,p_before_id:cursor?.id ?? null,
    })
    const { data,error } = await (signal ? query.abortSignal(signal) : query)
    if (signal?.aborted) return
    if (error) {
      setRows(null)
      setError('Could not load the threat queue.')
      if (error.code==='42501') await onAccessChanged()
    } else setRows(data as QueueItem[])
  },[filter,cursor,onAccessChanged])

  useEffect(() => {
    const controller = new AbortController()
    void load(controller.signal)
    const timer = !cursor && picked.length===0 ? window.setInterval(() => void load(controller.signal),5000) : undefined
    return () => {controller.abort();window.clearInterval(timer)}
  },[load,cursor,picked.length])

  function filterQueue(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const fields = new FormData(event.currentTarget)
    setFilter({
      state:String(fields.get('state') ?? 'open'),type:String(fields.get('type') ?? 'all'),
      severity:String(fields.get('severity') ?? 'all'),confidence:String(fields.get('confidence') ?? 'all'),
    })
    setRows(null)
    setCursor(null)
    setPicked([])
    setError('')
    setMessage('')
  }

  function toggle(row: QueueItem) {
    setPicked(current => current.some(item => item.id===row.id) ? current.filter(item => item.id!==row.id) :
      current.length<25 ? [...current,{id:row.id,revision:row.revision}] : current)
  }

  async function decide(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!picked.length || busy) return
    const form = event.currentTarget
    const fields = new FormData(form)
    setBusy(true)
    setError('')
    setMessage('')
    const { data,error } = await db!.rpc('st_v7_apply_threat_triage',{
      p_items:picked,p_action:fields.get('action'),p_reason:fields.get('reason'),
    })
    if (error) {
      setError(error.message)
      if (error.code==='42501') await onAccessChanged()
    } else {
      setPicked([])
      form.reset()
      setMessage(Number(data)===1 ? 'Triage decision applied to 1 item.' : 'Triage decision applied to ' + data + ' items.')
      await load()
    }
    setBusy(false)
  }

  function changePage(next: { at: string; id: string } | null) {
    setCursor(next)
    setRows(null)
    setPicked([])
    setError('')
    setMessage('')
  }

  const typeOptions = Object.fromEntries(scopes.map(scope => [scope,signalLabels[scope]]))
  const visible = rows?.slice(0,40)
  return <section className="panel release-panel" aria-label="Threat triage">
    <h2>Threat triage</h2>
    <p>Review enabled detections and attachment safety signals in your scope. Bulk decisions update the queue and its audit history.</p>
    <form className="release-form" aria-label="Threat filters" onSubmit={filterQueue}>
      <FilterSelect name="state" label="Triage status" choices={states} initial="open"/>
      <FilterSelect name="type" label="Signal type" choices={typeOptions}/>
      <FilterSelect name="severity" label="Severity" choices={severityLabels}/>
      <FilterSelect name="confidence" label="Signal confidence" choices={confidenceLabels}/>
      <button className="secondary" disabled={busy}>Apply threat filters</button>
    </form>
    <form className="release-form" aria-label="Bulk triage" onSubmit={decide}>
      <p>{picked.length} selected</p>
      <label>Bulk decision<select aria-label="Bulk decision" name="action" required defaultValue="">
        <option value="" disabled>Choose a decision</option>{Object.entries(decisions).map(([value,label]) =>
          <option key={value} value={value}>{label}</option>)}
      </select></label>
      <label>Triage reason<textarea name="reason" required minLength={10} maxLength={500}/></label>
      <button className="primary" disabled={busy || !picked.length}>Apply bulk triage</button>
      {picked.length>0 && <button className="secondary" disabled={busy} type="button" onClick={() => setPicked([])}>Clear selection</button>}
    </form>
    {!rows && !error && <p role="status">Loading threats…</p>}
    {rows?.length===0 && <p>No threats match these filters.</p>}
    {visible?.map(row => {
      const selected = picked.some(item => item.id===row.id)
      return <article className="release-board-item" key={row.id} data-threat-id={row.id}>
        <h3>{signalLabels[row.signal_type]}</h3>
        <p><span className="pill">{severityLabels[row.severity]}</span> · {confidenceLabels[row.confidence]} · {states[row.state]}</p>
        {row.signal_type==='detection' ? <>
          <p>{row.details.source==='login_anomalies' ? 'Platform sign-in' : detailNames[row.details.scope ?? '']}
            {' · '}{detailNames[row.details.metric ?? '']} · Rule version {row.details.version}</p>
          <p>Observed {row.details.observed} · Threshold {row.details.threshold}</p>
        </> : <p>{detailNames[row.details.signal ?? '']}</p>}
        <p><time dateTime={row.detected_at}>{new Date(row.detected_at).toLocaleString()}</time></p>
        <label><input type="checkbox" checked={selected} disabled={busy || !selected && picked.length>=25}
          onChange={() => toggle(row)}/>Select for triage</label>
        <ThreatHistory key={row.id + ':' + row.revision} item={row.id}/>
      </article>
    })}
    <div className="actions">
      {cursor && <button className="secondary" type="button" disabled={busy} onClick={() => changePage(null)}>First page</button>}
      {rows && rows.length>40 && <button className="secondary" type="button" disabled={busy}
        onClick={() => changePage({ at:rows[39].detected_at,id:rows[39].id })}>Next page</button>}
    </div>
    {message && <p role="status">{message}</p>}
    {error && <p role="alert" className="error">{error}</p>}
    <ThreatPlaybooks signals={visible ?? []} refreshQueue={load}/>
    {showResponseActions && <SocResponseActions/>}
  </section>
}

function FilterSelect({ name,label,choices,initial='all' }: { name: string; label: string; choices: Record<string,string>; initial?: string }) {
  return <label>{label}<select name={name} aria-label={label} defaultValue={initial}>
    <option value="all">All</option>
    {Object.entries(choices).map(([value,text]) => <option key={value} value={value}>{text}</option>)}
  </select></label>
}

function ThreatHistory({ item }: { item: string }) {
  const [eventsSeen,setEventsSeen] = useState<HistoryEvent[] | null>(null)
  const [error,setError] = useState(false)
  return <details onToggle={event => {
    if (!event.currentTarget.open || eventsSeen) return
    void db!.rpc('st_v7_threat_triage_history',{p_item:item}).then(({data,error}) => {
      setError(Boolean(error))
      if (!error) setEventsSeen(data as HistoryEvent[])
    })
  }}>
    <summary>Triage history</summary>
    {error ? <p role="alert">Could not load triage history.</p> : !eventsSeen ? <p role="status">Loading history…</p> :
      <ul className="audit">{eventsSeen.map(event => <li key={event.id}>
        <strong>{events[event.action]}</strong> · <time dateTime={event.occurred_at}>{new Date(event.occurred_at).toLocaleString()}</time>
        {event.reason && <p>{event.reason}</p>}
        {event.actor && <p>Reviewer <code>{event.actor}</code></p>}
      </li>)}</ul>}
  </details>
}
