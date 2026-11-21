'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { ArrowLeft, ArrowRight, Flag, ShieldAlert, ShieldCheck } from 'lucide-react'
import { categories, db, formatError, liveChannel, onReconnect } from '../lib/data'
import { downloadChatFile, type ChatFile } from '../lib/chat-files'
import { SocResponseActions } from './soc-response-actions'
import { CaseCollaboration, CaseCollaborationAlerts } from './case-collaboration'
import { CaseEscalation, CaseEscalationAssignments } from './case-escalation'
import { CaseBehaviorPanel } from './case-behavior-panel'

type Category = keyof typeof categories
export type Report = { id: string; category: Category; status: string; created_at: string }
type Queue = Report & { subject_handle: string }
type QueueTimer = Queue & {
  requested_priority: boolean
  acknowledge_by: string
  resolve_by: string
  acknowledged_at: string | null
  closed_at: string | null
  next_due: string | null
  overdue: boolean
}
type Case = Queue & {
  details: string; evidence: string | null; suspended_until: string | null
  message_redaction_available: boolean
  report_scope: 'direct' | 'group'
  attachment?: ChatFile | null
  history: { id: number; action: string; note: string; created_at: string }[]
}

export const labels: Record<string, string> = {
  open: 'Open', reviewing: 'In review', resolved: 'Resolved', dismissed: 'Dismissed',
  suspend: '24-hour suspension', restore: 'Restriction lifted', viewed: 'Evidence viewed',
  submitted:'Report received', escalated:'Escalated for review', warn:'Account warning issued',
  restrict:'Seven-day restriction', remove:'Indefinite restriction',
  redacted:'Reported message removed',
  case_note_added:'Collaboration note added', case_note_evidence_viewed:'Linked evidence opened',
  case_routed:'On-call stage assigned', case_route_acknowledged:'On-call stage acknowledged',
}

export function DateLabel({ value }: { value: string }) {
  return <time dateTime={value}>{new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}</time>
}

export function ModerationQueue({linkIncident}: {linkIncident?: (report: string) => void}) {
  const [rows, setRows] = useState<QueueTimer[] | null>(null)
  const [selected, setSelected] = useState<Case | null>(null)
  const [offset, setOffset] = useState(0)
  const [category, setCategory] = useState('')
  const [status, setStatus] = useState('active')
  const [due, setDue] = useState('any')
  const [error, setError] = useState('')
  const [working, setWorking] = useState(false)
  const [decisionAction, setDecisionAction] = useState('reviewing')
  const queueVersion = useRef(0)

  const load = useCallback(async () => {
    const version = ++queueVersion.current
    const { data, error } = await db!.rpc('st_v7_priority_abuse_queue', {
      p_category: category || null, p_status: status, p_due: due, p_offset: offset,
    })
    if (version !== queueVersion.current) return
    if (error) { setRows(null); setError('Could not load the moderation queue.') }
    else { setError(''); setRows(data as QueueTimer[]) }
  }, [category, status, due, offset])
  useEffect(() => {
    if (selected) return
    const refresh = () => { if (document.visibilityState === 'visible') void load() }
    const channel = liveChannel('moderation-queue', refresh)
      .on('postgres_changes', {event:'UPDATE',schema:'public',table:'st_v8_moderation_queue_signal'}, refresh)
      .subscribe()
    void load()
    const timer = window.setInterval(refresh, 15000)
    const removeReconnect = onReconnect(refresh)
    return () => {
      ++queueVersion.current
      window.clearInterval(timer)
      removeReconnect()
      void db!.removeChannel(channel)
    }
  }, [load, selected])
  const timer = selected && rows?.find(row => row.id === selected.id)

  async function open(id: string) {
    setWorking(true)
    setError('')
    const { data, error } = await db!.rpc('st_v5_case', { p_report: id })
    if (error) setError(formatError(error, 'Could not load case.'))
    else {setSelected(data as Case);setDecisionAction('reviewing')}
    setWorking(false)
    return !error && Boolean(data)
  }

  async function action(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!selected || working) return
    const form = event.currentTarget
    const values = new FormData(form)
    const decision=values.get('action')
    setWorking(true)
    setError('')
    if(decision==='remove'&&!window.confirm('Restrict this account until staff restore access?')){setWorking(false);return}
    if(decision==='redact_message'&&!window.confirm('Remove this reported message from the conversation and retain the shared evidence?')){
      setWorking(false);return
    }
    const terminal = selected.report_scope==='direct' && (decision==='resolved' || decision==='dismissed')
    const { error } = terminal ? await db!.rpc('st_v8_resolve_direct_report', {p_report:selected.id,p_action:decision,
      p_staff_note:values.get('reason'),p_reporter_summary:values.get('reporter-summary')}) : decision==='redact_message'
      ?await db!.rpc('st_v6_case_redact',{p_report:selected.id,p_note:values.get('reason')})
      :await db!.rpc('st_v5_moderate', { p_report: selected.id, p_action: decision, p_note: values.get('reason') })
    if (error) { setError(formatError(error, 'Could not record action.')); setWorking(false); return }
    form.reset()
    await load()
    await open(selected.id)
  }

  return <div className="panel"><div className="panel-header"><h2><ShieldAlert size={20}/> {selected ? 'Report details' : 'Moderation queue'}</h2>
    <button className="secondary" disabled={working} onClick={() => { if (selected) { setSelected(null); setError('') } else void load() }}>{selected ? 'Back to queue' : 'Refresh'}</button></div>
    {error && <p className="error" role="alert">{error}</p>}
    {!selected && <CaseCollaborationAlerts open={open}/>}
    {!selected && <CaseEscalationAssignments open={open}/>}
    {selected ? <div className="case">
      <span className={'pill state-' + selected.status}>{labels[selected.status]}</span>
      <h2>{categories[selected.category]}</h2><p>@{selected.subject_handle} · <DateLabel value={selected.created_at}/></p>
      {timer && <dl className="profile-stats">
        <div><dt>Acknowledge by</dt><dd><DateLabel value={timer.acknowledge_by}/></dd></div>
        <div><dt>Resolve by</dt><dd><DateLabel value={timer.resolve_by}/></dd></div>
        {timer.acknowledged_at && <div><dt>Acknowledged</dt><dd><DateLabel value={timer.acknowledged_at}/></dd></div>}
        {timer.closed_at && <div><dt>Closed</dt><dd><DateLabel value={timer.closed_at}/></dd></div>}
      </dl>}
      {selected.suspended_until && new Date(selected.suspended_until) > new Date() && <p className="warning">Restricted until <DateLabel value={selected.suspended_until}/></p>}
      {selected.suspended_until==='infinity'&&<p className="warning">Restricted until staff restore access</p>}
      <h3>Reporter notes</h3><p className="case-text">{selected.details || 'No notes provided.'}</p>
      <h3>Shared evidence</h3>{selected.evidence ? <blockquote>{selected.evidence}</blockquote> : <p>No message was attached.</p>}
      {linkIncident&&<button type="button" className="secondary" disabled={working}
        onClick={()=>linkIncident(selected.id)}>Link report to incident</button>}
      {selected.attachment&&<button type="button" className="secondary" onClick={async()=>{
        if(!selected.attachment)return
        try{await downloadChatFile(selected.attachment)}catch{setError('Evidence attachment could not be downloaded.')}
      }}>Download shared file</button>}
      <CaseCollaboration key={selected.id} report={selected.id}/>
      <SocResponseActions key={'response:' + selected.id} report={selected.id}/>
      <CaseEscalation key={'escalation-' + selected.id} report={selected.id}/>
      <CaseBehaviorPanel key={'behavior-' + selected.id} report={selected.id}/>
      <form onSubmit={action}><h3>Record a decision</h3><label>Action<select aria-label="Action" name="action" required
        value={decisionAction} onChange={event=>setDecisionAction(event.currentTarget.value)}>
        <option value="reviewing">Mark in review</option><option value="escalated">Flag for further review</option>
        {selected.message_redaction_available&&<option value="redact_message">Redact reported message</option>}
        <option value="warn">Warn account</option><option value="suspend">Restrict for 24 hours</option>
        <option value="restrict">Restrict for seven days</option><option value="remove">Restrict until restored</option>
        <option value="restore">Lift restriction</option>
        {(selected.report_scope!=='direct'||selected.status==='open'||selected.status==='reviewing')&&<>
          <option value="resolved">Resolve</option><option value="dismissed">Dismiss</option>
        </>}
      </select></label><label>Reason<textarea name="reason" minLength={4} maxLength={500} required rows={3}/></label>
        {selected.report_scope==='direct'&&(decisionAction==='resolved'||decisionAction==='dismissed')&&<>
          <p>The reason stays in the staff audit. The resolution summary goes to the reporter.</p>
          <label>Summary for reporter<textarea name="reporter-summary" minLength={4} maxLength={500} required rows={3}/></label>
        </>}
        <button className="primary" disabled={working}>Record decision</button></form>
      <h3>Audit trail</h3><ol className="audit">{selected.history.map(entry => <li key={entry.id}><strong>{labels[entry.action]}</strong><small><DateLabel value={entry.created_at}/></small>{entry.note && <p>{entry.note}</p>}</li>)}</ol>
    </div> : <>
      <div className="release-flex" role="group" aria-label="Moderation queue filters">
        <label>Report category<select aria-label="Report category" value={category} onChange={event=>{setCategory(event.target.value);setOffset(0)}}>
          <option value="">All categories</option>
          {Object.entries(categories).map(([key, name]) => <option key={key} value={key}>{name}</option>)}
        </select></label>
        <label>Report status<select aria-label="Report status" value={status} onChange={event=>{setStatus(event.target.value);setOffset(0)}}>
          <option value="active">Active reports</option><option value="open">Open</option>
          <option value="reviewing">In review</option><option value="closed">Closed reports</option><option value="any">All reports</option>
        </select></label>
        <label>Deadline<select aria-label="Deadline" value={due} onChange={event=>{setDue(event.target.value);setOffset(0)}}>
          <option value="any">Any deadline</option><option value="overdue">Overdue</option><option value="next_day">Due within 24 hours</option>
        </select></label>
      </div>
      {!rows && !error && <p role="status">Loading moderation queue…</p>}
      {rows?.length === 0 && <div className="list-empty"><ShieldCheck size={24}/><strong>No reports match these filters</strong></div>}
      {rows?.slice(0, 50).map(row => <button disabled={working} className="report-row" key={row.id} onClick={() => void open(row.id)}>
        <Flag size={17}/>
        <div><strong>{categories[row.category]} · @{row.subject_handle}</strong>
          {row.requested_priority && <small>Priority requested</small>}
          <small>{row.next_due ? <>{row.overdue ? 'Overdue · ' : ''}{row.acknowledged_at ? 'Resolve by ' : 'Acknowledge by '}
            <DateLabel value={row.next_due}/></> : <DateLabel value={row.created_at}/>}</small>
        </div>
        <span className={'pill state-' + row.status}>{labels[row.status]}</span><ArrowRight size={15}/>
      </button>)}
      {(offset > 0 || (rows?.length ?? 0) > 50) && <div className="pagination"><button className="secondary" disabled={!offset} onClick={() => setOffset(offset - 50)}><ArrowLeft size={15}/> Previous</button><button className="secondary" disabled={(rows?.length ?? 0) <= 50} onClick={() => setOffset(offset + 50)}>Next <ArrowRight size={15}/></button></div>}
    </>}
  </div>
}
