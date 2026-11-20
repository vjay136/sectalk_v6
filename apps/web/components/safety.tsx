'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { ArrowLeft, ArrowRight, Flag, Shield, ShieldAlert, ShieldCheck } from 'lucide-react'
import { categories, db, formatError, type Message } from '../lib/data'
import { Dialog } from './inbox'
import { SectionTabs } from './section-tabs'
import { downloadChatFile, type ChatFile } from '../lib/chat-files'
import { DeliveryLatency } from './delivery-latency'
import { UsageMetrics } from './usage-metrics'
import { ReleaseControls } from './release-controls'
import { RiskFeedback } from './risk-feedback'
import { TenantOperations } from './tenant-operations'
import { useAnalyticsStream } from '../lib/live-analytics'
import { ThreatTrends } from './threat-trends'
import { OperationalMetrics } from './operational-metrics'
import { DirectAttachmentHolds, type DirectHoldTarget } from './direct-attachment-holds'
import { AttachmentQuarantine } from './attachment-quarantine'
import { QueueOperations } from './queue-operations'

type Category = keyof typeof categories
type Report = { id: string; category: Category; status: string; created_at: string }
type Queue = Report & { subject_handle: string }
type QueueTimer = Queue & {
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
  attachment?: ChatFile | null
  history: { id: number; action: string; note: string; created_at: string }[]
}
type TimelineItem = { action:string; at:string }
type Notice = { id:number; action:string; until_at:string|null; created_at:string }

const labels: Record<string, string> = {
  open: 'Open', reviewing: 'In review', resolved: 'Resolved', dismissed: 'Dismissed',
  suspend: '24-hour suspension', restore: 'Restriction lifted', viewed: 'Evidence viewed',
  submitted:'Report received', escalated:'Escalated for review', warn:'Account warning issued',
  restrict:'Seven-day restriction', remove:'Indefinite restriction',
  redacted:'Reported message removed',
}

function DateLabel({ value }: { value: string }) {
  return <time dateTime={value}>{new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}</time>
}

export function ReportDialog({ chat, message, file, close, inform }: { chat:string;message:Message|null;file?:ChatFile;close:()=>void;inform:(notice:string)=>void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    const values = new FormData(event.currentTarget)
    setBusy(true)
    setError('')
    const result = await db!.rpc('st_v5_report', { p_chat: chat, p_message: message?.id ?? null, p_category: values.get('category'), p_details: values.get('details'), p_share_file:values.has('share-file') })
    setBusy(false)
    if (result.error) { setError(formatError(result.error, 'Could not submit your report.')); return }
    close()
    inform('Report submitted. Track it in the Safety center.')
  }
  return <Dialog title={message ? 'Report this message' : 'Report this contact'} close={close}><form onSubmit={submit}>
    <p>{message ? 'You’re sharing this message and your notes with SecTalk safety staff.' : 'Your notes will be shared with SecTalk safety staff.'}</p>
    {message && <blockquote>{message.body}</blockquote>}
    {file&&<label className="task-check"><input type="checkbox" name="share-file"/> Share the attached file with safety staff</label>}
    <label>Reason<select name="category" required>{Object.entries(categories).map(([key, name]) => <option key={key} value={key}>{name}</option>)}</select></label>
    <label>Details <span className="muted">(optional)</span><textarea name="details" maxLength={1500} rows={4} placeholder="What happened?" /></label>
    {error && <p className="error" role="alert">{error}</p>}
    <button className="primary" disabled={busy}><Flag size={16}/> Submit report</button>
  </form></Dialog>
}

export function Safety({ staff, refresh }: { staff: string; refresh: () => Promise<void> }) {
  const [reports, setReports] = useState<Report[]>([])
  const [error, setError] = useState('')
  const [view, setView] = useState<'mine' | 'queue' | 'notices' | 'latency' | 'usage' | 'release' | 'feedback' | 'tenants' | 'trends' | 'operations' | 'delivery-queue' | 'holds' | 'quarantine'>('mine')
  const [scanReviewer, setScanReviewer] = useState(false)
  const [holdTargets, setHoldTargets] = useState<DirectHoldTarget[]>([])
  const [flagOperator,setFlagOperator]=useState(false)
  const [tenantStatus,setTenantStatus]=useState<'none' | 'mfa' | 'verified'>('none')
  const [queueStatus,setQueueStatus]=useState<'none' | 'mfa' | 'verified'>('none')
  const [selected,setSelected]=useState<Report|null>(null)
  const [timeline,setTimeline]=useState<TimelineItem[]|null>(null)
  const [notices,setNotices]=useState<Notice[]>([])
  const analyticsRevision = useAnalyticsStream(staff === 'verified')

  const load = useCallback(async () => {
    const [reports,account]=await Promise.all([
      db!.from('st_reports').select('id,category,status,created_at').order('created_at', { ascending: false }).limit(100),
      db!.from('st_v5_account_notices').select('id,action,until_at,created_at').order('id',{ascending:false}).limit(100),
    ])
    if(reports.error||account.error) setError('Could not load the Safety center.')
    else{setError('');setReports(reports.data as Report[]);setNotices(account.data)}
  }, [])
  useEffect(() => {
    void load()
    const timer=window.setInterval(load,15000)
    return ()=>window.clearInterval(timer)
  }, [load, view])
  useEffect(()=>{
    if(!selected)return
    let live=true
    const refreshTimeline=async()=>{
      const {data,error}=await db!.rpc('st_v5_report_timeline',{p_report:selected.id})
      if(!live)return
      if(error)setError('Could not load the report timeline.')
      else setTimeline(data as TimelineItem[])
    }
    void refreshTimeline()
    const timer=window.setInterval(refreshTimeline,10000)
    return ()=>{live=false;window.clearInterval(timer)}
  },[selected])
  const staffAccess=staff==='mfa'||staff==='verified'
  useEffect(()=>{
    if(staff!=='verified'){setFlagOperator(false);return}
    let active=true
    void db!.rpc('st_v6_can_manage_flags').then(result=>{if(active)setFlagOperator(!result.error&&result.data===true)})
    return()=>{active=false}
  },[staff])
  const releaseAccess=staff==='verified'&&flagOperator
  useEffect(() => {
    if (staff !== 'verified') { setScanReviewer(false); return }
    let active = true
    void db!.rpc('st_v6_is_attachment_scan_reviewer').then(({data,error}) => {
      if (active) setScanReviewer(!error && data === true)
    })
    return () => { active = false }
  }, [staff])
  const scanAccess = staff === 'verified' && scanReviewer
  useEffect(() => {
    if (staff !== 'verified') { setHoldTargets([]); return }
    let active = true
    const load = async () => {
      const { data, error } = await db!.rpc('st_v6_direct_hold_targets')
      if (active) setHoldTargets(error ? [] : data as DirectHoldTarget[])
    }
    void load()
    const timer = window.setInterval(load, 30000)
    return () => { active = false; window.clearInterval(timer) }
  }, [staff])
  const holdAccess = staff === 'verified' && holdTargets.length > 0
  const refreshTenantStatus = useCallback(async (isCurrent: () => boolean = () => true) => {
    const { data, error } = await db!.rpc('st_v6_tenant_operations_status')
    if (isCurrent()) setTenantStatus(!error && (data === 'mfa' || data === 'verified') ? data : 'none')
  }, [])
  useEffect(() => {
    let current = true
    const update = () => void refreshTenantStatus(() => current)
    update()
    const timer = window.setInterval(update, 15000)
    return () => { current = false; window.clearInterval(timer) }
  }, [refreshTenantStatus])
  const refreshQueueStatus = useCallback(async (isCurrent: () => boolean = () => true) => {
    const { data, error } = await db!.rpc('st_v6_queue_operations_status')
    if (isCurrent()) setQueueStatus(!error && (data === 'mfa' || data === 'verified') ? data : 'none')
  }, [])
  useEffect(() => {
    if (!staffAccess) return
    let current = true
    const update = () => void refreshQueueStatus(() => current)
    update()
    const timer = window.setInterval(update, 15000)
    return () => { current = false; window.clearInterval(timer) }
  }, [refreshQueueStatus, staffAccess])
  const queueAccess = staffAccess ? queueStatus : 'none'
  const visibleView=((view==='latency'||view==='usage'||view==='feedback'||view==='trends'||view==='operations')&&staff!=='verified')||(view==='queue'&&!staffAccess)
    ||(view==='release'&&!releaseAccess)||(view==='tenants'&&tenantStatus==='none')||(view==='delivery-queue'&&queueAccess==='none')
    ||(view==='holds'&&!holdAccess)||(view==='quarantine'&&!scanAccess)?'mine':view

  return <section className="content-page safety-page">
    <header className="content-title"><div className="card-icon"><Shield size={23}/></div><div><h1>Safety center</h1><p>Review your reports and manage safety concerns.</p></div></header>
    <SectionTabs label="Safety center sections" value={visibleView} onChange={next=>{setView(next);setSelected(null);setError('')}} options={[
      ['mine','My reports'],['notices','Account notices'],...(staffAccess?[['queue','Staff console'] as const]:[]),
      ...(staff==='verified'?[['latency','Delivery metrics'] as const,['usage','Usage metrics'] as const,
        ['feedback','Warning feedback'] as const,['trends','Threat trends'] as const,['operations','Operational metrics'] as const]:[]),
      ...(releaseAccess?[['release','Release controls'] as const]:[]),
      ...(tenantStatus!=='none'?[['tenants','Tenant operations'] as const]:[]),
      ...(holdAccess?[['holds','Attachment holds'] as const]:[]),
      ...(scanAccess?[['quarantine','Attachment quarantine'] as const]:[]),
      ...(queueAccess!=='none'?[['delivery-queue','Queue operations'] as const]:[]),
    ]}/>
    {visibleView==='latency'?<DeliveryLatency revision={analyticsRevision}/>:visibleView==='usage'?<UsageMetrics revision={analyticsRevision}/>:visibleView==='release'?<ReleaseControls/>:
      visibleView==='feedback'?<RiskFeedback/>:
      visibleView==='trends'?<ThreatTrends/>:
      visibleView==='operations'?<OperationalMetrics/>:
      visibleView==='holds'?<DirectAttachmentHolds targets={holdTargets}/>:
      visibleView==='quarantine'?<AttachmentQuarantine/>:
      visibleView==='delivery-queue' ? (queueAccess === 'verified'
        ? <QueueOperations onAccessChanged={refreshQueueStatus}/>
        : <StaffMfa refresh={async () => { await refreshQueueStatus(); await refresh() }}
          explanation="Enter a current authenticator code to inspect or replay failed notification deliveries."/>) :
      visibleView==='tenants' ? (tenantStatus === 'verified'
        ? <TenantOperations onAccessChanged={refreshTenantStatus}/>
        : <StaffMfa refresh={async () => { await refreshTenantStatus(); await refresh() }}
          explanation="An authenticator code is required to view workspace metadata."/>) :
      visibleView==='queue' ? (staff === 'verified' ? <QueuePanel /> : <StaffMfa refresh={refresh}/>) :
      visibleView==='notices'?<div className="panel release-panel"><h2>Account notices</h2>
        {error&&<p role="alert" className="error">{error}</p>}
        {!notices.length&&<p>No account notices.</p>}
        {notices.map(notice=><div className="release-board-item" key={notice.id}><strong>{labels[notice.action]}</strong><p><DateLabel value={notice.created_at}/></p>
          {notice.until_at&&notice.until_at!=='infinity'&&<p>Restriction ends <DateLabel value={notice.until_at}/></p>}
          {notice.until_at==='infinity'&&<p>Messaging and calls are restricted until staff restore access.</p>}
        </div>)}
      </div> :
      selected?<div className="panel release-panel"><div className="panel-header"><h2>Report timeline</h2>
        <button className="secondary" onClick={()=>{setSelected(null);setTimeline(null);setError('')}}>Back to reports</button></div>
        <p>{categories[selected.category]} · {labels[reports.find(row=>row.id===selected.id)?.status||selected.status]}</p>
        {error&&<p role="alert" className="error">{error}</p>}
        {!timeline&&!error&&<p role="status">Loading your timeline…</p>}
        <ol className="audit">{timeline?.map((item,index)=><li key={item.at+item.action+index}>
          <strong>{labels[item.action]}</strong><small><DateLabel value={item.at}/></small>
        </li>)}</ol>
      </div> :
      <div className="panel"><div className="panel-header"><h2>My reports</h2><button className="secondary" onClick={load}>Refresh</button></div>
        {error && <p role="alert" className="error">{error}</p>}
        {!error && !reports.length && <div className="list-empty"><ShieldCheck size={24}/><strong>No reports yet</strong><p>Use the flag in a conversation to submit a report.</p></div>}
        {reports.map(row => <button type="button" className="report-row" key={row.id} onClick={()=>{setTimeline(null);setSelected(row)}}>
          <Flag size={17}/><span><strong>{categories[row.category]}</strong><small><DateLabel value={row.created_at} /></small></span>
          <span className={'pill state-' + row.status}>{labels[row.status]}</span><ArrowRight size={15}/>
        </button>)}
      </div>}
  </section>
}

function StaffMfa({ refresh, explanation = 'An authenticator code is required to review reports or change account restrictions.' }:
  { refresh: () => Promise<void>; explanation?: string }) {
  const [setup, setSetup] = useState<{ id: string; qr_code: string; secret: string } | null>(null)
  const [factor, setFactor] = useState('')
  const [loaded, setLoaded] = useState(false)
  const [pendingFactors, setPendingFactors] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => {
    void db!.auth.mfa.listFactors().then(({ data, error }) => {
      if (error) setError('Could not read your MFA settings.')
      else {
        setFactor(data.totp.find(item => item.status === 'verified')?.id || '')
        setPendingFactors(data.all.filter(item => item.factor_type === 'totp' && item.status === 'unverified').map(item => item.id))
        setLoaded(true)
      }
    })
  }, [])

  async function enroll() {
    setBusy(true)
    setError('')
    for (const id of pendingFactors) {
      const { error } = await db!.auth.mfa.unenroll({ factorId: id })
      if (error) { setError('Could not reset the unfinished authenticator setup.'); setBusy(false); return }
    }
    setPendingFactors([])
    const { data, error } = await db!.auth.mfa.enroll({ factorType: 'totp', issuer: 'SecTalk', friendlyName: 'SecTalk Staff' })
    if (error) setError('Could not enroll your authenticator.')
    else { setSetup({ id: data.id, ...data.totp }); setFactor(data.id) }
    setBusy(false)
  }

  async function verify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setError('')
    const code = String(new FormData(event.currentTarget).get('code'))
    const { error } = await db!.auth.mfa.challengeAndVerify({ factorId: factor, code })
    if (error) setError('The authenticator code is invalid or expired.')
    else await refresh()
    setBusy(false)
  }

  return <div className="panel mfa-panel"><div className="card-icon"><ShieldCheck size={22}/></div><h2>Verify staff access</h2><p>{explanation}</p>
    {setup && <div className="mfa-setup"><img src={setup.qr_code} alt="Scan with your authenticator app" width={180} height={180}/><p>Manual setup key</p><code>{setup.secret}</code></div>}
    {factor ? <form onSubmit={verify}><label>Authenticator code<input name="code" type="text" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required /></label><button className="primary" disabled={busy}>Verify access <ArrowRight size={16}/></button></form> :
      <button className="primary" disabled={busy || !loaded} onClick={enroll}>Set up authenticator</button>}
    {error && <p className="error" role="alert">{error}</p>}
  </div>
}

function QueuePanel() {
  const [rows, setRows] = useState<QueueTimer[] | null>(null)
  const [selected, setSelected] = useState<Case | null>(null)
  const [offset, setOffset] = useState(0)
  const [category, setCategory] = useState('')
  const [status, setStatus] = useState('active')
  const [due, setDue] = useState('any')
  const [error, setError] = useState('')
  const [working, setWorking] = useState(false)
  const queueVersion = useRef(0)

  const load = useCallback(async () => {
    const version = ++queueVersion.current
    const { data, error } = await db!.rpc('st_v6_abuse_queue', {
      p_category: category || null, p_status: status, p_due: due, p_offset: offset,
    })
    if (version !== queueVersion.current) return
    if (error) { setRows(null); setError('Could not load the moderation queue.') }
    else { setError(''); setRows(data as QueueTimer[]) }
  }, [category, status, due, offset])
  useEffect(() => {
    if (selected) return
    void load()
    const timer = window.setInterval(() => { if (document.visibilityState === 'visible') void load() }, 15000)
    return () => { ++queueVersion.current; window.clearInterval(timer) }
  }, [load, selected])
  const timer = selected && rows?.find(row => row.id === selected.id)

  async function open(id: string) {
    setWorking(true)
    setError('')
    const { data, error } = await db!.rpc('st_v5_case', { p_report: id })
    if (error) setError(formatError(error, 'Could not load case.'))
    else setSelected(data as Case)
    setWorking(false)
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
    const { error } = decision==='redact_message'
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
      {selected.attachment&&<button type="button" className="secondary" onClick={async()=>{
        if(!selected.attachment)return
        try{await downloadChatFile(selected.attachment)}catch{setError('Evidence attachment could not be downloaded.')}
      }}>Download shared file</button>}
      <form onSubmit={action}><h3>Record a decision</h3><label>Action<select name="action" required defaultValue="reviewing">
        <option value="reviewing">Mark in review</option><option value="escalated">Escalate for review</option>
        {selected.message_redaction_available&&<option value="redact_message">Redact reported message</option>}
        <option value="warn">Warn account</option><option value="suspend">Restrict for 24 hours</option>
        <option value="restrict">Restrict for seven days</option><option value="remove">Restrict until restored</option>
        <option value="restore">Lift restriction</option><option value="resolved">Resolve</option><option value="dismissed">Dismiss</option>
      </select></label><label>Reason<textarea name="reason" minLength={4} maxLength={500} required rows={3}/></label><button className="primary" disabled={working}>Record decision</button></form>
      <h3>Audit trail</h3><ol className="audit">{selected.history.map(entry => <li key={entry.id}><strong>{labels[entry.action]}</strong><small><DateLabel value={entry.created_at}/></small>{entry.note && <p>{entry.note}</p>}</li>)}</ol>
    </div> : <>
      <div className="release-flex" role="group" aria-label="Moderation queue filters">
        <label>Report category<select value={category} onChange={event=>{setCategory(event.target.value);setOffset(0)}}>
          <option value="">All categories</option>
          {Object.entries(categories).map(([key, name]) => <option key={key} value={key}>{name}</option>)}
        </select></label>
        <label>Report status<select value={status} onChange={event=>{setStatus(event.target.value);setOffset(0)}}>
          <option value="active">Active reports</option><option value="open">Open</option>
          <option value="reviewing">In review</option><option value="closed">Closed reports</option><option value="any">All reports</option>
        </select></label>
        <label>Deadline<select value={due} onChange={event=>{setDue(event.target.value);setOffset(0)}}>
          <option value="any">Any deadline</option><option value="overdue">Overdue</option><option value="next_day">Due within 24 hours</option>
        </select></label>
      </div>
      {!rows && !error && <p role="status">Loading moderation queue…</p>}
      {rows?.length === 0 && <div className="list-empty"><ShieldCheck size={24}/><strong>No reports match these filters</strong></div>}
      {rows?.slice(0, 50).map(row => <button disabled={working} className="report-row" key={row.id} onClick={() => void open(row.id)}>
        <Flag size={17}/>
        <div><strong>{categories[row.category]} · @{row.subject_handle}</strong>
          <small>{row.next_due ? <>{row.overdue ? 'Overdue · ' : ''}{row.acknowledged_at ? 'Resolve by ' : 'Acknowledge by '}
            <DateLabel value={row.next_due}/></> : <DateLabel value={row.created_at}/>}</small>
        </div>
        <span className={'pill state-' + row.status}>{labels[row.status]}</span><ArrowRight size={15}/>
      </button>)}
      {(offset > 0 || (rows?.length ?? 0) > 50) && <div className="pagination"><button className="secondary" disabled={!offset} onClick={() => setOffset(offset - 50)}><ArrowLeft size={15}/> Previous</button><button className="secondary" disabled={(rows?.length ?? 0) <= 50} onClick={() => setOffset(offset + 50)}>Next <ArrowRight size={15}/></button></div>}
    </>}
  </div>
}
