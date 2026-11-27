'use client'

import { messageSafetyAction } from '../lib/message-safety-action.mjs'
import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { ArrowRight, Flag, Shield } from 'lucide-react'
import { categories, db, formatError, type Message } from '../lib/data'
import { Dialog } from './inbox'
import { SectionTabs } from './section-tabs'
import { type ChatFile } from '../lib/chat-files'
import { DeliveryLatency } from './delivery-latency'
import { UsageMetrics } from './usage-metrics'
import { ReleaseControls } from './release-controls'
import { RiskFeedback } from './risk-feedback'
import { TenantOperations } from './tenant-operations'
import { AccountAdministration, useAccountOperator } from './account-administration'
import { GlobalAbuseBlocklists, useAbuseBlocklistAccess } from './global-abuse-blocklists'
import { DetectionRules, useDetectionRuleAccess } from './detection-rules'
import { ThreatTriage, useThreatTriageAccess } from './threat-triage'
import { useAnalyticsStream } from '../lib/live-analytics'
import { ThreatTrends } from './threat-trends'
import { OperationalMetrics } from './operational-metrics'
import { DirectAttachmentHolds, type DirectHoldTarget } from './direct-attachment-holds'
import { AttachmentQuarantine } from './attachment-quarantine'
import { QueueOperations } from './queue-operations'
import { SecurityIncidents } from './security-incidents'
import { SecurityCenterOverview } from './security-center-overview'
import { MyRoomReports, RoomReportQueue } from './room-reports'
import { ChannelReportQueue, MyChannelReports } from './channel-reports'
import { StaffMfa } from './staff-mfa'
import { EmergencyNotices } from './emergency-notices'
import { UrlInspection } from './url-inspection'
import { DisclosureQueue,useDisclosureAccess } from './disclosure-queue'
import { ModerationQueue, DateLabel, labels, type Report } from './moderation-queue'
import { isReportTicket, ReportTicket } from './report-ticket'

type TimelineItem = { action:string; at:string; summary:string|null }
type Notice = { id:number; action:string; until_at:string|null; created_at:string }

export function ReportDialog({ chat, message, file, close, inform }: { chat:string;message:Message|null;file?:ChatFile;close:()=>void;inform:(notice:string)=>void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const eligiblePriority = Boolean(message && !message.expires_at && messageSafetyAction(message.body).priority)
  const [category, setCategory] = useState(eligiblePriority ? 'threat' : 'harassment')
  const priorityAllowed = eligiblePriority && (category === 'threat' || category === 'sexual_content')
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    const values = new FormData(event.currentTarget)
    setBusy(true)
    setError('')
    const payload = { p_chat: chat, p_message: message?.expires_at ? null : message?.id ?? null,
      p_category: values.get('category'), p_details: values.get('details'), p_share_file: values.has('share-file') }
    const requested = priorityAllowed && values.has('priority-review')
    const result = requested ? await db!.rpc('st_v7_request_priority_message_review', {
      ...payload, p_revision: message?.edited_at || message?.created_at,
    }) : await db!.rpc('st_v5_report', payload)
    setBusy(false)
    if (result.error || !isReportTicket(result.data)) { setError(formatError(result.error, 'Could not confirm your report submission.')); return }
    close()
    inform(`${requested ? 'Priority review requested.' : 'Report submitted.'} Ticket ${result.data}. Track it in Safety under My reports.`)
  }
  return <Dialog title={message ? 'Report this message' : 'Report this contact'} close={close}><form onSubmit={submit}>
    <p>{message && !message.expires_at ? 'You’re sharing this message and your notes with SecTalk safety staff.' : 'Your notes will be shared with SecTalk safety staff.'}</p>
    {message && !message.expires_at && <blockquote>{message.body}</blockquote>}
    {file&&<label className="task-check"><input type="checkbox" name="share-file"/> Share the attached file with safety staff</label>}
    <label>Report category<select name="category" aria-label="Report category" required value={category}
      onChange={event=>setCategory(event.target.value)}>{Object.entries(categories).map(([key, name]) => <option key={key} value={key}>{name}</option>)}</select></label>
    {priorityAllowed && <label className="task-check"><input type="checkbox" name="priority-review" />
      Request urgent human review</label>}
    <label>Details <span className="muted">(optional)</span><textarea name="details" maxLength={1500} rows={4} placeholder="What happened?" /></label>
    {error && <p className="error" role="alert">{error}</p>}
    <button className="primary" disabled={busy}><Flag size={16}/> Submit report</button>
  </form></Dialog>
}

export function Safety({ staff, refresh, hints }: { staff: string; refresh: () => Promise<void>; hints: EventTarget }) {
  const [reports, setReports] = useState<Report[]>([])
  const [reportScope,setReportScope] = useState<'all'|'chat'|'room'|'channel'>('all')
  const [ticketQuery,setTicketQuery] = useState('')
  const normalizedTicketQuery=ticketQuery.trim().toLowerCase().replace(/^ticket\s+/,'')
  const matchingReports=reports.filter(row=>row.id.includes(normalizedTicketQuery))
  const [error, setError] = useState('')
  const [view, setView] = useState<'mine' | 'queue' | 'notices' | 'latency' | 'usage' | 'release' | 'feedback' | 'tenants' | 'trends' | 'operations' | 'delivery-queue' | 'holds' | 'quarantine' | 'incidents' | 'overview' | 'workspace-reports' | 'account-admin' | 'abuse-blocklists' | 'detection-rules' | 'url-inspection' | 'threat-triage' | 'disclosures'>('mine')
  const disclosureAccess=useDisclosureAccess()
  const threatTriage = useThreatTriageAccess()
  const detectionRules = useDetectionRuleAccess()
  const accountOperator = useAccountOperator()
  const abuseBlocks = useAbuseBlocklistAccess()
  const [roomReviewAccess,setRoomReviewAccess]=useState('none')
  const [incidentRole, setIncidentRole] = useState('none')
  const [incidentReport, setIncidentReport] = useState<string | null>(null)
  const [scanReviewer, setScanReviewer] = useState(false)
  const [holdTargets, setHoldTargets] = useState<DirectHoldTarget[]>([])
  const [flagOperator,setFlagOperator]=useState(false)
  const [tenantStatus,setTenantStatus]=useState<'none' | 'mfa' | 'verified'>('none')
  const [queueStatus,setQueueStatus]=useState<'none' | 'mfa' | 'verified'>('none')
  const [selected,setSelected]=useState<Report|null>(null)
  const [timeline,setTimeline]=useState<TimelineItem[]|null>(null)
  const [timelineError,setTimelineError]=useState('')
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
      const {data,error}=await db!.rpc('st_v8_my_message_report_timeline',{p_report:selected.id})
      if(!live)return
      if(error)setTimelineError('Could not load the report timeline.')
      else {setTimeline((data as TimelineItem[]).slice().reverse());setTimelineError('')}
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
  useEffect(() => {
    if (staff !== 'verified') { setIncidentRole('none'); setIncidentReport(null); return }
    let active = true
    const update = async () => {
      const { data, error } = await db!.rpc('st_v6_incident_access')
      if (active) setIncidentRole(!error && (data === 'lead' || data === 'responder') ? data : 'none')
    }
    void update()
    const timer = window.setInterval(update, 15000)
    return () => { active = false; window.clearInterval(timer) }
  }, [staff])
  const incidentAccess = staff === 'verified' && incidentRole !== 'none'
  const loadRoomReviewAccess = useCallback(async () => {
    const {data,error}=await db!.rpc('st_v6_room_report_review_access')
    setRoomReviewAccess(error ? 'none' : data)
  }, [])
  useEffect(() => { void loadRoomReviewAccess() }, [loadRoomReviewAccess,staff])
  const visibleView=((view==='overview'||view==='latency'||view==='usage'||view==='feedback'||view==='trends'||view==='operations')&&staff!=='verified')||(view==='queue'&&!staffAccess)
    ||(view==='release'&&!releaseAccess)||(view==='tenants'&&tenantStatus==='none')||(view==='delivery-queue'&&queueAccess==='none')
    ||(view==='holds'&&!holdAccess)||(view==='quarantine'&&!scanAccess)||(view==='incidents'&&!incidentAccess)
    ||(view==='workspace-reports'&&roomReviewAccess==='none')||(view==='account-admin'&&accountOperator.access==='none')
    ||(view==='abuse-blocklists'&&abuseBlocks.access==='none')
    ||(view==='detection-rules'&&detectionRules.access==='none')
    ||(view==='threat-triage'&&threatTriage.access.status==='none')
    ||(view==='disclosures'&&disclosureAccess.access==='none')?'mine':view

  return <section className="content-page safety-page">
    <header className="content-title"><div className="card-icon"><Shield size={23}/></div><div><h1>Safety center</h1><p>Track reports, inspect links, and review notices.</p></div></header>
    <SectionTabs label="Safety center sections" value={visibleView} onChange={next=>{setView(next);setSelected(null);setError('')}} options={[
      ...(staff==='verified'?[['overview','Security overview'] as const]:[]),
      ['mine','My reports'],['url-inspection','URL inspection'],['notices','Account notices'],...(staffAccess?[['queue','Staff console'] as const]:[]),
      ...(roomReviewAccess!=='none'?[['workspace-reports','Workspace report review'] as const]:[]),
      ...(staff==='verified'?[['latency','Delivery metrics'] as const,['usage','Usage metrics'] as const,
        ['feedback','Warning feedback'] as const,['trends','Threat trends'] as const,['operations','Operational metrics'] as const]:[]),
      ...(releaseAccess?[['release','Release controls'] as const]:[]),
      ...(tenantStatus!=='none'?[['tenants','Tenant operations'] as const]:[]),
      ...(accountOperator.access !== 'none' ? [['account-admin','Account administration'] as const] : []),
      ...(abuseBlocks.access !== 'none' ? [['abuse-blocklists','Global abuse blocklists'] as const] : []),
      ...(detectionRules.access !== 'none' ? [['detection-rules','Detection rules'] as const] : []),
      ...(threatTriage.access.status !== 'none' ? [['threat-triage','Threat triage'] as const] : []),
      ...(holdAccess?[['holds','Attachment holds'] as const]:[]),
      ...(scanAccess?[['quarantine','Attachment quarantine'] as const]:[]),
      ...(queueAccess!=='none'?[['delivery-queue','Queue operations'] as const]:[]),
      ...(incidentAccess?[['incidents','Incidents'] as const]:[]),
      ...(disclosureAccess.access!=='none'?[['disclosures','Vulnerability disclosures'] as const]:[]),
    ]}/>
    {visibleView==='disclosures'?<DisclosureQueue {...disclosureAccess}/>:
      visibleView==='url-inspection'?<UrlInspection/>:
      visibleView==='overview'?<SecurityCenterOverview/>:
      visibleView==='latency'?<DeliveryLatency revision={analyticsRevision}/>:visibleView==='usage'?<UsageMetrics revision={analyticsRevision}/>:visibleView==='release'?<ReleaseControls/>:
      visibleView==='feedback'?<RiskFeedback/>:
      visibleView==='trends'?<ThreatTrends/>:
      visibleView==='operations'?<OperationalMetrics/>:
      visibleView==='account-admin'?<AccountAdministration {...accountOperator}/>:
      visibleView==='abuse-blocklists'?<GlobalAbuseBlocklists {...abuseBlocks}/>:
      visibleView==='detection-rules'?<DetectionRules {...detectionRules}/>:
      visibleView==='threat-triage'?<ThreatTriage {...threatTriage}/>:
      visibleView==='holds'?<DirectAttachmentHolds targets={holdTargets}/>:
      visibleView==='quarantine'?<AttachmentQuarantine/>:
      visibleView==='incidents'?<SecurityIncidents report={incidentReport} onLinked={()=>setIncidentReport(null)}/>:
      visibleView==='delivery-queue' ? (queueAccess === 'verified'
        ? <QueueOperations onAccessChanged={refreshQueueStatus}/>
        : <StaffMfa refresh={async () => { await refreshQueueStatus(); await refresh() }}
          explanation="Enter a current authenticator code to inspect or replay failed notification deliveries."/>) :
      visibleView==='tenants' ? (tenantStatus === 'verified'
        ? <TenantOperations onAccessChanged={refreshTenantStatus}/>
        : <StaffMfa refresh={async () => { await refreshTenantStatus(); await refresh() }}
          explanation="An authenticator code is required to view workspace metadata."/>) :
      visibleView==='workspace-reports' ? (roomReviewAccess==='verified' ? <><RoomReportQueue scope="workspace"/><ChannelReportQueue scope="workspace"/></> :
        <StaffMfa refresh={loadRoomReviewAccess} explanation="Enter a current authenticator code to review eligible workspace reports."/>) :
      visibleView==='queue' ? (staff === 'verified' ? <><ModerationQueue linkIncident={incidentAccess ? reportId => {
        setIncidentReport(reportId);setView('incidents')
      } : undefined} /><RoomReportQueue scope="platform"/><ChannelReportQueue scope="platform"/></> : <StaffMfa refresh={refresh}/>) :
      visibleView==='notices'?<div className="panel release-panel"><h2>Account notices</h2>
        {error&&<p role="alert" className="error">{error}</p>}
        {!notices.length&&<p>No account restriction notices.</p>}
        {notices.map(notice=><div className="release-board-item" key={notice.id}><strong>{labels[notice.action]}</strong><p><DateLabel value={notice.created_at}/></p>
          {notice.until_at&&notice.until_at!=='infinity'&&<p>Restriction ends <DateLabel value={notice.until_at}/></p>}
          {notice.until_at==='infinity'&&<p>Messaging and calls are restricted until staff restore access.</p>}
        </div>)}
        <EmergencyNotices hints={hints}/>
      </div> :
      selected?<div className="panel release-panel"><div className="panel-header"><h2>Report timeline</h2>
        <button className="secondary" onClick={()=>{setSelected(null);setTimeline(null);setTimelineError('')}}>Back to reports</button></div>
        <p><ReportTicket id={selected.id}/></p>
        <p>{categories[selected.category]} · <strong>{labels[reports.find(row=>row.id===selected.id)?.status||selected.status]}</strong></p>
        {timelineError&&<p role="alert" className="error">{timelineError}</p>}
        {!timeline&&!timelineError&&<p role="status">Loading your timeline…</p>}
        <ol className="audit">{timeline?.map((item,index)=><li key={item.at+item.action+index}>
          <strong>{labels[item.action]??'Report updated'}</strong><small><DateLabel value={item.at}/></small>
          {item.summary&&<p><strong>Response from SecTalk Safety</strong> {item.summary}</p>}
        </li>)}</ol>
      </div> :
      <div className="panel personal-reports-panel"><div className="panel-header"><h2>My reports</h2><button className="secondary" onClick={()=>{
        void load();hints.dispatchEvent(new Event('personal_reports_refresh'))
      }}>Refresh</button></div>
        <div className="release-section report-filters">
          <SectionTabs label="My report scopes" value={reportScope} onChange={setReportScope}
            options={([['all','All'],['chat','Chat'],['room','Room'],['channel','Channel']] as const)
              .map(([id,label])=>[id,<>{label}<span className="visually-hidden"> reports</span></>])}/>
          <label>Filter recent reports by ticket number<input type="search" value={ticketQuery} maxLength={64}
            onChange={event=>setTicketQuery(event.target.value)} placeholder="Enter a ticket number"/></label>
        </div>
        {error && <p role="alert" className="error">{error}</p>}
        {(reportScope==='all'||reportScope==='chat')&&<section className="release-section" aria-label="My chat reports">
          <h3>My chat reports</h3>
          {!error && matchingReports.length===0 &&
            <p className="report-empty muted">{normalizedTicketQuery ? 'No matching chat reports.' : 'No chat reports yet. Use the flag in a conversation to submit one.'}</p>}
          {matchingReports.map(row =>
            <button type="button" className="report-row" key={row.id} onClick={()=>{setTimeline(null);setTimelineError('');setSelected(row)}}>
              <Flag size={17}/><span style={{flex:1,minWidth:0}}><strong>{categories[row.category]}</strong>
                <small><DateLabel value={row.created_at}/></small>
                <ReportTicket id={row.id}/></span>
              <span className={'pill state-' + row.status}>{labels[row.status]}</span><ArrowRight size={15}/>
            </button>)}
        </section>}
        {(reportScope==='all'||reportScope==='room')&&<MyRoomReports hints={hints} ticketQuery={normalizedTicketQuery} showRefresh={reportScope==='room'}/>}
        {(reportScope==='all'||reportScope==='channel')&&<MyChannelReports hints={hints} ticketQuery={normalizedTicketQuery}/>}
      </div>}
  </section>
}
