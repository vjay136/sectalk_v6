'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
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
import { QueueOperations } from './queue-operations'

type Category = keyof typeof categories
type Report = { id: string; category: Category; status: string; created_at: string }
type Queue = Report & { subject_handle: string }
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
  const [view, setView] = useState<'mine' | 'queue' | 'notices' | 'latency' | 'usage' | 'release' | 'feedback' | 'tenants' | 'trends' | 'operations' | 'delivery-queue'>('mine')
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
