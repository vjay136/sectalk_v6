'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { ArrowLeft, ArrowRight, Flag, Shield, ShieldAlert, ShieldCheck } from 'lucide-react'
import { categories, db, formatError, type Message } from '../lib/data'
import { Dialog } from './inbox'

type Category = keyof typeof categories
type Report = { id: string; category: Category; status: string; created_at: string }
type Queue = Report & { subject_handle: string }
type Case = Queue & {
  details: string; evidence: string | null; suspended_until: string | null
  history: { id: number; action: string; note: string; created_at: string }[]
}

const labels: Record<string, string> = {
  open: 'Open', reviewing: 'In review', resolved: 'Resolved', dismissed: 'Dismissed',
  suspend: '24-hour suspension', restore: 'Restriction lifted', viewed: 'Evidence viewed',
}

function DateLabel({ value }: { value: string }) {
  return <time dateTime={value}>{new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}</time>
}

export function ReportDialog({ chat, message, close, inform }: { chat: string; message: Message | null; close: () => void; inform: (notice: string) => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    const values = new FormData(event.currentTarget)
    setBusy(true)
    setError('')
    const result = await db!.rpc('st_report', { p_chat: chat, p_message: message?.id ?? null, p_category: values.get('category'), p_details: values.get('details') })
    setBusy(false)
    if (result.error) { setError(formatError(result.error, 'Could not submit your report.')); return }
    close()
    inform('Report submitted. Track it in the Safety center.')
  }
  return <Dialog title={message ? 'Report this message' : 'Report this contact'} close={close}><form onSubmit={submit}>
    <p>{message ? 'You’re sharing this message and your notes with SecTalk safety staff.' : 'Your notes will be shared with SecTalk safety staff.'}</p>
    {message && <blockquote>{message.body}</blockquote>}
    <label>Reason<select name="category" required>{Object.entries(categories).map(([key, name]) => <option key={key} value={key}>{name}</option>)}</select></label>
    <label>Details <span className="muted">(optional)</span><textarea name="details" maxLength={1500} rows={4} placeholder="What happened?" /></label>
    {error && <p className="error" role="alert">{error}</p>}
    <button className="primary" disabled={busy}><Flag size={16}/> Submit report</button>
  </form></Dialog>
}

export function Safety({ staff, refresh }: { staff: string; refresh: () => Promise<void> }) {
  const [reports, setReports] = useState<Report[]>([])
  const [error, setError] = useState('')
  const [view, setView] = useState<'mine' | 'queue'>('mine')

  const load = useCallback(async () => {
    const { data, error } = await db!.from('st_reports').select('id,category,status,created_at').order('created_at', { ascending: false }).limit(100)
    if (error) setError('Could not load your reports.')
    else { setError(''); setReports(data as Report[]) }
  }, [])
  useEffect(() => { void load() }, [load, view])

  return <section className="content-page safety-page">
    <header className="content-title"><div className="card-icon"><Shield size={23}/></div><div><h1>Safety center</h1><p>Review your reports and manage safety concerns.</p></div></header>
    {staff !== 'none' && <div className="tabs content-tabs"><button className={view === 'mine' ? 'active' : ''} onClick={() => setView('mine')}>My reports</button><button className={view === 'queue' ? 'active' : ''} onClick={() => setView('queue')}>Staff console</button></div>}
    {view === 'queue' && staff !== 'none' ? (staff === 'verified' ? <QueuePanel /> : <StaffMfa refresh={refresh}/>) :
      <div className="panel"><div className="panel-header"><h2>My reports</h2><button className="secondary" onClick={load}>Refresh</button></div>
        {error && <p role="alert" className="error">{error}</p>}
        {!error && !reports.length && <div className="list-empty"><ShieldCheck size={24}/><strong>No reports yet</strong><p>Use the flag in a conversation to submit a report.</p></div>}
        {reports.map(row => <div className="report-row" key={row.id}><Flag size={17}/><div><strong>{categories[row.category]}</strong><small><DateLabel value={row.created_at} /></small></div><span className={'pill state-' + row.status}>{labels[row.status]}</span></div>)}
      </div>}
  </section>
}

function StaffMfa({ refresh }: { refresh: () => Promise<void> }) {
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

  return <div className="panel mfa-panel"><div className="card-icon"><ShieldCheck size={22}/></div><h2>Verify staff access</h2><p>An authenticator code is required to review reports or change account restrictions.</p>
    {setup && <div className="mfa-setup"><img src={setup.qr_code} alt="Scan with your authenticator app" width={180} height={180}/><p>Manual setup key</p><code>{setup.secret}</code></div>}
    {factor ? <form onSubmit={verify}><label>Authenticator code<input name="code" type="text" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required /></label><button className="primary" disabled={busy}>Verify access <ArrowRight size={16}/></button></form> :
      <button className="primary" disabled={busy || !loaded} onClick={enroll}>Set up authenticator</button>}
    {error && <p className="error" role="alert">{error}</p>}
  </div>
}

function QueuePanel() {
  const [rows, setRows] = useState<Queue[]>([])
  const [selected, setSelected] = useState<Case | null>(null)
  const [offset, setOffset] = useState(0)
  const [error, setError] = useState('')
  const [working, setWorking] = useState(false)

  const load = useCallback(async () => {
    const { data, error } = await db!.rpc('st_queue', { p_offset: offset })
    if (error) setError('Could not load the moderation queue.')
    else { setError(''); setRows(data as Queue[]) }
  }, [offset])
  useEffect(() => { void load() }, [load])

  async function open(id: string) {
    setWorking(true)
    setError('')
    const { data, error } = await db!.rpc('st_case', { p_report: id })
    if (error) setError(formatError(error, 'Could not load case.'))
    else setSelected(data as Case)
    setWorking(false)
  }

  async function action(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!selected || working) return
    const form = event.currentTarget
    const values = new FormData(form)
    setWorking(true)
    setError('')
    const { error } = await db!.rpc('st_moderate', { p_report: selected.id, p_action: values.get('action'), p_note: values.get('reason') })
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
      {selected.suspended_until && new Date(selected.suspended_until) > new Date() && <p className="warning">Restricted until <DateLabel value={selected.suspended_until}/></p>}
      <h3>Reporter notes</h3><p className="case-text">{selected.details || 'No notes provided.'}</p>
      <h3>Shared evidence</h3>{selected.evidence ? <blockquote>{selected.evidence}</blockquote> : <p>No message was attached.</p>}
      <form onSubmit={action}><h3>Record a decision</h3><label>Action<select name="action" required defaultValue="reviewing">
        <option value="reviewing">Mark in review</option><option value="resolved">Resolve</option><option value="dismissed">Dismiss</option><option value="suspend">Restrict contact for 24 hours</option><option value="restore">Lift restriction</option>
      </select></label><label>Reason<textarea name="reason" minLength={4} maxLength={500} required rows={3}/></label><button className="primary" disabled={working}>Record decision</button></form>
      <h3>Audit trail</h3><ol className="audit">{selected.history.map(entry => <li key={entry.id}><strong>{labels[entry.action]}</strong><small><DateLabel value={entry.created_at}/></small>{entry.note && <p>{entry.note}</p>}</li>)}</ol>
    </div> : <>
      {!rows.length && !error && <div className="list-empty"><ShieldCheck size={24}/><strong>No reports in the queue</strong></div>}
      {rows.slice(0, 50).map(row => <button disabled={working} className="report-row" key={row.id} onClick={() => void open(row.id)}><Flag size={17}/><div><strong>{categories[row.category]} · @{row.subject_handle}</strong><small><DateLabel value={row.created_at}/></small></div><span className={'pill state-' + row.status}>{labels[row.status]}</span><ArrowRight size={15}/></button>)}
      {(offset > 0 || rows.length > 50) && <div className="pagination"><button className="secondary" disabled={!offset} onClick={() => setOffset(offset - 50)}><ArrowLeft size={15}/> Previous</button><button className="secondary" disabled={rows.length <= 50} onClick={() => setOffset(offset + 50)}>Next <ArrowRight size={15}/></button></div>}
    </>}
  </div>
}
