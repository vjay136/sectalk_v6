'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'

const categories = {
  harassment: 'Harassment', threat: 'Threat', scam: 'Scam', impersonation: 'Impersonation',
  spam: 'Spam', sexual_content: 'Sexual content', other: 'Other',
}
const statuses = {open: 'Open', reviewing: 'In review', resolved: 'Resolved', dismissed: 'Dismissed'}
const stages = ['Unassigned', 'L1', 'L2', 'Workspace admin', 'Platform']
type Report = {
  id: string
  category: keyof typeof categories
  status: keyof typeof statuses
  created_at: string
  share_with_workspace?: boolean
  handed_off_at: string | null
  details?: string
  room_name?: string | null
  workspace_name?: string
  evidence?: string | null
  stage?: number | null
  acknowledge_by?: string | null
  action_by?: string | null
  acknowledged_at?: string | null
  assigned_to_you?: boolean
  can_acknowledge?: boolean
  can_route?: boolean
  can_decide?: boolean
  can_delegate?: boolean
  assigned_at?: string
  decision_scope?: 'workspace' | 'platform' | null
  decided_at?: string | null
}

export function RoomPostReport({room, post, close}: {room: string; post: string; close: () => void}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [sent, setSent] = useState(false)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    setBusy(true)
    setError('')
    const form = new FormData(event.currentTarget)
    const {error} = await db!.rpc('st_v6_submit_room_report', {
      p_room: room, p_post: post, p_category: form.get('category'),
      p_details: form.get('details'), p_share: form.has('share'),
    })
    if (error) setError(formatError(error, 'Could not submit this room report.'))
    else setSent(true)
    setBusy(false)
  }

  return <section className="release-section" aria-label="Report room message">
    <h3>Report room message</h3>
    {sent ? <p role="status">Report submitted. Follow its status in Safety under My reports.</p> :
      <form className="release-form" onSubmit={submit}>
        <label>Category<select name="category" required defaultValue="">
          <option value="" disabled>Choose a category</option>
          {Object.entries(categories).map(([key, label]) => <option key={key} value={key}>{label}</option>)}
        </select></label>
        <label>Private details for platform staff<textarea name="details" maxLength={1500} rows={3}/></label>
        <label><input type="checkbox" name="share"/> Allow platform staff to share this post and category with authorized workspace admins</label>
        <button className="primary" disabled={busy}>Submit room report</button>
      </form>}
    {error && <p className="error" role="alert">{error}</p>}
    <button className="secondary" type="button" disabled={busy} onClick={close}>{sent ? 'Done' : 'Cancel room report'}</button>
  </section>
}

function useRoomReports(scope: 'mine' | 'platform' | 'workspace') {
  const [rows, setRows] = useState<Report[] | null>(null)
  const [error, setError] = useState('')
  const load = useCallback(async () => {
    const result = scope === 'mine' ? await db!.rpc('st_v7_my_room_report_status')
      : scope === 'workspace' ? await db!.rpc('st_v7_workspace_room_review_queue')
      : await db!.rpc('st_v6_room_report_queue', {p_scope: scope})
    setRows(result.error ? null : result.data as Report[])
    setError(result.error ? 'Room reports are unavailable.' : '')
  }, [scope])
  useEffect(() => {
    void load()
    if (scope !== 'mine') return
    const timer = window.setInterval(() => { if (document.visibilityState === 'visible') void load() }, 5000)
    return () => window.clearInterval(timer)
  }, [load, scope])
  return {rows, error, load}
}

export function MyRoomReports() {
  const {rows, error, load} = useRoomReports('mine')
  return <section className="release-section" aria-label="My room reports">
    <div className="release-row"><h3>My room reports</h3>
      <button type="button" className="secondary" onClick={() => void load()}>Refresh room reports</button>
    </div>
    {error && <p role="alert" className="error">{error}</p>}
    {rows?.length === 0 && <p>No room reports yet.</p>}
    {rows?.map(row => <article className="release-board-item" key={row.id}>
      <strong>{categories[row.category]}</strong><p>{statuses[row.status]}</p>
      <time dateTime={row.created_at}>{new Date(row.created_at).toLocaleString()}</time>
      {row.decision_scope && row.decided_at && <p>{row.decision_scope === 'workspace' ? 'Decided by your workspace reviewer' : 'Decided by Platform Safety'}
        {' · '}<time dateTime={row.decided_at}>{new Date(row.decided_at).toLocaleString()}</time></p>}
      <p>{row.handed_off_at ? 'Shared with authorized workspace admins' :
        row.share_with_workspace ? 'You allowed workspace sharing' : 'Platform review only'}</p>
    </article>)}
  </section>
}

export function RoomReportQueue({scope}: {scope: 'platform' | 'workspace'}) {
  const {rows, error, load} = useRoomReports(scope)
  const [active, setActive] = useState('')
  const [busy, setBusy] = useState(false)
  const [actionError, setActionError] = useState('')
  const [feedback, setFeedback] = useState('')
  const [action, setAction] = useState('')
  const [candidate, setCandidate] = useState('')
  const [reviewers, setReviewers] = useState<Array<{ id: string; name: string; handle: string }>>([])
  const selected = rows?.find(row => row.id === active)
  const title = scope === 'platform' ? 'Platform room reports' : 'Workspace room reports'

  const assignable = scope === 'workspace' && selected?.can_delegate ? selected.id : null
  useEffect(() => {
    const request = new AbortController()
    setReviewers([])
    setCandidate('')
    if (assignable) void db!.rpc('st_v7_workspace_room_reviewers', { p_report: assignable }).abortSignal(request.signal)
      .then(result => { if (!request.signal.aborted && !result.error) setReviewers(result.data ?? []) })
    return () => request.abort()
  }, [assignable])
  async function review(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!selected || busy) return
    const form = event.currentTarget
    const fields = new FormData(form)
    setBusy(true)
    setActionError('')
    setFeedback('')
    const chosen = fields.get('action')
    const workspaceAction = scope === 'workspace' && (chosen === 'resolved' || chosen === 'dismissed' || chosen === 'delegate')
    const {error} = workspaceAction ? await db!.rpc('st_v7_workspace_room_case_action', {
      p_report: selected.id, p_action: chosen, p_reason: fields.get('reason'),
      p_expected_assignment: selected.assigned_at, p_reviewer: chosen === 'delegate' ? candidate : null,
    }) : await db!.rpc('st_v6_review_room_report', {
      p_report: selected.id, p_scope: scope, p_action: chosen, p_reason: fields.get('reason'),
      p_expected_stage: selected.stage ?? 0,
    })
    if (error) setActionError(formatError(error, 'Could not update this room report.'))
    else {
      form.reset()
      setAction('')
      setCandidate('')
      await load()
      setFeedback('Room report updated.')
    }
    setBusy(false)
  }

  const ordered = rows?.slice().sort((left, right) => Number(Boolean(right.assigned_to_you)) - Number(Boolean(left.assigned_to_you)))
  return <section className="release-section" aria-label={title}>
    <div className="release-row"><h3>{title}</h3>
      <button type="button" className="secondary" disabled={busy} onClick={() => void load()}>Refresh room reports</button>
    </div>
    {error && <p role="alert" className="error">{error}</p>}
    {feedback && <p role="status">{feedback}</p>}
    {!error && !rows && <p role="status">Loading room reports…</p>}
    {rows?.length === 0 && <p>No room reports to review.</p>}
    {selected ? <article className="release-board-item">
      <button className="secondary" disabled={busy} type="button" onClick={() => {setActive('');setAction('');setActionError('');setFeedback('')}}>Back to room reports</button>
      <h4>{categories[selected.category]}</h4>
      <p>{statuses[selected.status]} · {selected.room_name || 'Room unavailable'}</p>
      <p>{selected.workspace_name}</p>
      {scope === 'platform' && selected.share_with_workspace && <p>Room report ID <code>{selected.id}</code></p>}
      {selected.details && <p className="case-text">{selected.details}</p>}
      {selected.evidence ? <blockquote>{selected.evidence}</blockquote> : <p>The reported post is no longer available.</p>}
      {selected.handed_off_at && <p>Shared with authorized workspace admins.</p>}
      {scope === 'platform' && !selected.share_with_workspace && <p>Reporter selected platform review only.</p>}
      {(selected.share_with_workspace || selected.stage) && <dl className="profile-stats">
        <div><dt>Current stage</dt><dd>{stages[selected.stage ?? 0]}</dd></div>
        {selected.assigned_to_you && <div><dt>Assignment</dt><dd>Assigned to you</dd></div>}
        {selected.acknowledge_by && <div><dt>Acknowledge by</dt><dd>{new Date(selected.acknowledge_by).toLocaleString()}</dd></div>}
        {selected.action_by && <div><dt>Action due</dt><dd>{new Date(selected.action_by).toLocaleString()}</dd></div>}
        {selected.acknowledged_at && <div><dt>Acknowledged</dt><dd>{new Date(selected.acknowledged_at).toLocaleString()}</dd></div>}
      </dl>}
      {actionError && <p role="alert" className="error">{actionError}</p>}
      {(selected.can_decide || selected.can_acknowledge || selected.can_route || reviewers.length > 0) && <form key={selected.id} className="release-form" onSubmit={review}>
        <label>Review action<select name="action" required onChange={event => setAction(event.target.value)}>
          {selected.can_route && <option value="route">Route to {stages[(selected.stage ?? 0) + 1]}</option>}
          {selected.can_acknowledge && <option value="acknowledge">Acknowledge stage</option>}
          {selected.can_decide && <>
            {scope === 'platform' && <option value="reviewing">Mark in review</option>}
            <option value="resolved">Resolve</option>
            <option value="dismissed">Dismiss</option>
          </>}
          {reviewers.length > 0 && <option value="delegate">Reassign to another workspace reviewer</option>}
        </select></label>
        {action === 'delegate' && <label>Workspace reviewer<select value={candidate} required
          onChange={event => setCandidate(event.target.value)}>
          <option value="">Choose a verified reviewer</option>
          {reviewers.map(reviewer => <option key={reviewer.id} value={reviewer.id}>{reviewer.name} (@{reviewer.handle})</option>)}
        </select></label>}
        <label>Review reason<textarea name="reason" maxLength={500} rows={2} required/></label>
        <button className="primary" disabled={busy}>Update room report</button>
      </form>}
    </article> : ordered?.map(row => <button className="report-row" type="button" key={row.id} onClick={() => setActive(row.id)}>
      <span><strong>{categories[row.category]} · {row.room_name || 'Room unavailable'}</strong>
        <small>{row.workspace_name} {row.stage ? stages[row.stage] : ''} {row.assigned_to_you ? '· Assigned to you' : ''}{' '}
          <time dateTime={row.created_at}>{new Date(row.created_at).toLocaleString()}</time></small></span>
      <span>{statuses[row.status]}</span>
    </button>)}
  </section>
}
