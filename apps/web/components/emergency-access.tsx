'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'
import { StaffMfa } from './staff-mfa'

type State = 'pending' | 'approved' | 'denied' | 'revoked' | 'accessed' | 'closed' | 'expired'
type ReviewAction = 'approved' | 'denied' | 'revoked' | 'closed'
type AccessRequest = {
  id: string; workspace: string; report: string; reason: string; state: State; expires: string
  history: { action: State | 'requested'; at: string; reason?: string }[]
}
const reviewLabels: Record<ReviewAction, string> = {
  approved: 'Approve one view', denied: 'Deny request', revoked: 'Revoke approval', closed: 'Close review',
}
const uuidPattern = '[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}'

export function EmergencyAccess({ workspace = null }: { workspace?: string | null }) {
  const [requests, setRequests] = useState<AccessRequest[] | null>(null)
  const [reauth, setReauth] = useState(false)
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const [content, setContent] = useState<{ value: string; expiresAt: number } | null>(null)
  const version = useRef(0)
  const load = useCallback(async () => {
    const selected = ++version.current
    const result = await db!.rpc('st_v6_break_glass_list', { p_workspace: workspace })
    if (selected !== version.current) return
    setRequests(result.error ? null : result.data as AccessRequest[])
    setReauth(result.error?.code === '42501')
    if (result.error?.code === '42501') setContent(null)
    if (result.error && result.error.code !== '42501') setError('Could not load emergency access requests.')
  }, [workspace])

  useEffect(() => {
    void load()
    const timer = window.setInterval(() => void load(), 10000)
    return () => {
      ++version.current
      window.clearInterval(timer)
    }
  }, [load])

  useEffect(() => {
    if (!content) return
    const timer = window.setTimeout(() => setContent(null), Math.max(0, content.expiresAt - Date.now()))
    return () => window.clearTimeout(timer)
  }, [content])

  async function run(action: () => PromiseLike<{ data?: unknown; error: unknown }>, onSuccess: (data: unknown) => void) {
    if (busy) return
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const result = await action()
      if (result.error) throw result.error
      onSuccess(result.data)
      await load()
    } catch (cause) {
      setError(formatError(cause, 'Could not complete the emergency access action.'))
      await load()
    } finally {
      setBusy(false)
    }
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = event.currentTarget
    const fields = new FormData(form)
    void run(() => db!.rpc('st_v6_request_break_glass', { p_report: fields.get('report'), p_justification: fields.get('reason') }), () => {
      form.reset()
      setNotice('Request sent to the workspace owner for review.')
    })
  }

  function review(event: FormEvent<HTMLFormElement>, id: string) {
    event.preventDefault()
    const form = event.currentTarget
    const fields = new FormData(form)
    void run(() => db!.rpc('st_v6_review_break_glass', {
      p_grant: id, p_action: fields.get('action'), p_reason: fields.get('reason'),
    }), () => {
      form.reset()
      setNotice('Review decision recorded.')
    })
  }

  function reveal(request: AccessRequest) {
    void run(() => db!.rpc('st_v6_read_break_glass', { p_grant: request.id }), value => {
      if (typeof value === 'string') {
        setContent({ value, expiresAt: Math.min(Date.now() + 60000, Date.parse(request.expires)) })
        setNotice('One-time evidence access recorded.')
      }
    })
  }

  if (reauth) return <StaffMfa refresh={load} explanation="Enter a current authenticator code to access emergency review."/>
  return <section aria-label="Emergency access">
    <div className="panel-header"><h3>Emergency access</h3>
      <button type="button" className="secondary" disabled={busy} onClick={() => void load()}>Refresh requests</button>
    </div>
    {!workspace && <form className="release-form" onSubmit={submit}>
      <label>Workspace room report ID<input name="report" maxLength={36} pattern={uuidPattern} required/></label>
      <label>Why is emergency access needed?<textarea name="reason" minLength={20} maxLength={500} required/></label>
      <button className="primary" disabled={busy}>Request emergency access</button>
    </form>}
    {notice && <p role="status">{notice}</p>}
    {error && <p role="alert" className="error">{error}</p>}
    {!requests && !error && <p role="status">Loading emergency requests…</p>}
    {requests?.length === 0 && <p>No emergency requests.</p>}
    {content && <div className="release-board-item" aria-label="One-time room evidence">
      <div className="panel-header"><strong>One-time room evidence</strong>
        <button type="button" className="secondary" onClick={() => setContent(null)}>Close evidence</button>
      </div>
      <blockquote style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{content.value}</blockquote>
    </div>}
    {requests?.map(request => {
      const actions: ReviewAction[] = request.state === 'pending' ? ['approved', 'denied']
        : request.state === 'approved' ? ['revoked'] : request.state === 'accessed' ? ['closed'] : []
      return <article className="release-board-item" key={request.id}>
        <div className="release-row"><strong>{request.workspace}</strong><span className="pill">{request.state}</span></div>
        <p>{request.reason}</p>
        <p>Room report <code>{request.report}</code></p>
        {['pending', 'approved'].includes(request.state) &&
          <p>Expires <time dateTime={request.expires}>{new Date(request.expires).toLocaleString()}</time></p>}
        {workspace && actions.length > 0 && <form className="release-form" onSubmit={event => review(event, request.id)}>
          <label>Decision<select name="action" required>{actions.map(action =>
            <option key={action} value={action}>{reviewLabels[action]}</option>
          )}</select></label>
          <label>Decision reason<textarea name="reason" minLength={12} maxLength={500} required/></label>
          <button className="primary" disabled={busy}>Record decision</button>
        </form>}
        {!workspace && request.state === 'approved' &&
          <button type="button" className="primary" disabled={busy} onClick={() => reveal(request)}>View approved evidence once</button>}
        <details><summary>Review history</summary>
          <ol>{request.history.map(entry => <li key={entry.at + entry.action}>
            {entry.action} · <time dateTime={entry.at}>{new Date(entry.at).toLocaleString()}</time>
            {entry.reason && <p>{entry.reason}</p>}
          </li>)}</ol>
        </details>
      </article>
    })}
  </section>
}
