'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db } from '../lib/data'

const categories = {
  spam: 'Spam', unwanted: 'Unwanted message', fake: 'Misleading or fake content', abuse: 'Abuse or harassment',
  fraud: 'Fraud or scam', gambling: 'Gambling', insecure_link: 'Potentially unsafe link', other: 'Other safety concern',
} as const
const verdictLabels = { warning: 'Reviewed warning', cleared: 'Reviewed · no issue confirmed' } as const

type Verdict = keyof typeof verdictLabels
type Category = keyof typeof categories
type Decision = '' | Verdict | 'remove'
type Propagation = {
  eligible: boolean
  can_change: boolean
  verdict: Verdict | null
  category: Category | null
  forward_count: number
  forwarders: number
  original_name: string | null
  first_report_at: string | null
}
type ChainAccount = { display_name: string; handle: string; shares: number; original: boolean }
const pageSize = 25

function ChainAccounts({ report }: { report: string }) {
  const [offset, setOffset] = useState(0)
  const [accounts, setAccounts] = useState<ChainAccount[] | null>(null)
  const [failure, setFailure] = useState(false)
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    const request = new AbortController()
    void db!.rpc('st_report_propagation_members', { p_report: report, p_offset: offset })
      .abortSignal(request.signal).then(result => {
        if (request.signal.aborted) return
        if (result.error || !Array.isArray(result.data)) setFailure(true)
        else setAccounts(result.data as ChainAccount[])
      })
    return () => request.abort()
  }, [report, offset, attempt])

  function changePage(next: number) {
    setAccounts(null)
    setFailure(false)
    setOffset(next)
    setAttempt(value => value + 1)
  }

  return <div>
    {failure ? <p role="alert">Accounts in this chain could not be loaded.</p> : !accounts ?
      <p role="status">Loading accounts…</p> : accounts.length > 0 ? <ul>
      {accounts.map(account => <li key={account.handle}>
        <strong>{account.display_name}</strong> @{account.handle} · {account.original ? 'Original sender · ' : ''}
        {account.shares.toLocaleString()} {account.shares === 1 ? 'forward' : 'forwards'}
      </li>)}
    </ul> : <p>No further accounts in this chain.</p>}
    <div className="pagination" role="group" aria-label="Accounts in chain pages">
      {offset > 0 && <button type="button" className="secondary" onClick={() => changePage(offset - pageSize)}>Previous accounts</button>}
      {accounts?.length === pageSize && <button type="button" className="secondary" onClick={() => changePage(offset + pageSize)}>Next accounts</button>}
      {failure && <button type="button" className="secondary" onClick={() => changePage(offset)}>Retry accounts</button>}
    </div>
  </div>
}

export function CaseMessageSafety({ report, reportStatus }: { report: string; reportStatus: string }) {
  const [propagation, setPropagation] = useState<Propagation | null>(null)
  const [loadError, setLoadError] = useState(false)
  const [attempt, setAttempt] = useState(0)
  const [decision, setDecision] = useState<Decision>('')
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState('')
  const [failure, setFailure] = useState('')
  const [showAccounts, setShowAccounts] = useState(false)

  const read = useCallback(async (signal?: AbortSignal) => {
    const request = db!.rpc('st_report_propagation', { p_report: report })
    const result = await (signal ? request.abortSignal(signal) : request)
    if (signal?.aborted) return
    if (result.error || typeof result.data?.eligible !== 'boolean') setLoadError(true)
    else setPropagation(result.data as Propagation)
  }, [report])

  useEffect(() => {
    const request = new AbortController()
    void read(request.signal)
    return () => request.abort()
  }, [read, attempt])

  const closed = reportStatus === 'resolved' || reportStatus === 'dismissed'

  async function apply(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!propagation?.eligible || !propagation.can_change || !closed || !decision || busy || loadError) return
    const form = event.currentTarget
    const fields = new FormData(form)
    const note = String(fields.get('audit-note') ?? '').trim()
    if (note.length < 4) {
      setFailure('Enter at least four characters in the private audit note.')
      return
    }
    setBusy(true)
    setFailure('')
    setNotice('')
    const { error } = await db!.rpc('st_set_report_advisory', {
      p_report: report, p_verdict: decision,
      p_category: decision === 'remove' ? null : fields.get('safety-category'), p_note: note,
    })
    if (error) setFailure('The label could not be saved. Check the current case status and your staff verification.')
    else {
      form.reset()
      setDecision('')
      setNotice(decision === 'remove' ? 'Message safety label removed.' : 'Message safety label saved.')
      await read()
    }
    setBusy(false)
  }

  return <section aria-label="Message safety label">
    <h3>Message safety label</h3>
    {loadError ? <>
      <p role="alert">The message safety record could not be loaded.</p>
      <button type="button" className="secondary" onClick={() => {
        setLoadError(false)
        setPropagation(null)
        setAttempt(value => value + 1)
      }}>Retry message safety</button>
    </> : !propagation ? <p role="status">Loading message safety record…</p> : !propagation.eligible ?
      <p>This report has no eligible direct-message evidence for a safety label.</p> : <>
      <dl className="profile-stats">
        <div><dt>Current label</dt><dd>{propagation.verdict ? verdictLabels[propagation.verdict] : 'None'}</dd></div>
        {propagation.verdict === 'warning' && propagation.category &&
          <div><dt>Warning reason</dt><dd>{categories[propagation.category]}</dd></div>}
        {propagation.original_name && <div><dt>Original sender</dt><dd>{propagation.original_name}</dd></div>}
        <div><dt>Forwards</dt><dd>{propagation.forward_count.toLocaleString()}</dd></div>
        <div><dt>Accounts that forwarded</dt><dd>{propagation.forwarders.toLocaleString()}</dd></div>
        {propagation.first_report_at && <div><dt>First report</dt><dd><time dateTime={propagation.first_report_at}>
          {new Date(propagation.first_report_at).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}
        </time></dd></div>}
      </dl>
      <details onToggle={event => setShowAccounts(event.currentTarget.open)}>
        <summary>Accounts in chain</summary>
        {showAccounts && <ChainAccounts report={report}/>}
      </details>
      {!closed ? <p>Close the report before applying a reviewed label.</p> : !propagation.can_change ?
        <p>Manage the active label from the report that issued it.</p> : <form onSubmit={apply}>
        <label>Reviewed label<select value={decision} onChange={event => setDecision(event.currentTarget.value as Decision)} required disabled={busy}>
          <option value="">Choose a label</option>
          {reportStatus === 'resolved' && <option value="warning">Show a reviewed warning</option>}
          {reportStatus === 'dismissed' && <option value="cleared">Show reviewed · no issue confirmed</option>}
          {propagation.verdict && <option value="remove">Remove label from this case</option>}
        </select></label>
        {decision === 'warning' && <label>Warning reason<select name="safety-category" required defaultValue={propagation.category ?? ''} disabled={busy}>
          <option value="">Choose a preset reason</option>
          {Object.entries(categories).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select></label>}
        <label>Private audit note<textarea name="audit-note" rows={3} minLength={4} maxLength={500} required disabled={busy}/></label>
        <p>Recipients see the reviewed label and its preset warning reason when applicable. The audit note remains in the staff case.</p>
        <button type="submit" className="primary" disabled={!decision || busy}>{busy ? 'Saving label…' : 'Save message safety label'}</button>
      </form>}
    </>}
    {failure && <p role="alert">{failure}</p>}
    {notice && <p role="status">{notice}</p>}
  </section>
}
