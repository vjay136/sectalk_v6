'use client'

import { useState, type FormEvent } from 'react'
import { db } from '../lib/data'
import { isReportTicket,ReportTicket } from './report-ticket'

export function GroupMessageReport({ group, message, text }: { group: string; message: string; text: string }) {
  const [includeText, setIncludeText] = useState(false)
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<string|null>(null)
  const reported=isReportTicket(result)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy || reported) return
    const form = new FormData(event.currentTarget)
    setBusy(true)
    setResult(null)
    try {
      const { data, error } = await db!.rpc('st_report_group_message', {
        p_group: group, p_message: message, p_category: form.get('category'),
        p_share: includeText, p_evidence: includeText ? text : null,
      })
      setResult(error || !isReportTicket(data) ? 'error' : data)
    } catch {
      setResult('error')
    } finally {
      setBusy(false)
    }
  }

  return <details>
    <summary>Report group message</summary>
    {reported ? <div role="status"><p>Report submitted to Safety.</p><ReportTicket id={result}/></div> : <form onSubmit={event => void submit(event)}>
      <label>Reason<select name="category" defaultValue="scam" disabled={busy}>
        <option value="scam">Scam or spam</option><option value="harassment">Harassment</option>
        <option value="threat">Threat</option><option value="impersonation">Impersonation</option>
        <option value="other">Other</option>
      </select></label>
      <label><input type="checkbox" checked={includeText}
        onChange={event => setIncludeText(event.target.checked)} disabled={busy} /> Share this message’s text with verified Safety reviewers</label>
      {!includeText && <p>The report includes the sender and message reference.</p>}
      {includeText && <blockquote>{text}</blockquote>}
      <button className="secondary" disabled={busy}>{includeText ? 'Submit report with message text' : 'Submit report without message text'}</button>
      {result === 'error' && <p role="alert">The report could not be submitted.</p>}
    </form>}
  </details>
}
