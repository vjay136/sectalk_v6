'use client'

import { useEffect, useState, type FormEvent } from 'react'
import { db } from '../lib/data'
import { formatChatFileBytes } from '../lib/chat-files'

const labels = {
  quarantined: 'Scan unavailable',
  awaiting_release: 'Clean re-scan received',
  malware: 'Blocked by scanner',
}
type QueueItem = { file_id: string; size_bytes: number; state: keyof typeof labels; scanned_at: string }

export function AttachmentQuarantine() {
  const [rows, setRows] = useState<QueueItem[] | null>(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  const [revision, setRevision] = useState(0)

  useEffect(() => {
    const request = new AbortController()
    void db!.rpc('st_v6_attachment_scan_queue').abortSignal(request.signal).then(({ data, error }) => {
      if (request.signal.aborted) return
      if (error) setError('Could not load attachment quarantine.')
      else setRows(data as QueueItem[])
    })
    return () => request.abort()
  }, [revision])

  async function release(event: FormEvent<HTMLFormElement>, file: string) {
    event.preventDefault()
    if (busy) return
    const form = event.currentTarget
    const reason = String(new FormData(form).get('reason')).trim()
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const { error } = await db!.rpc('st_v6_release_attachment_scan', { p_file: file, p_reason: reason })
      if (error) setError('A current clean re-scan and reviewer assignment are required.')
      else {
        form.reset()
        setNotice('Released. The sender can retry sending this attachment.')
        setRevision(value => value + 1)
      }
    } finally {
      setBusy(false)
    }
  }

  return <section className="panel release-panel" aria-labelledby="attachment-quarantine-title">
    <div className="panel-header">
      <h2 id="attachment-quarantine-title">Attachment quarantine</h2>
      <button className="secondary" type="button" onClick={() => {
        setError('')
        setRevision(value => value + 1)
      }}>Refresh quarantine</button>
    </div>
    <p>Release requires a clean re-scan of the same bytes. Scanner-blocked attachments cannot be released.</p>
    {error && <p role="alert" className="error">{error}</p>}
    {notice && <p role="status">{notice}</p>}
    {!rows && !error && <p role="status">Loading attachment quarantine…</p>}
    {rows?.length === 0 && <p>No attachments in quarantine.</p>}
    {rows?.map(row => <article key={row.file_id} className="release-board-item">
      <h3>{labels[row.state]}</h3>
      <p><code>{row.file_id}</code> · {formatChatFileBytes(row.size_bytes)}</p>
      <time dateTime={row.scanned_at}>{new Date(row.scanned_at).toLocaleString()}</time>
      {row.state === 'awaiting_release' && <form onSubmit={event => void release(event, row.file_id)}>
        <label>Reason for release<textarea name="reason" required minLength={4} maxLength={500} rows={2}/></label>
        <button className="primary" disabled={busy}>Release attachment</button>
      </form>}
    </article>)}
  </section>
}
