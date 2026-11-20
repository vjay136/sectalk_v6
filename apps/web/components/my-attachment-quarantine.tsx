'use client'

import { useEffect, useState, type FormEvent } from 'react'
import { db } from '../lib/data'
import { attachmentInspectionLabel } from '../lib/attachment-inspection'

const labels = {
  quarantined: 'Scan unavailable',
  awaiting_release: 'Awaiting security review',
  released: 'Released for sending',
  malware: 'Blocked by scanner',
}
type Item = { file_id: string; filename: string; state: keyof typeof labels; retain_until: string; inspection_reason: string | null }

export function MyAttachmentQuarantine({ onPublished }: { onPublished: () => void }) {
  const [open, setOpen] = useState(false)
  const [revision, setRevision] = useState(0)
  const [rows, setRows] = useState<Item[] | null>(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!open) return
    const request = new AbortController()
    void db!.rpc('st_v6_my_attachment_quarantine').abortSignal(request.signal).then(({ data, error }) => {
      if (request.signal.aborted) return
      if (error) setError('Could not load pending security scans.')
      else setRows(data as Item[])
    })
    return () => request.abort()
  }, [open, revision])

  async function retry(event: FormEvent<HTMLFormElement>, item: Item) {
    event.preventDefault()
    if (busy) return
    const caption = String(new FormData(event.currentTarget).get('caption'))
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const { data } = await db!.auth.getSession()
      if (!data.session) { setError('Sign in to retry this attachment.'); return }
      const response = await fetch('/api/files/publish', {
        method: 'POST', headers: { Authorization: 'Bearer ' + data.session.access_token, 'Content-Type': 'application/json' },
        body: JSON.stringify({ file: item.file_id, caption, mime: '' }),
      })
      if (response.ok) {
        setNotice('Attachment sent.')
        onPublished()
      } else {
        const detail = await response.json().catch(() => null)
        setError(detail?.error || 'Could not send this attachment.')
      }
      setRevision(value => value + 1)
    } catch {
      setError('Could not send this attachment.')
    } finally {
      setBusy(false)
    }
  }

  return <details onToggle={event => setOpen(event.currentTarget.open)}>
    <summary>Pending security scans</summary>
    <button className="secondary" type="button" onClick={() => { setError(''); setRevision(value => value + 1) }}>
      Refresh security scans
    </button>
    {error && <p role="alert" className="error">{error}</p>}
    {notice && <p role="status">{notice}</p>}
    {rows?.length === 0 && <p>No pending attachments.</p>}
    {rows?.map(row => <article className="release-board-item" key={row.file_id}>
      <strong>{row.filename}</strong><p>{labels[row.state]}</p>
      {row.inspection_reason && <p>Static inspection flagged {attachmentInspectionLabel(row.inspection_reason)?.toLowerCase()}.</p>}
      {(row.state === 'quarantined' || row.state === 'released') && <form onSubmit={event => void retry(event, row)}>
        <label>Caption<input name="caption" maxLength={4000}/></label>
        <button className="secondary" disabled={busy}>Retry sending</button>
      </form>}
    </article>)}
  </details>
}
