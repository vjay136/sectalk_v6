'use client'

import { useEffect, useState } from 'react'
import { formatChatFileBytes } from '../lib/chat-files'
import { db } from '../lib/data'
import { Dialog } from './inbox'
import { AttachmentShareLinks } from './attachment-share-links'

type Details = { filename: string; size_bytes: number; shared_at: string; can_view_history: boolean }
type Activity = {
  event: 'share' | 'view' | 'download' | 'link_created' | 'link_revoked' | 'link_view' | 'link_download'
  participant: 'owner' | 'recipient' | 'link_visitor'
  occurred_at: string
}

const labels: Record<Activity['event'], string> = {
  share: 'Shared in direct chat',
  view: 'File details viewed',
  download: 'Attachment downloaded',
  link_created: 'Share link created',
  link_revoked: 'Share link revoked',
  link_view: 'Share link details viewed',
  link_download: 'Shared attachment downloaded',
}
const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' })

function DateLabel({ at }: { at: string }) {
  return <time dateTime={at}>{dateFormat.format(new Date(at))}</time>
}

export function AttachmentDetails({ file, close }: { file: string; close: () => void }) {
  const [details, setDetails] = useState<Details | null | undefined>(undefined)
  const [history, setHistory] = useState<Activity[] | null | undefined>(undefined)
  const [attempt, setAttempt] = useState(0)
  const showHistory = details?.can_view_history === true

  useEffect(() => {
    const request = new AbortController()
    void db!.rpc('st_v6_view_file_details', { p_file: file }).abortSignal(request.signal).maybeSingle()
      .then(({ data, error }) => {
        if (!request.signal.aborted) setDetails(error ? null : data as Details | null)
      })
    return () => request.abort()
  }, [file])

  useEffect(() => {
    if (!showHistory) return
    const request = new AbortController()
    void db!.rpc('st_v6_file_access_history', { p_file: file }).abortSignal(request.signal)
      .then(({ data, error }) => {
        if (!request.signal.aborted) setHistory(error ? null : data as Activity[])
      })
    return () => request.abort()
  }, [file, showHistory, attempt])

  return <Dialog title="Attachment details" close={close}>
    {details === undefined && <p role="status">Loading attachment details…</p>}
    {details === null && <p role="alert" className="error">Attachment details are unavailable.</p>}
    {details && <>
      <h3>{details.filename}</h3>
      <p>{formatChatFileBytes(details.size_bytes)} · Shared <DateLabel at={details.shared_at}/></p>
    </>}
    {showHistory && <AttachmentShareLinks file={file} onChanged={() => setAttempt(value => value + 1)}/>}
    {showHistory && <section aria-labelledby="attachment-access-history">
      <div className="panel-header">
        <h3 id="attachment-access-history">Access history</h3>
        <button className="secondary" type="button" onClick={() => setAttempt(value => value + 1)}>Refresh history</button>
      </div>
      <p className="muted">Latest 50 attachment events. Repeat direct-chat detail views within five minutes count as one.</p>
      {history === undefined && <p role="status">Loading access history…</p>}
      {history === null && <p role="alert" className="error">Could not load access history.</p>}
      {!!history?.length && <ol className="audit">{history.map((row, index) => <li key={row.occurred_at + row.event + index}>
        <strong>{labels[row.event]}</strong>
        <small>{row.participant === 'owner' ? 'You' : row.participant === 'recipient' ? 'Recipient' : 'Link visitor'} · <DateLabel at={row.occurred_at}/></small>
      </li>)}</ol>}
    </section>}
  </Dialog>
}
