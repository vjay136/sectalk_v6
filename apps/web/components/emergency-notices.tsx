'use client'

import { useEffect, useState } from 'react'
import { db } from '../lib/data'

type Notice = { id: string; workspace: string; stage: string; occurred_at: string; read_at: string | null }
const stageLabels: Record<string, string> = {
  requested: 'Emergency evidence access was requested.',
  approved: 'A one-time emergency request was approved.',
  denied: 'An emergency request was denied.',
  revoked: 'An emergency approval was revoked.',
  accessed: 'The approved evidence was accessed.',
  closed: 'The emergency access review was closed.',
}

export function EmergencyNotices({hints}: {hints: EventTarget}) {
  const [rows, setRows] = useState<Notice[] | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')
  const [revision, setRevision] = useState(0)
  useEffect(() => {
    let active = true
    async function load() {
      const result = await db!.rpc('st_v6_my_emergency_notices')
      if (!active) return
      setRows(result.error ? [] : result.data as Notice[])
      setError(result.error ? 'Could not load workspace access notices.' : '')
    }
    void load()
    hints.addEventListener('emergency_customer_notice', load)
    return () => {
      active = false
      hints.removeEventListener('emergency_customer_notice', load)
    }
  }, [hints, revision])

  async function acknowledge(id: string) {
    if (busy) return
    setBusy(id)
    const { error } = await db!.rpc('st_v6_read_emergency_notice', { p_notice: id })
    setBusy('')
    if (error) setError('Could not mark the notice as read.')
    else setRevision(value => value + 1)
  }
  if (rows?.length === 0 && !error) return null
  return <section aria-label="Workspace emergency notices">
    <h3>Workspace emergency notices</h3>
    {error && <p role="alert" className="error">{error}</p>}
    {rows?.map(notice => <article className="release-board-item" key={notice.id}>
      <strong>{notice.workspace}</strong>
      <p>{stageLabels[notice.stage]}</p>
      <time dateTime={notice.occurred_at}>{new Date(notice.occurred_at).toLocaleString()}</time>
      {!notice.read_at && <button type="button" className="secondary" disabled={Boolean(busy)}
        onClick={() => void acknowledge(notice.id)}>Mark notice as read</button>}
    </article>)}
  </section>
}
