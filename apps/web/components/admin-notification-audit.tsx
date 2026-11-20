'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { db } from '../lib/data'

const statuses = {
  processed: 'Processing recorded',
  unconfirmed: 'No browser receipt recorded',
  acknowledged: 'Browser receipt recorded',
}
type AuditEntry = {
  post_id: string
  sender: string
  processed_at: string
  status: keyof typeof statuses
}

export function AdminNotificationAudit({room, name}: {room: string; name: (user: string) => string}) {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null)
  const [error, setError] = useState(false)
  const requestVersion = useRef(0)
  const load = useCallback(async () => {
    const request = ++requestVersion.current
    const result = await db!.rpc('st_v6_admin_notification_audit', {p_room: room})
    if (request !== requestVersion.current) return
    setError(Boolean(result.error))
    setEntries(result.error ? null : result.data as AuditEntry[])
  }, [room])

  useEffect(() => {
    void load()
    return () => { ++requestVersion.current }
  }, [load])

  return <section aria-label="Admin notification delivery">
    <div className="release-row">
      <h3>Admin notification delivery</h3>
      <button className="secondary" type="button" onClick={() => void load()}>Refresh delivery status</button>
    </div>
    <p>A browser receipt confirms that at least one connected browser received the alert. Small audiences show only the processing record.</p>
    {error && <p className="error" role="alert">Could not load notification delivery.</p>}
    {!entries && !error && <p role="status">Loading notification delivery…</p>}
    {entries?.length === 0 && <p>No notification delivery records yet.</p>}
    {entries && entries.length > 0 && <ol className="audit">
      {entries.map(entry => <li key={entry.post_id}>
        <strong>{statuses[entry.status]}</strong>
        <span>{name(entry.sender)} · <time dateTime={entry.processed_at}>{new Date(entry.processed_at).toLocaleString()}</time></span>
      </li>)}
    </ol>}
  </section>
}
