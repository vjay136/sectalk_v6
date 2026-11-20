'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { db } from '../lib/data'

type Entry = {id: string; kind: string; occurred_at: string; read_at: string | null}
const labels: Record<string, string> = {
  'dm.message': 'Direct message',
  'call.incoming': 'Incoming call',
  'mention.user': 'Room mention',
  'mention.group': 'Room mention',
  'mention.here': 'Room mention',
  'mention.channel': 'Room mention',
  'thread.reply': 'Thread reply',
  'task.due': 'Task reminder',
  'task.completed': 'Completed task',
  'security.report': 'Safety report update',
  'security.account': 'Account notice',
  'billing.subscription': 'Billing update',
  'admin.room': 'Admin-room activity',
}

export function NotificationDelivery() {
  const [items, setItems] = useState<Entry[] | null>(null)
  const [reading, setReading] = useState<string | null>(null)
  const [error, setError] = useState('')
  const version = useRef(0)
  const load = useCallback(async () => {
    const request = ++version.current
    const {data, error} = await db!.rpc('st_v6_notification_fallbacks')
    if (request !== version.current) return
    if (error) setError('Could not load fallback alerts.')
    else {
      setError('')
      setItems(data as Entry[])
    }
  }, [])

  useEffect(() => {
    void load()
    const timer = window.setInterval(load, 15000)
    return () => { version.current++; window.clearInterval(timer) }
  }, [load])

  async function markRead(id: string) {
    if (reading) return
    setReading(id)
    const {error} = await db!.rpc('st_v6_read_notification_fallback', {p_id: id})
    if (error) setError('Could not mark the fallback alert as read.')
    else await load()
    setReading(null)
  }

  return <section className="panel release-panel" aria-label="Delivery fallback">
    <div className="release-row"><h2>Delivery fallback</h2>
      <button type="button" className="secondary" onClick={() => void load()}>Refresh delivery</button>
    </div>
    <p>Alerts can appear here for seven days when browser push delivery fails.</p>
    {error && <p role="alert" className="error">{error}</p>}
    {!items && !error && <p role="status">Loading fallback alerts…</p>}
    {items?.length === 0 && <p>No fallback alerts.</p>}
    {items?.map(item => <article className="release-board-item" key={item.id}>
      <div className="release-row">
        {!item.read_at && <span className="status-dot" aria-label="Unread"/>}
        <strong>{labels[item.kind] ?? 'SecTalk alert'}</strong>
        <time dateTime={item.occurred_at}>{new Date(item.occurred_at).toLocaleString()}</time>
        {!item.read_at && <button type="button" className="text-button" disabled={Boolean(reading)}
          onClick={() => void markRead(item.id)}>Mark read</button>}
      </div>
    </article>)}
  </section>
}
