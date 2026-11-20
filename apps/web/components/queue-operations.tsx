'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { db } from '../lib/data'

type Entry = {id: string; channel: 'web_push' | 'email'; reason: string; failed_at: string; replayable: boolean}
const reasons: Record<string, string> = {
  provider_rejected: 'Provider rejected delivery',
  subscription_gone: 'Subscription ended',
  retry_exhausted: 'Retry limit reached',
  expired: 'Delivery window expired',
}

export function QueueOperations({onAccessChanged}: {onAccessChanged: () => Promise<void>}) {
  const [entries, setEntries] = useState<Entry[] | null>(null)
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const version = useRef(0)
  const load = useCallback(async () => {
    const request = ++version.current
    const result = await db!.rpc('st_v6_queue_dead_letters')
    if (request !== version.current) return
    if (result.error) {
      setEntries(null)
      setError('Could not load the notification dead-letter queue.')
      if (result.error.code === '42501') await onAccessChanged()
    } else {
      setEntries(result.data as Entry[])
      setError('')
    }
  }, [onAccessChanged])

  useEffect(() => {
    void load()
    return () => { ++version.current }
  }, [load])

  async function replay(id: string) {
    if (busy) return
    setBusy(true)
    setNotice('')
    setError('')
    const result = await db!.rpc('st_v6_replay_queue_dead_letter', {p_id: id})
    if (result.error) {
      if (result.error.code === '42501') await onAccessChanged()
      setError('This failed delivery is no longer available for replay.')
    } else {
      await load()
      setNotice('Replay queued.')
    }
    setBusy(false)
  }

  return <section className="panel release-panel" aria-label="Queue operations">
    <div className="panel-header"><h2>Queue operations</h2>
      <button type="button" className="secondary" disabled={busy} onClick={() => void load()}>Refresh queue</button>
    </div>
    <p>Retry eligible email or browser push failures from the last seven days.</p>
    {notice && <p role="status">{notice}</p>}
    {error && <p role="alert" className="error">{error}</p>}
    {!entries && !error && <p role="status">Loading delivery failures…</p>}
    {entries?.length === 0 && <p>No recent delivery failures.</p>}
    {entries?.map(entry => <article className="release-board-item" key={entry.id}>
      <div className="release-row">
        <strong>{entry.channel === 'email' ? 'Email' : 'Browser push'}</strong>
        <span>{reasons[entry.reason] ?? 'Delivery failed'}</span>
        <time dateTime={entry.failed_at}>{new Date(entry.failed_at).toLocaleString()}</time>
        {entry.replayable ? <button type="button" className="secondary" disabled={busy}
          onClick={() => void replay(entry.id)}>Replay delivery</button> : <span>Replay unavailable</span>}
      </div>
    </article>)}
  </section>
}
