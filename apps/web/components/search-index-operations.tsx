'use client'

import { useCallback, useEffect, useState } from 'react'
import { db } from '../lib/data'

type Operation = 'status' | 'backfill' | 'rebuild' | 'process'
type State = { pending: number; mode: 'backfill' | 'rebuild' | null; finished_at: string | null; processed: number | null; scanned: number | null }

export function SearchIndexOperations({ onAccessChanged }: { onAccessChanged: () => Promise<void> }) {
  const [state, setState] = useState<State>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const run = useCallback(async (action: Operation) => {
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const result = await db!.rpc('st_v7_search_index_operation', { p_action: action })
      if (result.error || !result.data) {
        setState(undefined)
        if (result.error?.code === '42501') await onAccessChanged()
        setError('The managed search index operation could not be completed.')
        return
      }
      const latest = result.data as State
      setState(latest)
      if (action === 'process') setNotice('Processed ' + latest.processed + ' queued updates and scanned ' + latest.scanned + ' sources.')
    } catch {
      setError('The managed search index operation could not be completed.')
    } finally {
      setBusy(false)
    }
  }, [onAccessChanged])

  useEffect(() => { void run('status') }, [run])

  return <section aria-label="Managed search index">
    <div className="panel-header"><h3>Managed search index</h3>
      <button className="secondary" type="button" disabled={busy} onClick={() => void run('status')}>Refresh search index status</button>
    </div>
    {state && <>
      <p role="status">{state.pending} queued updates. {state.mode === 'backfill' ? 'Backfill in progress.' :
        state.mode === 'rebuild' ? 'Rebuild in progress.' : 'No scan in progress.'}</p>
      {state.finished_at && <p>Last scan finished <time dateTime={state.finished_at}>{new Date(state.finished_at).toLocaleString()}</time>.</p>}
      <div className="actions">
        <button className="secondary" type="button" disabled={busy || state.mode !== null}
          onClick={() => void run('backfill')}>Backfill missing entries</button>
        <button className="secondary" type="button" disabled={busy || state.mode !== null}
          onClick={() => void run('rebuild')}>Rebuild managed search</button>
        <button className="secondary" type="button" disabled={busy} onClick={() => void run('process')}>Process search batch</button>
      </div>
    </>}
    {notice && <p role="status">{notice}</p>}
    {error && <p role="alert">{error}</p>}
  </section>
}
