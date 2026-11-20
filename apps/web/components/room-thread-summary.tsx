'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { db } from '../lib/data'

type Status = { workspaceEnabled?: boolean; owner: boolean; policy: boolean; consented: boolean; revision: string | null }
type Summary = { revision: string; summary: string[]; actions: string[] }
type Action = 'view' | 'generate' | 'policy' | 'opt-in' | 'withdraw'
type Result = Status & { draft?: { summary: string[]; actions: string[] } }

export function RoomThreadSummary({ room, root }: { room: string; root: string }) {
  const [status, setStatus] = useState<Status | null>(null)
  const [draft, setDraft] = useState<Summary | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const commandVersion = useRef(0)
  const changing = useRef(false)

  const request = useCallback(async (action: Action, enabled?: boolean, signal?: AbortSignal): Promise<Result> => {
    const { data } = await db!.auth.getSession()
    if (!data.session) throw new Error('Sign in to open the thread summary.')
    const query = new URLSearchParams({ room, thread: root, action })
    if (enabled !== undefined) query.set('enabled', String(enabled))
    const result = await fetch('/api/rooms/thread-summary?' + query, {
      method: 'POST', headers: { Authorization: 'Bearer ' + data.session.access_token }, signal,
    })
    const value = await result.json().catch(() => null)
    if (!result.ok) throw new Error(value?.error || 'Thread summaries are unavailable.')
    return value as Result
  }, [room, root])

  const showingDraft = draft !== null
  useEffect(() => {
    const controller = new AbortController()
    async function refresh() {
      if (changing.current || document.visibilityState !== 'visible') return
      const version = commandVersion.current
      try {
        const signal = AbortSignal.any([controller.signal, AbortSignal.timeout(4000)])
        const current = await request('view', undefined, signal)
        if (controller.signal.aborted || version !== commandVersion.current) return
        setStatus(current)
        setDraft(previous => previous?.revision === current.revision ? previous : null)
      } catch {
        if (controller.signal.aborted || version !== commandVersion.current) return
        setStatus(null)
        setDraft(null)
        setError('Thread summary access could not be verified.')
      }
    }
    function visibilityChanged() {
      if (document.visibilityState === 'visible') void refresh()
      else setDraft(null)
    }
    void refresh()
    const timer = window.setInterval(() => void refresh(), showingDraft ? 5000 : 15000)
    document.addEventListener('visibilitychange', visibilityChanged)
    return () => {
      controller.abort()
      window.clearInterval(timer)
      document.removeEventListener('visibilitychange', visibilityChanged)
    }
  }, [request, showingDraft])

  async function run(action: Exclude<Action, 'view'>, enabled?: boolean) {
    if (changing.current) return
    changing.current = true
    commandVersion.current++
    setBusy(true)
    setError('')
    setDraft(null)
    try {
      const { draft: suggestion, ...current } = await request(action, enabled)
      setStatus(current)
      if (suggestion && current.revision && document.visibilityState === 'visible') {
        setDraft({ ...suggestion, revision: current.revision })
      }
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Thread summaries are unavailable.')
    } finally {
      changing.current = false
      setBusy(false)
    }
  }

  return <section className="release-section" aria-label="Thread summary">
    <h3>Thread summary</h3>
    {!status && !error && <p role="status">Checking thread summary access…</p>}
    {status?.owner && status.workspaceEnabled !== false && <button className="secondary" type="button" disabled={busy}
      onClick={() => void run('policy', !status.policy)}>
      {status.policy ? 'Disable workspace thread summaries' : 'Enable workspace thread summaries'}
    </button>}
    {status && !status.policy && <p>Thread summaries are off for this workspace.</p>}
    {status?.workspaceEnabled === false && status.consented && <button type="button" className="secondary"
      disabled={busy} onClick={() => void run('withdraw')}>Withdraw my posts</button>}
    {status?.policy && <>
      <p>Opt in to include your posts in this thread while your consent is active.</p>
      <button className="secondary" type="button" disabled={busy}
        onClick={() => void run(status.consented ? 'withdraw' : 'opt-in')}>
        {status.consented ? 'Withdraw my posts' : 'Opt in to this thread'}
      </button>
      {status.consented && <button className="secondary" type="button" disabled={busy}
        onClick={() => void run('generate')}>Generate thread summary</button>}
    </>}
    {busy && <p role="status">Working on the thread summary…</p>}
    {error && <p className="error" role="alert">{error}</p>}
    {draft && <div aria-label="Thread summary draft">
      {draft.summary.length > 0 && <ul>{draft.summary.map(item => <li key={item}>{item}</li>)}</ul>}
      {draft.actions.length > 0 && <><h4>Action items</h4><ul>{draft.actions.map(item => <li key={item}>{item}</li>)}</ul></>}
      {!draft.summary.length && !draft.actions.length && <p>No excerpts qualified for this draft.</p>}
    </div>}
  </section>
}
