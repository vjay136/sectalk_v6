'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'
import { meetingLink } from '../lib/meeting-calendar'

type Call = { id: string; title: string; starts_at: string; live: boolean; roster: string[]; your_status: string | null }
type State = { can_start: boolean; calls: Call[] }

export function RoomCalls({ room }: { room: string }) {
  const [state, setState] = useState<State | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const pending = useRef<{ title: string; id: string } | null>(null)
  const load = useCallback(async (signal?: AbortSignal) => {
    const request = db!.rpc('st_v6_room_calls', { p_room: room })
    const { data, error } = await (signal ? request.abortSignal(signal) : request)
    if (signal?.aborted) return
    if (error || !data) {
      setState(null)
      setError('Could not load room calls.')
    } else setState(data as State)
  }, [room])

  useEffect(() => {
    const controller = new AbortController()
    void load(controller.signal)
    const timer = window.setInterval(() => void load(controller.signal), 5000)
    return () => {
      controller.abort()
      window.clearInterval(timer)
    }
  }, [load])

  async function start(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy || !state?.can_start || state.calls.some(call => call.live)) return
    const form = event.currentTarget
    const title = String(new FormData(form).get('title') || '').trim()
    if (pending.current?.title !== title) pending.current = { title, id: crypto.randomUUID() }
    setBusy(true)
    setError('')
    try {
      const { error } = await db!.rpc('st_v6_start_room_call', { p_room: room, p_id: pending.current.id, p_title: title })
      if (error) throw error
      pending.current = null
      form.reset()
      await load()
    } catch (failure) {
      setError(formatError(failure, 'Could not start this room call.'))
    } finally {
      setBusy(false)
    }
  }

  return <section className="release-section" aria-label="Room calls">
    <h2>Room calls</h2>
    {state?.can_start && !state.calls.some(call => call.live) && <form className="release-form" onSubmit={start}>
      <label>Room call title<input name="title" maxLength={100}/></label>
      <button className="primary" disabled={busy}>Start room call</button>
    </form>}
    {!state && !error && <p role="status">Loading room calls…</p>}
    {error && <p role="alert" className="error">{error}</p>}
    {state?.calls.length === 0 && <p>No room calls yet.</p>}
    {state?.calls.map(call => <article key={call.id} className="release-board-item">
      <h3>{call.title}</h3>
      <p>{call.live ? 'Live' : 'Ended'} · <time dateTime={call.starts_at}>{new Date(call.starts_at).toLocaleString()}</time></p>
      {call.live && <>
        <p>Admitted: {call.roster.length ? call.roster.join(', ') : 'Nobody yet'}</p>
        {call.your_status && <p>Your status: {call.your_status}</p>}
        <a href={meetingLink(window.location.origin, call.id)}>Open room call</a>
      </>}
    </article>)}
  </section>
}
