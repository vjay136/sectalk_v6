'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { db, liveChannel, onReconnect } from '../lib/data'
import { SectionTabs } from './section-tabs'

type Participant = { user_id: string; name: string; is_host: boolean }
type ChatMessage = { id: string; user_id: string; author_name: string; body: string; sent_at: string }
const tabs = [['participants', 'Participants'], ['chat', 'In-call chat']] as const

export function MeetingCollaboration({ meeting, user, host, setFocus }: {
  meeting: string; user: string; host: boolean; setFocus: (value: string | null) => void
}) {
  const [tab, setTab] = useState<'participants' | 'chat'>('participants')
  const [roster, setRoster] = useState<Participant[] | null>(null)
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [spotlight, setSpotlight] = useState<string | null>(null)
  const [localPin, setLocalPin] = useState<string | null>(null)
  const [draft, setDraft] = useState('')
  const [loadError, setLoadError] = useState(false)
  const [actionError, setActionError] = useState('')
  const [busy, setBusy] = useState(false)
  const version = useRef(0)
  const pendingMessage = useRef<{ id: string; body: string } | null>(null)
  const pinned = roster?.some(person => person.user_id === localPin) ? localPin : null
  const highlighted = roster?.some(person => person.user_id === spotlight) ? spotlight : null

  const reload = useCallback(async () => {
    const request = ++version.current
    const [participants, chat, controls] = await Promise.all([
      db!.rpc('st_v6_meeting_roster', { p_meeting: meeting }),
      db!.from('st_v6_meeting_chat').select('id,user_id,author_name,body,sent_at')
        .eq('meeting_id', meeting).order('sent_at', { ascending: false })
        .order('id', { ascending: false }).limit(100).returns<ChatMessage[]>(),
      db!.from('st_v6_meeting_controls').select('spotlight').eq('meeting_id', meeting).maybeSingle(),
    ])
    if (request !== version.current) return
    setLoadError(Boolean(participants.error || chat.error || controls.error))
    const people = participants.data as Participant[] | null
    setRoster(people)
    setMessages(chat.data?.reverse() ?? [])
    setSpotlight(controls.data?.spotlight ?? null)
    if (people) {
      setLocalPin(pin => people.some(person => person.user_id === pin) ? pin : null)
    }
  }, [meeting])

  useEffect(() => {
    const filter = { schema: 'public', filter: 'meeting_id=eq.' + meeting }
    const channel = liveChannel('meeting-collaboration:' + meeting, reload)
      .on('postgres_changes', { event: 'INSERT', table: 'st_v6_meeting_chat', ...filter }, reload)
      .on('postgres_changes', { event: 'INSERT', table: 'st_v6_meeting_controls', ...filter }, reload)
      .on('postgres_changes', { event: 'UPDATE', table: 'st_v6_meeting_controls', ...filter }, reload)
      .subscribe(status => { if (status === 'SUBSCRIBED') void reload() })
    void reload()
    const reconnect = onReconnect(reload)
    const timer = window.setInterval(reload, 5000)
    return () => {
      ++version.current
      reconnect()
      window.clearInterval(timer)
      void db!.removeChannel(channel)
    }
  }, [meeting, reload])

  useEffect(() => { setFocus(pinned ?? highlighted) }, [pinned, highlighted, setFocus])
  useEffect(() => () => setFocus(null), [setFocus])

  async function send(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const body = draft.trim()
    if (!body || busy) return
    setBusy(true)
    setActionError('')
    const message = pendingMessage.current?.body === body
      ? pendingMessage.current
      : { id: crypto.randomUUID(), body }
    pendingMessage.current = message
    try {
      const { error } = await db!.rpc('st_v6_send_meeting_chat', {
        p_meeting: meeting, p_id: message.id, p_body: message.body,
      })
      if (error) throw error
      pendingMessage.current = null
      setDraft('')
      await reload()
    } catch {
      setActionError('Could not send your message. Try again.')
    } finally {
      setBusy(false)
    }
  }

  async function changeSpotlight(participant: string | null) {
    if (busy) return
    setBusy(true)
    setActionError('')
    try {
      const { error } = await db!.rpc('st_v6_set_meeting_spotlight', { p_meeting: meeting, p_participant: participant })
      if (error) throw error
      await reload()
    } catch {
      setActionError('Could not update the spotlight. Check that the participant is still in the meeting.')
    } finally {
      setBusy(false)
    }
  }

  return <section className="release-section" aria-label="In-call collaboration">
    <SectionTabs label="In-call panels" value={tab} onChange={setTab} options={tabs}/>
    {loadError && <p role="alert" className="error">Could not load in-call information. SecTalk will retry automatically.</p>}
    {actionError && <p role="alert" className="error">{actionError}</p>}
    {tab === 'participants' && <section aria-label="Participants">
      {roster === null ? <p role="status">Loading participants…</p> : <ul className="meeting-participant-list">
        {roster.map(person => {
          const name = person.user_id === user ? 'you' : person.name
          const isPinned = pinned === person.user_id
          const isHighlighted = highlighted === person.user_id
          return <li className="release-row" key={person.user_id}>
            <strong>{person.name}{person.user_id === user ? ' (you)' : ''}</strong>
            {person.is_host && <span className="pill">Host</span>}
            {isHighlighted && <span className="pill">Spotlight</span>}
            <button className="secondary" type="button" aria-label={(isPinned ? 'Unpin ' : 'Pin ') + name}
              aria-pressed={isPinned} onClick={() => setLocalPin(isPinned ? null : person.user_id)}>{isPinned ? 'Unpin' : 'Pin'}</button>
            {host && <button className="secondary" type="button" disabled={busy}
              aria-label={isHighlighted ? 'Clear spotlight' : 'Spotlight ' + name}
              onClick={() => void changeSpotlight(isHighlighted ? null : person.user_id)}>
              {isHighlighted ? 'Clear spotlight' : 'Spotlight'}
            </button>}
          </li>
        })}
      </ul>}
    </section>}
    {tab === 'chat' && <section className="meeting-chat" aria-label="In-call chat">
      <div className="meeting-chat-log" role="log" aria-label="Meeting messages" aria-live="polite">
        {messages.length ? <ol>{messages.map(message => <li key={message.id}>
          <strong>{message.author_name}{message.user_id === user ? ' (you)' : ''}</strong>
          <time dateTime={message.sent_at}>{new Date(message.sent_at).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}</time>
          <p>{message.body}</p>
        </li>)}</ol> : <p>No meeting messages yet.</p>}
      </div>
      <form onSubmit={send} className="meeting-chat-form">
        <label>Message to meeting
          <input value={draft} onChange={event => setDraft(event.target.value)} maxLength={1000} disabled={!roster || busy}/>
        </label>
        <button className="primary" type="submit" disabled={!roster || busy || !draft.trim()}>Send message</button>
      </form>
    </section>}
  </section>
}
