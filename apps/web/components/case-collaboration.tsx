'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'
import { downloadChatFile, type ChatFile } from '../lib/chat-files'

type Note = {id: string; author_name: string; body: string; created_at: string; has_message: boolean; has_file: boolean}
type Collaboration = {may_link_message: boolean; may_link_file: boolean; notes: Note[]}
type Mention = {report_id: string; note_id: string; created_at: string; read_at: string | null}

function CollaborationDate({value}: {value: string}) {
  return <time dateTime={value}>{new Date(value).toLocaleString()}</time>
}

export function CaseCollaboration({report}: {report: string}) {
  const [collaboration, setCollaboration] = useState<Collaboration | null>(null)
  const [error, setError] = useState('')
  const [feedback, setFeedback] = useState('')
  const [busy, setBusy] = useState(false)
  const [opened, setOpened] = useState<{note: string; excerpt: string} | null>(null)
  const pending = useRef<{key: string; id: string} | null>(null)
  const version = useRef(0)
  const load = useCallback(async () => {
    const request = ++version.current
    const result = await db!.rpc('st_v6_case_collaboration', {p_report: report})
    if (request !== version.current) return
    if (result.error) {
      setCollaboration(null)
      setOpened(null)
      setError('Case collaboration is unavailable.')
    } else {
      setCollaboration(result.data as Collaboration)
      setError('')
    }
  }, [report])

  useEffect(() => {
    void load()
    const timer = window.setInterval(load, 15000)
    return () => { ++version.current;window.clearInterval(timer) }
  }, [load])

  async function post(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    const form = event.currentTarget
    const values = new FormData(form)
    const body = String(values.get('staff-note') ?? '').trim()
    const message = values.has('shared-message')
    const file = values.has('shared-file')
    const key = JSON.stringify([body, message, file])
    if (pending.current?.key !== key) pending.current = {key, id: crypto.randomUUID()}
    setBusy(true)
    setError('')
    setFeedback('')
    const result = await db!.rpc('st_v6_append_case_note', {
      p_report: report, p_note: pending.current.id, p_body: body, p_link_message: message, p_link_file: file,
    })
    if (result.error) setError(formatError(result.error, 'Could not add the staff note.'))
    else {
      pending.current = null
      form.reset()
      await load()
      setFeedback('Staff note added.')
    }
    setBusy(false)
  }

  async function openEvidence(note: string, kind: 'message' | 'file') {
    if (busy) return
    setBusy(true)
    setError('')
    try {
      const result = await db!.rpc('st_v6_case_note_evidence', {p_report: report, p_note: note, p_kind: kind})
      if (result.error) throw result.error
      if (kind === 'file') await downloadChatFile(result.data as ChatFile)
      else setOpened({note, excerpt: result.data.excerpt as string})
    } catch {
      setOpened(null)
      setError('The linked evidence is unavailable.')
    } finally { setBusy(false) }
  }

  return <section className="release-section" aria-label="Case collaboration">
    <h3>Case collaboration</h3>
    <p>Posted staff notes are read-only. Use @handle to mention up to five eligible staff.</p>
    {!collaboration && !error && <p role="status">Loading staff notes…</p>}
    {error && <p role="alert" className="error">{error}</p>}
    {feedback && <p role="status">{feedback}</p>}
    {collaboration && <>
      <form className="release-form" onSubmit={post}>
        <label>Staff note<textarea name="staff-note" required maxLength={2000} rows={4} disabled={busy}/></label>
        {collaboration.may_link_message && <label className="task-check">
          <input name="shared-message" type="checkbox" disabled={busy}/> Link shared message evidence
        </label>}
        {collaboration.may_link_file && <label className="task-check">
          <input name="shared-file" type="checkbox" disabled={busy}/> Link shared attachment
        </label>}
        <button type="submit" className="secondary" disabled={busy}>Add staff note</button>
      </form>
      {collaboration.notes.length === 0 && <p>No staff notes yet.</p>}
      {collaboration.notes.map(note => <article className="release-board-item" key={note.id}>
        <div className="release-row"><strong>{note.author_name}</strong><CollaborationDate value={note.created_at}/></div>
        <p className="case-text">{note.body}</p>
        {(note.has_message || note.has_file) && <div className="actions">
          {note.has_message && <button type="button" className="secondary" disabled={busy}
            onClick={() => void openEvidence(note.id, 'message')}>Open linked message evidence</button>}
          {note.has_file && <button type="button" className="secondary" disabled={busy}
            onClick={() => void openEvidence(note.id, 'file')}>Download linked evidence</button>}
        </div>}
        {opened?.note === note.id && note.has_message && <blockquote>{opened.excerpt}</blockquote>}
      </article>)}
    </>}
  </section>
}

export function CaseCollaborationAlerts({open}: {open: (report: string) => Promise<boolean>}) {
  const [mentions, setMentions] = useState<Mention[] | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const version = useRef(0)
  const load = useCallback(async () => {
    const request = ++version.current
    const result = await db!.rpc('st_v6_case_collaboration_alerts', {p_unread_only: false})
    if (request !== version.current) return
    if (result.error) {
      setMentions(null)
      setError('Could not load your case mentions.')
    } else {
      setMentions(result.data as Mention[])
      setError('')
    }
  }, [])

  useEffect(() => {
    void load()
    const timer = window.setInterval(load, 15000)
    return () => { ++version.current;window.clearInterval(timer) }
  }, [load])

  async function openMention(mention: Mention) {
    if (busy) return
    setBusy(true)
    if (await open(mention.report_id) && !mention.read_at) {
      await db!.rpc('st_v6_read_case_collaboration_alert', {p_report: mention.report_id, p_note: mention.note_id})
    }
    setBusy(false)
  }

  return <section className="release-section" aria-label="Case mentions">
    <h3>Case mentions</h3>
    {error && <p role="alert" className="error">{error}</p>}
    {!mentions && !error && <p role="status">Loading case mentions…</p>}
    {mentions?.length === 0 && <p>No case mentions.</p>}
    {mentions?.map(mention => <article className="release-board-item" key={mention.report_id + mention.note_id}>
      <div className="release-row">
        {!mention.read_at && <span className="status-dot" aria-label="Unread"/>}
        <p>Mention in a staff case note</p><CollaborationDate value={mention.created_at}/>
        <button type="button" className="secondary" disabled={busy} onClick={() => void openMention(mention)}>Open case</button>
      </div>
    </article>)}
  </section>
}
