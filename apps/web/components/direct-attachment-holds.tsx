'use client'

import { useEffect, useState, type FormEvent } from 'react'
import { db } from '../lib/data'

export type DirectHoldTarget = { file_id: string }
type Hold = { id: string; reason: string; placed_at: string; released_at: string | null; release_reason: string | null }

const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' })

export function DirectAttachmentHolds({ targets }: { targets: DirectHoldTarget[] }) {
  const [chosen, setChosen] = useState('')
  const [result, setResult] = useState<{ file: string; rows: Hold[] | null } | null>(null)
  const [revision, setRevision] = useState(0)
  const [working, setWorking] = useState(false)
  const [error, setError] = useState('')
  const file = targets.some(target => target.file_id === chosen) ? chosen : targets[0]?.file_id
  const current = result?.file === file ? result : null
  const active = current?.rows?.find(row => !row.released_at)

  useEffect(() => {
    if (!file) return
    const request = new AbortController()
    void db!.rpc('st_v6_direct_hold_history', { p_file: file }).abortSignal(request.signal)
      .then(({ data, error }) => {
        if (!request.signal.aborted) setResult({ file, rows: error ? null : data as Hold[] })
      })
    return () => request.abort()
  }, [file, revision])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!file || working) return
    const form = event.currentTarget
    const reason = String(new FormData(form).get('reason')).trim()
    setWorking(true)
    setError('')
    try {
      const request = active
        ? db!.rpc('st_v6_release_direct_file_hold', { p_file: file, p_hold: active.id, p_reason: reason })
        : db!.rpc('st_v6_place_direct_file_hold', { p_file: file, p_reason: reason })
      const { error } = await request
      if (error) setError(error.code === 'PT409' ? 'The attachment is unavailable or purge has started.' : 'Could not update the attachment hold.')
      else {
        form.reset()
        setRevision(value => value + 1)
      }
    } finally {
      setWorking(false)
    }
  }

  return <section className="panel release-panel" aria-labelledby="direct-holds-title">
    <h2 id="direct-holds-title">Attachment holds</h2>
    <p>Place or release a retention hold for an attachment assigned to you.</p>
    <label>Assigned attachment<select value={file || ''} disabled={working} onChange={event => {
      setChosen(event.target.value)
      setError('')
    }}>
      {targets.map(target => <option key={target.file_id} value={target.file_id}>{target.file_id}</option>)}
    </select></label>
    {!current && <p role="status">Loading attachment holds…</p>}
    {current && !current.rows && <p role="alert" className="error">Could not load attachment holds.</p>}
    {current?.rows && <form key={file + (active?.id || '')} onSubmit={submit}>
      <label>{active ? 'Reason for release' : 'Reason for hold'}
        <textarea name="reason" required minLength={4} maxLength={500} rows={3}/>
      </label>
      <button className="primary" disabled={working}>{active ? 'Release hold' : 'Place hold'}</button>
    </form>}
    {error && <p role="alert" className="error">{error}</p>}
    {!!current?.rows?.length && <ol className="audit">{current.rows.map(row => <li key={row.id}>
      <strong>{row.released_at ? 'Released hold' : 'Active hold'}</strong>
      <p>{row.reason}</p>
      <small>Placed <time dateTime={row.placed_at}>{dateFormat.format(new Date(row.placed_at))}</time></small>
      {row.released_at && <>
        <small>Released <time dateTime={row.released_at}>{dateFormat.format(new Date(row.released_at))}</time></small>
        <p>{row.release_reason}</p>
      </>}
    </li>)}</ol>}
  </section>
}
