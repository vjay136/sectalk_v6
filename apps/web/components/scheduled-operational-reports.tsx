'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'
import {useSensitiveAction} from './sensitive-action'

type Cadence = 'daily' | 'weekly'
type Run = {id: string; cadence: Cadence; period_end: string; state: 'pending' | 'sent' | 'failed' | 'cancelled'}
type Settings = {available: boolean; active: boolean; cadence: Cadence; next_at: string | null; runs: Run[]}
const statuses: Record<Run['state'], string> = {
  pending: 'Email pending', sent: 'Email accepted', failed: 'Email delivery failed', cancelled: 'Email cancelled',
}

export function ScheduledOperationalReports() {
  const {authorize,confirmation}=useSensitiveAction()
  const [settings, setSettings] = useState<Settings | null>(null)
  const [configured, setConfigured] = useState(false)
  const [cadence, setCadence] = useState<Cadence>('daily')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const requestVersion = useRef(0)
  const load = useCallback(async () => {
    const request = ++requestVersion.current
    const [result, mail] = await Promise.all([
      db!.rpc('st_v6_operational_report_settings'),
      fetch('/api/operational-reports/drain', {cache: 'no-store'})
        .then(response => response.json()).catch(() => null),
    ])
    if (request !== requestVersion.current) return
    if (result.error || !result.data) {
      setSettings(null)
      setError(result.error?.code === '42501' ? 'Verify your staff authenticator to manage scheduled reports.'
        : 'Could not load scheduled reports.')
      return
    }
    const snapshot = result.data as Settings
    setSettings(snapshot)
    setCadence(snapshot.cadence)
    setConfigured(mail?.available === true)
    setError('')
  }, [])

  useEffect(() => {
    void load()
    return () => { ++requestVersion.current }
  }, [load])

  async function save(active: boolean) {
    if (busy) return
    setBusy(true)
    setError('')
    setNotice('')
    const {error} = await db!.rpc('st_v6_set_operational_report', {p_cadence: cadence, p_active: active})
    if (error) setError(formatError(error, 'Could not update your report schedule.'))
    else {
      await load()
      setNotice(active ? 'Report schedule saved.' : 'Report schedule paused.')
    }
    setBusy(false)
  }

  async function download(run: Run) {
    if (busy) return
    setBusy(true)
    setError('')
    try {
      const {data} = await db!.auth.getSession()
      if (!data.session) throw new Error()
      const response = await fetch('/api/operational-reports/export?run=' + encodeURIComponent(run.id), {
        headers: {Authorization: 'Bearer ' + data.session.access_token}, cache: 'no-store',
      })
      if (!response.ok) throw new Error()
      const url = URL.createObjectURL(await response.blob())
      const link = document.createElement('a')
      link.href = url
      link.download = 'sectalk-' + run.cadence + '-operational-report.csv'
      link.click()
      window.setTimeout(() => URL.revokeObjectURL(url), 1000)
    } catch { setError('Could not download this operational report.') }
    finally { setBusy(false) }
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (configured && settings?.available) void save(true)
  }

  return <section className="release-section" aria-label="Scheduled operational reports">
    {confirmation}
    <div className="panel-header">
      <h3>Scheduled operational reports</h3>
      <button type="button" className="secondary" disabled={busy} onClick={() => void load()}>Refresh reports</button>
    </div>
    <p>Receive aggregate request counts and latency bands at your verified profile email. Operations with fewer than ten requests are omitted.</p>
    {!settings && !error && <p role="status">Loading scheduled reports…</p>}
    {settings && <>
      <form className="release-form" onSubmit={submit}>
        <label>Frequency<select value={cadence} disabled={busy} onChange={event => setCadence(event.target.value as Cadence)}>
          <option value="daily">Daily</option><option value="weekly">Weekly</option>
        </select></label>
        <div className="actions">
          <button type="submit" className="secondary" disabled={busy || !settings.available || !configured}>Save report schedule</button>
          {settings.active && <button type="button" className="secondary" disabled={busy} onClick={() => void save(false)}>Pause reports</button>}
        </div>
      </form>
      {!settings.available && <p role="status">Verify your current profile email to schedule reports.</p>}
      {!configured && <p role="status">Scheduled email delivery is unavailable.</p>}
      {settings.next_at && <p>Next report <time dateTime={settings.next_at}>{new Date(settings.next_at).toLocaleString()}</time></p>}
      {settings.runs.length === 0 && <p>No scheduled reports have been generated.</p>}
      {settings.runs.map(run => <article className="release-board-item" key={run.id}>
        <div className="release-row">
          <strong>{run.cadence === 'weekly' ? 'Weekly report' : 'Daily report'}</strong>
          <time dateTime={run.period_end}>{new Date(run.period_end).toLocaleString()}</time>
          <span>{statuses[run.state]}</span>
          <button className="secondary" type="button" disabled={busy} onClick={() => void authorize('export',()=>download(run))}>Download CSV</button>
        </div>
      </article>)}
    </>}
    {notice && <p role="status">{notice}</p>}
    {error && <p role="alert" className="error">{error}</p>}
  </section>
}
