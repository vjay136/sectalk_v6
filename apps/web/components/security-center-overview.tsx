'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { db } from '../lib/data'
import styles from './threat-trends.module.css'

type Average = {minutes: number; samples: number} | null
type Overview = {
  as_of: string
  open_cases: number
  reviewing_cases: number
  queue_depth: number
  open_incidents: number | null
  incident_scope: 'all' | 'assigned_or_created' | null
  trend: {week_start: string; reports: number | null}[]
  response_times: {since: string; until: string; acknowledgement: Average; resolution: Average}
}

const dateTime = new Intl.DateTimeFormat(undefined, {dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC'})
const date = new Intl.DateTimeFormat(undefined, {dateStyle: 'medium', timeZone: 'UTC'})

function duration(minutes: number) {
  if (minutes === 0) return 'Under 1 min'
  const days = Math.floor(minutes / 1440)
  const hours = Math.floor(minutes % 1440 / 60)
  const remainder = minutes % 60
  return [days ? days + ' d' : '', hours ? hours + ' h' : '', remainder ? remainder + ' min' : ''].filter(Boolean).join(' ')
}

function AverageTime({average}: {average: Average}) {
  if (!average) return <>Below threshold</>
  return <>{duration(average.minutes)} <small>({average.samples.toLocaleString()} cases)</small></>
}

export function SecurityCenterOverview() {
  const [overview, setOverview] = useState<Overview | null>(null)
  const [error, setError] = useState('')
  const requestVersion = useRef(0)
  const load = useCallback(async () => {
    const version = ++requestVersion.current
    const {data, error} = await db!.rpc('st_v6_security_center_overview')
    if (version !== requestVersion.current) return
    setOverview(error ? null : data as Overview)
    setError(error?.code === '42501' ? 'Verify your staff authenticator to view the security overview.'
      : error ? 'Could not load the security overview.' : '')
  }, [])

  useEffect(() => {
    void load()
    const timer = window.setInterval(load, 30000)
    return () => { ++requestVersion.current;window.clearInterval(timer) }
  }, [load])

  const maximum = Math.max(5, ...overview?.trend.map(week => week.reports ?? 0) ?? [])
  return <section className="panel release-panel" aria-label="Security overview">
    <div className="panel-header">
      <h2>Security overview</h2>
      <button type="button" className="secondary" onClick={() => void load()}>Refresh overview</button>
    </div>
    {!overview && !error && <p role="status">Loading security overview…</p>}
    {error && <p role="alert" className="error">{error}</p>}
    {overview && <>
      <p>As of <time dateTime={overview.as_of}>{dateTime.format(new Date(overview.as_of))} UTC</time></p>
      <dl className="activity-stats">
        <div><dt>Open cases</dt><dd>{overview.open_cases.toLocaleString()}</dd></div>
        <div><dt>Case queue depth</dt><dd>{overview.queue_depth.toLocaleString()}</dd><small>Open and under review</small></div>
        <div><dt>Open incidents</dt><dd>{overview.open_incidents?.toLocaleString() ?? 'Restricted'}</dd>
          {overview.incident_scope === 'assigned_or_created' && <small>Assigned to you or created by you</small>}
        </div>
      </dl>
      <h3>Moderation response times</h3>
      <p><time dateTime={overview.response_times.since}>{dateTime.format(new Date(overview.response_times.since))}</time>
        {' to '}<time dateTime={overview.response_times.until}>{dateTime.format(new Date(overview.response_times.until))} UTC</time>
        {' (past seven days)'}</p>
      <dl className="activity-stats">
        <div><dt>Mean time to acknowledge (MTTA)</dt><dd><AverageTime average={overview.response_times.acknowledgement}/></dd></div>
        <div><dt>Mean time to resolve (MTTR)</dt><dd><AverageTime average={overview.response_times.resolution}/></dd></div>
      </dl>
      <p>Elapsed time from filing to the first recorded review, escalation, enforcement, or closure. Resolution uses the first resolution or dismissal. Each average includes milestones reached in the period and requires at least five distinct reporters and five distinct reported accounts.</p>
      <h3>Risk trend</h3>
      <p>Reports filed across all categories in the last eight complete UTC weeks. Reports are allegations. Counts require five distinct reporters and five distinct reported accounts, then round down to the nearest five.</p>
      <div className={styles.scroll}><table className={styles.table}>
        <thead><tr><th scope="col">Week of</th><th scope="col">Reports filed</th></tr></thead>
        <tbody>{overview.trend.map(week => <tr key={week.week_start}>
          <th scope="row"><time dateTime={week.week_start}>{date.format(new Date(week.week_start))}</time></th>
          <td>{week.reports === null ? <span className="muted">Below threshold</span> : <div className={styles.count}>
            <strong>{week.reports.toLocaleString()}</strong>
            <meter className={styles.filed} min={0} max={maximum} value={week.reports} aria-hidden="true" tabIndex={-1}/>
          </div>}</td>
        </tr>)}</tbody>
      </table></div>
    </>}
  </section>
}
