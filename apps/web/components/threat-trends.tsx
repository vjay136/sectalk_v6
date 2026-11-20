'use client'

import { useEffect, useState } from 'react'
import { categories, db } from '../lib/data'
import { SecurityReports } from './security-reports'
import styles from './threat-trends.module.css'

type Category = keyof typeof categories
type Week = { week_start: string; reports: number | null; actioned: number | null }
const dateFormat = new Intl.DateTimeFormat(undefined, {
  month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC',
})

function Count({ value, maximum, actioned = false }: { value: number | null; maximum: number; actioned?: boolean }) {
  if (value === null) return <span className="muted">Below threshold</span>
  return <div className={styles.count}>
    <strong>{value.toLocaleString()}</strong>
    <meter aria-hidden="true" tabIndex={-1} min={0} max={maximum} value={value}
      className={actioned ? styles.actioned : styles.filed}/>
  </div>
}

export function ThreatTrends() {
  const [category, setCategory] = useState<Category>('threat')
  const [result, setResult] = useState<{ category: Category; weeks: Week[] | null } | null>(null)
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    const request = new AbortController()
    void db!.rpc('st_v6_threat_trends', { p_category: category }).abortSignal(request.signal).then(({ data, error }) => {
      if (!request.signal.aborted) setResult({ category, weeks: error ? null : data as Week[] })
    })
    return () => request.abort()
  }, [category, attempt])

  const current = result?.category === category ? result : null
  const maximum = Math.max(5, ...current?.weeks?.flatMap(({ reports, actioned }) => [reports ?? 0, actioned ?? 0]) ?? [])

  return <section className="panel release-panel" aria-labelledby="threat-trends-title">
    <div className="panel-header">
      <h2 id="threat-trends-title">Threat trends</h2>
      <button type="button" className="secondary" onClick={() => setAttempt(value => value + 1)}>Refresh trends</button>
    </div>
    <div className="release-flex"><label>Report category
      <select value={category} onChange={event => setCategory(event.target.value as Category)}>
        {Object.entries(categories).map(([key, label]) => <option key={key} value={key}>{label}</option>)}
      </select>
    </label></div>
    <p>Compare reports filed with reports that received a staff warning, suspension, restriction, or removal.
      Reports are allegations. Staff actions reflect moderation decisions.</p>
    <p className="muted">Counts require at least five different reporters and five different reported accounts.
      Eligible counts are rounded down to the nearest five.</p>
    {!current && <p role="status">Loading threat trends…</p>}
    {current && !current.weeks && <p role="alert" className="error">Could not load threat trends.</p>}
    {current?.weeks && <div className={styles.scroll}>
      <table className={styles.table}>
        <caption>{categories[category]} over the last eight complete UTC weeks</caption>
        <thead><tr><th scope="col">Week of</th><th scope="col">Reports filed</th><th scope="col">Reports with staff action</th></tr></thead>
        <tbody>{current.weeks.map(week => <tr key={week.week_start}>
          <th scope="row"><time dateTime={week.week_start}>{dateFormat.format(new Date(week.week_start))}</time></th>
          <td><Count value={week.reports} maximum={maximum}/></td>
          <td><Count value={week.actioned} maximum={maximum} actioned/></td>
        </tr>)}</tbody>
      </table>
    </div>}
    <SecurityReports/>
  </section>
}
