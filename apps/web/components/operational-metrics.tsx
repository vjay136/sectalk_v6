'use client'

import { useEffect, useState } from 'react'
import { db } from '../lib/data'
import { SectionTabs } from './section-tabs'
import styles from './operational-metrics.module.css'

const operations = {
  file_upload: 'Upload attachment',
  file_publish: 'Publish attachment',
  file_download_grant: 'Authorize download',
  file_download: 'Download attachment',
  call_ice: 'Direct call network setup',
  meeting_token: 'Meeting media token',
  billing_action: 'Billing action',
  billing_webhook: 'Billing webhook',
}

type Window = '1h' | '24h' | '7d'
type Rollup = {
  operation: keyof typeof operations
  requests: number
  client_errors: number
  server_errors: number
  throttled: number
  unavailable: number
  peak_in_flight: number
  p50_band: number
  p95_band: number
}

const bands = [25, 50, 100, 250, 500, 1000, 2500, 5000]
const latency = (band: number) => band > bands.length ? '> 5,000 ms' : '≤ ' + bands[band - 1]?.toLocaleString() + ' ms'

export function OperationalMetrics() {
  const [window, setWindow] = useState<Window>('1h')
  const [result, setResult] = useState<{ window: Window; rows: Rollup[] | null } | null>(null)
  const [attempt, refresh] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    void db!.rpc('st_v6_operational_metrics', { p_window: window }).abortSignal(controller.signal)
      .then(({ data, error }) => {
        if (!controller.signal.aborted) setResult({ window, rows: error ? null : data as Rollup[] })
      })
    return () => controller.abort()
  }, [window, attempt])

  const current = result?.window === window ? result : null
  return <section className="panel release-panel" aria-labelledby="operational-metrics-title">
    <div className="panel-header">
      <h2 id="operational-metrics-title">Operational metrics</h2>
      <button type="button" className="secondary" onClick={() => refresh(value => value + 1)}>Refresh operations</button>
    </div>
    <SectionTabs label="Operational metrics period" value={window} onChange={setWindow}
      options={ [['1h', '1 hour'], ['24h', '24 hours'], ['7d', '7 days']] }/>
    <p>Latency bands show server handler time. Peak concurrency is the highest number of tracked handlers observed
      at once in one app instance. HTTP 429 and 503 responses indicate throttling or service unavailability.</p>
    {!current && <p role="status">Loading operational metrics…</p>}
    {current && !current.rows && <p role="alert" className="error">Could not load operational metrics.</p>}
    {current?.rows?.length === 0 && <p role="status">No operational samples were recorded in this period.</p>}
    {!!current?.rows?.length && <div className={styles.scroll}>
      <table className={styles.table} aria-label="Server request aggregates">
        <thead><tr>
          <th scope="col">Operation</th><th scope="col">Requests</th><th scope="col">p50 latency</th><th scope="col">p95 latency</th>
          <th scope="col">4xx</th><th scope="col">5xx</th><th scope="col">429</th><th scope="col">503</th>
          <th scope="col">Peak concurrency</th>
        </tr></thead>
        <tbody>{current.rows.map(row => <tr key={row.operation}>
          <th scope="row">{operations[row.operation]}</th><td>{row.requests.toLocaleString()}</td>
          <td>{latency(row.p50_band)}</td><td>{latency(row.p95_band)}</td>
          <td>{row.client_errors.toLocaleString()}</td><td>{row.server_errors.toLocaleString()}</td>
          <td>{row.throttled.toLocaleString()}</td><td>{row.unavailable.toLocaleString()}</td>
          <td>{row.peak_in_flight.toLocaleString()}</td>
        </tr>)}</tbody>
      </table>
    </div>}
  </section>
}
