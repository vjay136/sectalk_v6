'use client'

import { useEffect, useState, type FormEvent } from 'react'
import { db } from '../lib/data'
import { SectionTabs } from './section-tabs'
import styles from './threat-map.module.css'

type Event = 'high_risk_sign_in' | 'step_up_requested' | 'session_terminated'
type Aggregate = { event: Event; accounts_floor: number }
type Cell = Aggregate & { latitude_band: number; longitude_band: number }
type Network = Aggregate & { asn: number }
type MapData = { day: string; minimum_accounts: number; cells: Cell[]; networks: Network[] }

const events: [Event, string][] = [
  ['high_risk_sign_in', 'Risky sign-ins'], ['step_up_requested', 'Verification requested'], ['session_terminated', 'Sessions ended'],
]

function utcDay(daysAgo: number) {
  const day = new Date()
  day.setUTCDate(day.getUTCDate() - daysAgo)
  return day.toISOString().slice(0, 10)
}

function coordinate(value: number, positive: string, negative: string) {
  return value === 0 ? '0°' : `${Math.abs(value)}° ${value > 0 ? positive : negative}`
}

function bounds(band: number, start: number, positive: string, negative: string) {
  const from = start + band * 20
  return `${coordinate(from, positive, negative)} to ${coordinate(from + 20, positive, negative)}`
}

export function ThreatMap({ refreshAccess }: { refreshAccess: () => Promise<void> }) {
  const [latestDay] = useState(() => utcDay(1))
  const [firstDay] = useState(() => utcDay(14))
  const [day, setDay] = useState(latestDay)
  const [requested, setRequested] = useState({ day: latestDay })
  const [event, setEvent] = useState<Event>('high_risk_sign_in')
  const [map, setMap] = useState<MapData | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    const controller = new AbortController()
    setMap(null)
    setError('')
    void db!.rpc('st_v7_security_threat_map', { p_day: requested.day }).abortSignal(controller.signal).then(async result => {
      if (controller.signal.aborted) return
      if (result.error) {
        setError('Could not load threat aggregates for this date.')
        if (result.error.code === '42501') await refreshAccess()
      } else setMap(result.data as MapData)
    })
    return () => controller.abort()
  }, [requested, refreshAccess])

  function selectDay(form: FormEvent<HTMLFormElement>) {
    form.preventDefault()
    setRequested({ day })
  }

  const cells = map?.cells.filter(row => row.event === event) ?? []
  const networks = map?.networks.filter(row => row.event === event) ?? []

  return <section className="panel release-panel" aria-label="Threat map">
    <h2>Threat map</h2>
    <p>Coarse geographic and network counts for completed UTC days. Each result represents at least five accounts and is rounded down to a multiple of five.</p>
    <form className="release-form" onSubmit={selectDay}>
      <label>UTC date<input type="date" value={day} min={firstDay} max={latestDay} required onChange={input => setDay(input.target.value)} /></label>
      <button type="submit" className="secondary">View date</button>
    </form>
    <SectionTabs label="Threat events" value={event} onChange={setEvent} options={events}/>
    {error && <p role="alert" className="error">{error}</p>}
    {!map && !error && <p role="status">Loading threat aggregates…</p>}
    {map && !cells.length && !networks.length && <p>No reportable aggregates for {map.day}.</p>}
    {cells.length > 0 && <>
      <h3>Geographic bands</h3>
      <div aria-hidden="true" className={styles.chart}>
        <span className={styles.top}>90° N</span><span className={styles.left}>180° W</span><span className={styles.right}>180° E</span>
        <span className={styles.bottom}>90° S</span>
        <div className={styles.grid}>
          {cells.map(cell => <span className={styles.cell} key={`${cell.latitude_band}:${cell.longitude_band}`}
            style={{ gridRow: 9 - cell.latitude_band, gridColumn: 1 + cell.longitude_band,
              opacity: Math.min(.95, .25 + cell.accounts_floor * .04) }} />)}
        </div>
      </div>
      <div className={styles.table}><table>
        <caption>Geographic cohorts for {map?.day}</caption>
        <thead><tr><th scope="col">Latitude</th><th scope="col">Longitude</th><th scope="col">At least this many accounts</th></tr></thead>
        <tbody>{cells.map(cell => <tr key={`${cell.latitude_band}:${cell.longitude_band}`}>
          <td>{bounds(cell.latitude_band, -90, 'N', 'S')}</td><td>{bounds(cell.longitude_band, -180, 'E', 'W')}</td>
          <td>{cell.accounts_floor}</td>
        </tr>)}</tbody>
      </table></div>
    </>}
    {networks.length > 0 && <div className={styles.table}><table>
      <caption>Network cohorts for {map?.day}</caption>
      <thead><tr><th scope="col">Autonomous system</th><th scope="col">At least this many accounts</th></tr></thead>
      <tbody>{networks.map(network => <tr key={network.asn}><td>AS{network.asn}</td><td>{network.accounts_floor}</td></tr>)}</tbody>
    </table></div>}
  </section>
}
