'use client'

import { useEffect, useState } from 'react'
import { db } from '../lib/data'

type Objective = { total: number; good: number; target: number }
type DeliveryQueue = { depth: number; oldest_seconds: number; dead_letters: number }
type QueueHealth = {
  through: string
  queues: { web_push: DeliveryQueue; email: DeliveryQueue }
  slo: { availability: Objective; handler_latency: Objective & { threshold_ms: number } }
}

function ObjectiveRow({ name, objective }: { name: string; objective: Objective }) {
  const percentage = objective.total > 0 ? 100 * objective.good / objective.total : null
  return <tr>
    <th scope="row">{name}</th>
    <td>{objective.target}%</td>
    <td>{percentage === null ? 'No samples' : percentage.toFixed(2) + '%'}</td>
    <td>{objective.total.toLocaleString()}</td>
    <td>{percentage === null ? 'Waiting for data' : percentage >= objective.target ? 'Meeting target' : 'Below target'}</td>
  </tr>
}

export function QueueHealthPanel({ onAccessChanged }: { onAccessChanged: () => Promise<void> }) {
  const [health, setHealth] = useState<QueueHealth | null>(null)
  const [ready, setReady] = useState<boolean | null>(null)
  const [error, setError] = useState('')
  const [revision, setRevision] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    async function refresh() {
      const [snapshot, availability] = await Promise.all([
        db!.rpc('st_v6_platform_queue_health').abortSignal(controller.signal),
        fetch('/api/ready', { cache: 'no-store', signal: controller.signal }).then(response => response.ok, () => false),
      ])
      if (controller.signal.aborted) return
      setReady(availability)
      setHealth(snapshot.error ? null : snapshot.data as QueueHealth)
      setError(snapshot.error ? 'Could not load queue health.' : '')
      if (snapshot.error?.code === '42501') void onAccessChanged()
    }
    void refresh()
    const interval = window.setInterval(() => void refresh(), 30000)
    return () => {
      controller.abort()
      window.clearInterval(interval)
    }
  }, [onAccessChanged, revision])

  return <section aria-label="Service health and SLOs">
    <div className="panel-header"><h3>Service health</h3>
      <button type="button" className="secondary" onClick={() => setRevision(current => current + 1)}>Refresh service health</button>
    </div>
    <p role="status">API and database readiness {ready === null ? 'checking' : ready ? 'ready' : 'degraded'}.</p>
    {error && <p role="alert" className="error">{error}</p>}
    {!health && !error && <p role="status">Loading queue depth and objectives…</p>}
    {health && <>
      <h3>Delivery backlog</h3>
      <div className="release-board">
        {([['web_push', 'Browser push'], ['email', 'Email']] as const).map(([channel, title]) => {
          const queue = health.queues[channel]
          return <article className="release-board-item" aria-label={title} key={channel}>
            <h4>{title}</h4>
            <p>{queue.depth.toLocaleString()} pending · {queue.dead_letters.toLocaleString()} dead letters in 7 days</p>
            {queue.depth > 0 && <p>Oldest pending for {Math.floor(queue.oldest_seconds / 60).toLocaleString()} minutes</p>}
          </article>
        })}
      </div>
      <h3>Service objectives</h3>
      <p>Tracked server requests in the last completed 24 hours, through <time dateTime={health.through}>{new Date(health.through).toLocaleString()}</time>.</p>
      <div className="table-scroll" tabIndex={0} aria-label="Service objectives table">
        <table aria-label="Service objectives">
          <thead><tr><th scope="col">Objective</th><th scope="col">Target</th><th scope="col">Observed</th>
            <th scope="col">Requests</th><th scope="col">State</th></tr></thead>
          <tbody>
            <ObjectiveRow name="Request availability" objective={health.slo.availability}/>
            <ObjectiveRow name={`Handler time ≤ ${health.slo.handler_latency.threshold_ms} ms`} objective={health.slo.handler_latency}/>
          </tbody>
        </table>
      </div>
      <p>Availability excludes regular client errors and counts rate limits and server errors against the target.</p>
    </>}
  </section>
}
