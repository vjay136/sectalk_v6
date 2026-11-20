'use client'

import { useEffect, useState } from 'react'
import { db, onReconnect } from '../lib/data'
import { SectionTabs } from './section-tabs'
import { WorkspaceAnalytics } from './workspace-analytics'

type Snapshot = {
  plan: string; seat_limit: number; occupied: number; active: number
  pending_invites: number; expiring_links: number; access_requests: number; contributors: number | null
}

export function WorkspaceAdminOverview({ workspace }: { workspace: string }) {
  const [tab, setTab] = useState<'summary' | 'analytics'>('summary')
  return <>
    <SectionTabs label="Workspace overview tabs" value={tab} onChange={setTab}
      options={[['summary', 'Health and seats'], ['analytics', 'Analytics']]} />
    {tab === 'summary' ? <WorkspaceOverviewSnapshot workspace={workspace} /> : <WorkspaceAnalytics workspace={workspace} />}
  </>
}

function WorkspaceOverviewSnapshot({ workspace }: { workspace: string }) {
  const [data, setData] = useState<Snapshot | null>(null)
  const [health, setHealth] = useState<boolean | null>(null)
  const [error, setError] = useState('')
  const [refreshes, setRefreshes] = useState(0)

  useEffect(() => {
    let version = 0
    let active = true
    const controller = new AbortController()
    const load = async () => {
      const request = ++version
      const [metrics, ready] = await Promise.all([
        db!.rpc('st_v6_workspace_admin_overview', { p_workspace: workspace }),
        fetch('/api/ready', { signal: controller.signal, cache: 'no-store' })
          .then(async response => response.ok && (await response.json()).status === 'ready').catch(() => false),
      ])
      if (!active || request !== version) return
      setHealth(ready)
      if (metrics.error) {
        setData(null); setError('Could not load the workspace overview.')
      } else {
        setData(metrics.data as Snapshot); setError('')
      }
    }
    void load()
    const reconnect = onReconnect(load)
    const timer = window.setInterval(() => { if (document.visibilityState === 'visible') void load() }, 20000)
    return () => { active = false; controller.abort(); reconnect(); window.clearInterval(timer) }
  }, [workspace, refreshes])

  return <section className="release-section" aria-labelledby="ws-overview-heading">
    <div className="panel-header">
      <h2 id="ws-overview-heading">Workspace overview</h2>
      <button type="button" className="secondary" onClick={() => setRefreshes(value => value + 1)}>Refresh overview</button>
    </div>
    {error && <p role="alert" className="error">{error}</p>}
    {!data && !error && <p role="status">Loading workspace overview…</p>}
    <div className="release-board">
      <article className="panel release-panel">
        <h3>Service health</h3>
        <p>{health === null ? 'Checking service…' : health ? 'Ready' : 'Service readiness check failed'}</p>
      </article>
      {data && <>
      <article className="panel release-panel">
        <h3>Workspace seats</h3>
        <p><strong>{data.occupied} of {data.seat_limit}</strong> seats occupied</p>
        <p>{data.active} active member{data.active === 1 ? '' : 's'} · {data.plan.replace(/^[a-z]/, char => char.toUpperCase())} plan</p>
        {data.occupied >= data.seat_limit && <p role="status">Seat limit reached.</p>}
      </article>
      <article className="panel release-panel">
        <h3>Alerts</h3>
        <ul>
          <li>{data.pending_invites} pending invitation{data.pending_invites === 1 ? '' : 's'}</li>
          <li>{data.expiring_links} invitation {data.expiring_links === 1 ? 'link expires' : 'links expire'} within 24 hours</li>
          <li>{data.access_requests} room access request{data.access_requests === 1 ? '' : 's'}</li>
        </ul>
      </article>
      <article className="panel release-panel">
        <h3>Weekly adoption</h3>
        {data.contributors === null ? <p>Activity totals are withheld for small groups.</p> :
          <p><strong>{data.contributors} of {data.active}</strong> active members posted in shared rooms or channels in the past seven days.</p>}
      </article>
      </>}
    </div>
  </section>
}
