'use client'

import { useEffect, useState } from 'react'
import { db } from '../lib/data'

type Metrics = {
  period_start: string
  period_end: string
  shared_activity: { posts: number; contributors: number } | null
  meeting_quality: { join?: { samples: number; percent: number }; relay?: { samples: number; percent: number } }
  security_posture: { managed_rooms: number; protected_rooms: number; blocked_forwarding: number; archived_rooms: number }
}

function utcDate(value: string) {
  return new Intl.DateTimeFormat(undefined, { timeZone: 'UTC', month: 'short', day: 'numeric', year: 'numeric' })
    .format(new Date(value))
}

export function WorkspaceAnalytics({ workspace }: { workspace: string }) {
  const [metrics, setMetrics] = useState<Metrics | null>(null)
  const [error, setError] = useState('')
  const [refresh, setRefresh] = useState(0)

  useEffect(() => {
    let enabled = true
    async function load() {
      const result = await db!.rpc('st_v6_workspace_analytics', { p_workspace: workspace })
      if (!enabled) return
      if (result.error) {
        setMetrics(null)
        setError(result.error.code === '42501' ? 'Verify your authenticator in Profile → Security to view workspace analytics.'
          : 'Could not load workspace analytics.')
      } else {
        setMetrics(result.data as Metrics)
        setError('')
      }
    }
    void load()
    const timer = window.setInterval(() => { if (document.visibilityState === 'visible') void load() }, 30000)
    return () => { enabled = false; window.clearInterval(timer) }
  }, [workspace, refresh])

  return <section className="release-section" aria-labelledby="workspace-analytics-heading">
    <div className="panel-header">
      <h3 id="workspace-analytics-heading">Workspace analytics</h3>
      <button type="button" className="secondary" onClick={() => setRefresh(value => value + 1)}>Refresh analytics</button>
    </div>
    {error && <p role="alert" className="error">{error}</p>}
    {!error && !metrics && <p role="status">Loading workspace analytics…</p>}
    {metrics && <>
      <p>{utcDate(metrics.period_start)} through {utcDate(new Date(Date.parse(metrics.period_end) - 1).toISOString())} UTC</p>
      <div className="release-board">
        <article className="panel release-panel">
          <h4>Shared activity and adoption</h4>
          {metrics.shared_activity ? <>
            <p>{metrics.shared_activity.posts}+ shared posts</p>
            <p>{metrics.shared_activity.contributors}+ contributing members</p>
          </> : <p>Activity totals are withheld for small groups.</p>}
        </article>
        <article className="panel release-panel">
          <h4>Meeting call quality</h4>
          {metrics.meeting_quality.join ? <p>{metrics.meeting_quality.join.percent}% connected across
            {' '}{metrics.meeting_quality.join.samples}+ sampled joins</p> : <p>Join rates are withheld for small groups.</p>}
          {metrics.meeting_quality.relay && <p>{metrics.meeting_quality.relay.percent}% of sampled connections used a relay</p>}
        </article>
        <article className="panel release-panel">
          <h4>Current security posture</h4>
          <ul>
            <li>{metrics.security_posture.managed_rooms} visible rooms</li>
            <li>{metrics.security_posture.protected_rooms} classified Confidential or Restricted</li>
            <li>{metrics.security_posture.blocked_forwarding} with forwarding disabled</li>
            <li>{metrics.security_posture.archived_rooms} archived</li>
          </ul>
        </article>
      </div>
    </>}
  </section>
}
