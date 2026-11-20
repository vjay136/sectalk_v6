'use client'

import { useCallback, useEffect, useState } from 'react'
import { db, formatError } from '../lib/data'
import type { Feature } from '../lib/use-feature'
import { StaffMfa } from './staff-mfa'

type Decision = {
  feature: Feature; paused: boolean; entitled: boolean; release_allowed: boolean;
  emergency_stop: boolean; effective: boolean; can_change: boolean
}
type State = { verified: boolean; features: Decision[] }
const names: Record<Feature, string> = {
  task_creation: 'Room task creation',
  recurring_meetings: 'Recurring meetings',
  integration_api: 'Workspace API',
}

function reason(feature: Decision) {
  if (feature.emergency_stop) return 'Stopped by a platform emergency rule.'
  if (!feature.entitled) return 'Requires a Team or Enterprise workspace plan.'
  if (feature.paused) return 'Paused by a workspace administrator.'
  if (!feature.release_allowed) return 'Unavailable under the current release rules.'
  return feature.feature === 'integration_api' ? 'Available for authorized API credentials.' : 'Available to your account.'
}

export function WorkspaceFeatures({ workspace }: { workspace: string }) {
  const [state, setState] = useState<State | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [verifying, setVerifying] = useState(false)

  const load = useCallback(async () => {
    const result = await db!.rpc('st_v6_tenant_feature_state', { p_workspace: workspace })
    if (result.error || !result.data) {
      setState(null)
      setError('Could not load workspace feature controls.')
      return
    }
    setState(result.data as State)
    if (result.data.verified) setVerifying(false)
  }, [workspace])

  useEffect(() => {
    void load()
    const timer = window.setInterval(() => {
      if (document.visibilityState === 'visible') void load()
    }, 10000)
    return () => window.clearInterval(timer)
  }, [load])

  async function save(feature: Decision) {
    if (busy || !feature.can_change) return
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const result = await db!.rpc('st_v6_set_tenant_feature_pause', {
        p_workspace: workspace, p_feature: feature.feature, p_paused: !feature.paused,
      })
      if (result.error) throw result.error
      await load()
      setNotice(feature.paused ? 'Inherited access restored.' : 'Workspace feature paused.')
    } catch (failure) {
      setError(formatError(failure, 'Could not change the workspace feature.'))
    } finally {
      setBusy(false)
    }
  }

  return <section className="release-section" aria-label="Workspace features">
    <h2>Workspace features</h2>
    {error && <p className="error" role="alert">{error}</p>}
    {notice && <p role="status">{notice}</p>}
    {!state && !error && <p role="status">Loading workspace feature controls…</p>}
    {state && !state.verified && (!verifying
      ? <button className="secondary" type="button" onClick={() => setVerifying(true)}>Verify to change features</button>
      : <StaffMfa refresh={load} explanation="Verify your authenticator to change workspace feature settings."/>)}
    {state?.features.map(feature => <article key={feature.feature} className="release-board-item">
      <h3>{names[feature.feature]}</h3>
      <p>{feature.effective ? 'Available' : 'Unavailable'} · {feature.paused ? 'Paused locally' : 'Release default'}</p>
      <p>{reason(feature)}</p>
      {feature.can_change && <button className="secondary" type="button" disabled={busy}
        onClick={() => void save(feature)}>
        {feature.paused ? 'Restore inherited access' : 'Pause feature'}
      </button>}
      {state.verified && !feature.can_change && feature.feature === 'integration_api' &&
        <p>Only the workspace owner can change API availability.</p>}
    </article>)}
  </section>
}
