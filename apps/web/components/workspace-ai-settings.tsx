'use client'

import { useEffect, useState, type FormEvent } from 'react'
import { db } from '../lib/data'
import { ProfileRuleRegistry } from './profile-rule-registry'

type Settings = { owner: boolean; enabled: boolean; consent: boolean; threshold: number; retentionDays: number }

export function WorkspaceAISettings({ workspace }: { workspace: string }) {
  const [settings, setSettings] = useState<Settings>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  useEffect(() => {
    let closed = false
    void db!.rpc('st_v7_workspace_ai_settings', { p_workspace: workspace }).then(result => {
      if (closed) return
      if (result.error || !result.data) setError('Workspace AI settings could not be loaded.')
      else setSettings(result.data as Settings)
    })
    return () => { closed = true }
  }, [workspace])

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!settings?.owner || busy) return
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const result = await db!.rpc('st_v7_workspace_ai_settings', {
        p_workspace: workspace, p_enabled: settings.enabled, p_processing_consent: settings.consent,
        p_advisory_threshold: settings.threshold, p_retention_days: settings.retentionDays,
      })
      if (result.error || !result.data) throw new Error('Settings unavailable')
      setSettings(result.data as Settings)
      setNotice('Workspace AI settings saved.')
    } catch {
      setError('Workspace AI settings could not be saved.')
    } finally {
      setBusy(false)
    }
  }

  return <><section className="release-section" aria-label="Workspace AI settings">
    <h2>AI settings</h2>
    {!settings && !error && <p role="status">Loading workspace AI settings…</p>}
    {settings && <form className="release-form" onSubmit={event => void save(event)}>
      {!settings.owner && <p>Only the workspace owner can change these settings.</p>}
      <fieldset disabled={!settings.owner || busy}>
        <legend>Workspace policy</legend>
        <label><input type="checkbox" checked={settings.enabled} onChange={event =>
          setSettings({ ...settings, enabled: event.target.checked })} /> Enable managed AI features</label>
        <label><input type="checkbox" checked={settings.consent} onChange={event =>
          setSettings({ ...settings, consent: event.target.checked })} /> Allow processing of opted-in content</label>
        <p>Captions and drafts still require each contributor’s consent. Turning off content processing hides saved transcripts.</p>
        <label>Impersonation advisory sensitivity
          <select value={settings.threshold} onChange={event => setSettings({ ...settings, threshold: Number(event.target.value) })}>
            <option value={1}>Broad – include nearby usernames</option>
            <option value={2}>Balanced – include visually similar profiles</option>
            <option value={3}>Strict – same display name</option>
          </select>
        </label>
        <label>Transcript retention in days
          <input type="number" min={1} max={90} required value={Number.isNaN(settings.retentionDays) ? '' : settings.retentionDays}
            onChange={event => setSettings({ ...settings, retentionDays: event.target.value === '' ? NaN : Number(event.target.value) })}
            aria-describedby="workspace-transcript-retention" />
        </label>
        <p id="workspace-transcript-retention">Keep transcripts for 1–90 days. Expired text becomes inaccessible and is deleted by the scheduled cleanup.</p>
      </fieldset>
      {settings.owner && <button className="primary" type="submit" disabled={busy}>Save AI settings</button>}
    </form>}
    {notice && <p role="status">{notice}</p>}
    {error && <p role="alert">{error}</p>}
  </section><ProfileRuleRegistry workspace={workspace} /></>
}
