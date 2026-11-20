'use client'

import { useEffect, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'

const choices = [['mention', 'Room mentions'], ['task', 'Task updates'], ['call', 'Missed calls']] as const
type Category = typeof choices[number][0]
type Settings = { available: boolean; enabled: boolean; cadence: 'prompt' | 'daily' | 'weekly'; categories: Category[] }

export function NotificationEmailSettings() {
  const [settings, setSettings] = useState<Settings | null>(null)
  const [available, setAvailable] = useState(false)
  const [saving, setSaving] = useState(false)
  const [feedback, setFeedback] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    let current = true
    void Promise.all([
      db!.rpc('st_v6_notification_email_settings'),
      fetch('/api/notification-email/drain', { cache: 'no-store' }).then(response => response.json()).catch(() => null),
    ]).then(([configuration, service]) => {
      if (!current) return
      if (configuration.error || !configuration.data) setError('Could not load email notification settings.')
      else setSettings(configuration.data as Settings)
      setAvailable(service?.available === true)
    })
    return () => { current = false }
  }, [])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!settings || saving) return
    setSaving(true)
    setFeedback('')
    setError('')
    const { error } = await db!.rpc('st_v6_set_notification_email', {
      p_enabled: settings.enabled, p_cadence: settings.cadence, p_categories: settings.categories,
    })
    if (error) setError(formatError(error, 'Could not save your email notification settings.'))
    else setFeedback('Email notification settings saved.')
    setSaving(false)
  }

  return <section className="panel release-panel" aria-label="Email notifications">
    <h2>Email notifications</h2>
    <p>Send activity counts to your verified email. Every email includes an unsubscribe link.</p>
    {!settings && !error && <p role="status">Loading email notification settings…</p>}
    {settings && (!available || !settings.available) && <p role="status">
      {settings.available ? 'Email delivery is unavailable.' : 'Verify your current email to subscribe.'}
    </p>}
    {settings && <form className="release-form" onSubmit={submit}>
      <label className="task-check"><input type="checkbox" checked={settings.enabled}
        disabled={saving || (!settings.enabled && (!settings.available || !available))}
        onChange={event => setSettings({ ...settings, enabled: event.target.checked })}/> Send email notifications</label>
      {settings.enabled && <fieldset disabled={saving || !available}>
        <legend>Email categories</legend>
        {choices.map(([category, name]) => <label className="task-check" key={category}>
          <input type="checkbox" checked={settings.categories.includes(category)}
            onChange={event => setSettings({ ...settings, categories: event.target.checked
              ? [...settings.categories, category] : settings.categories.filter(value => value !== category) })}/> {name}
        </label>)}
        <label>Frequency<select value={settings.cadence} onChange={event =>
          setSettings({ ...settings, cadence: event.target.value as Settings['cadence'] })}>
          <option value="prompt">As activity arrives</option>
          <option value="daily">Daily digest</option>
          <option value="weekly">Weekly digest</option>
        </select></label>
      </fieldset>}
      <button type="submit" className="secondary" disabled={saving || (settings.enabled && (!available || !settings.categories.length))}>
        Save email preferences
      </button>
    </form>}
    {feedback && <p role="status">{feedback}</p>}
    {error && <p role="alert" className="error">{error}</p>}
  </section>
}
