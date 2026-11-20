'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'

const choices = [
  ['mention', 'Room mentions'],
  ['thread', 'Followed thread replies'],
  ['task', 'Room task notices'],
  ['admin', 'Admin-room activity'],
] as const
type Category = typeof choices[number][0]
type Policy = {mandatory_categories: Category[]; max_quiet_minutes: number | null}

export function WorkspaceNotificationPolicy({workspace, manager}: {workspace: string; manager: boolean}) {
  const [policy, setPolicy] = useState<Policy | null>(null)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)
  const requestVersion = useRef(0)
  const load = useCallback(async () => {
    const request = ++requestVersion.current
    const {data, error} = await db!.rpc('st_v6_workspace_notification_settings', {p_workspace: workspace})
    if (request !== requestVersion.current) return
    if (error) setError('Could not load the notification policy.')
    else {
      setError('')
      setPolicy(data as Policy)
    }
  }, [workspace])

  useEffect(() => {
    void load()
    return () => { ++requestVersion.current }
  }, [load])

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (saving) return
    const fields = new FormData(event.currentTarget)
    const categories = choices.flatMap(([category]) => fields.has(category) ? [category] : [])
    const minutes = fields.get('max-quiet-minutes')
    const maxQuiet = minutes === '' ? null : Number(minutes)
    setSaving(true)
    setError('')
    setSaved(false)
    const {error} = await db!.rpc('st_v6_set_workspace_notification_policy', {
      p_workspace: workspace, p_categories: categories, p_quiet_minutes: maxQuiet,
    })
    if (error) setError(formatError(error, 'Could not save the notification policy.'))
    else {
      setPolicy({mandatory_categories: categories, max_quiet_minutes: maxQuiet})
      setSaved(true)
    }
    setSaving(false)
  }

  const required = choices.filter(([category]) => policy?.mandatory_categories.includes(category)).map(([, label]) => label)
  return <section className="release-section" aria-label="Notification policy">
    <h3>Notification policy</h3>
    <p>Required alerts can appear during quiet hours even when the personal category is off. This policy applies to this workspace.</p>
    {error && <p className="error" role="alert">{error}</p>}
    {!policy && (error
      ? <button className="secondary" type="button" onClick={() => void load()}>Try again</button>
      : <p role="status">Loading notification policy…</p>)}
    {policy && (manager
      ? <form className="release-form" onSubmit={save} onChange={() => setSaved(false)}>
        <fieldset disabled={saving}>
          <legend>Required alerts</legend>
          {choices.map(([category, label]) => <label className="task-check" key={category}>
            <input type="checkbox" name={category} defaultChecked={policy.mandatory_categories.includes(category)}/> {label}
          </label>)}
        </fieldset>
        <label>Maximum quiet minutes<input type="number" name="max-quiet-minutes" min={0} max={1440} step={1}
          placeholder="No limit" disabled={saving} defaultValue={policy.max_quiet_minutes ?? ''}/></label>
        <p>Applies to each mute, snooze, or scheduled quiet window for workspace room and channel alerts. Enter 0 for no quiet time, or leave the field blank for no limit.</p>
        <button type="submit" className="secondary" disabled={saving}>{saving ? 'Saving…' : 'Save notification policy'}</button>
        {saved && <p role="status">Notification policy saved.</p>}
      </form>
      : <dl>
        <dt>Required alerts</dt><dd>{required.join(', ') || 'None'}</dd>
        <dt>Maximum quiet minutes</dt><dd>{policy.max_quiet_minutes ?? 'No limit'}</dd>
      </dl>)}
  </section>
}
