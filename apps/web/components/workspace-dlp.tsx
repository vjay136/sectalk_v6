'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db } from '../lib/data'
import { StaffMfa } from './staff-mfa'

export const dlpLabels = {
  pii: 'Email addresses', phi: 'Health record identifiers', payment_card: 'Payment card numbers', credential: 'Credentials',
} as const
type Category = keyof typeof dlpLabels
type Action = 'allow' | 'warn' | 'block' | 'redact'
type Policy = { access: 'mfa' | 'sso' } | { access: 'verified'; revision: number; rules: Record<Category, Action> }

export function WorkspaceDlp({ workspace }: { workspace: string }) {
  const [policy, setPolicy] = useState<Policy | null>(null)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const load = useCallback(async (signal?: AbortSignal) => {
    const query = db!.rpc('st_v7_workspace_dlp', { p_workspace: workspace })
    const response = await (signal ? query.abortSignal(signal) : query)
    if (signal?.aborted) return
    if (response.error) { setPolicy(null); setError('Workspace data loss controls are unavailable.'); return }
    setPolicy(response.data as Policy)
    setError('')
  }, [workspace])

  useEffect(() => {
    const controller = new AbortController()
    void load(controller.signal)
    return () => controller.abort()
  }, [load])

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (policy?.access !== 'verified' || saving) return
    const fields = new FormData(event.currentTarget)
    const rules = Object.fromEntries(Object.keys(dlpLabels).map(category => [category, fields.get(category)]))
    setSaving(true)
    setError('')
    setNotice('')
    try {
      const result = await db!.rpc('st_v7_set_workspace_dlp', {
        p_workspace: workspace, p_revision: policy.revision, p_rules: rules,
      })
      if (result.error) {
        if (result.error.code === 'PT409') setError('Someone changed this policy. Refresh it before saving again.')
        else { await load(); setError('Could not save the workspace policy.') }
        return
      }
      setPolicy({ access: 'verified', revision: result.data, rules: rules as Record<Category, Action> })
      setNotice('Workspace data loss policy saved.')
    } finally { setSaving(false) }
  }

  return <section className="panel release-panel" aria-label="Data loss controls">
    <h2>Data loss controls</h2>
    <p>Apply rules to managed room and channel messages. Redaction replaces matching text with […].</p>
    {!policy && !error && <p role="status">Loading workspace rules…</p>}
    {policy?.access === 'sso' && <p>Sign in with workspace single sign-on to manage data loss controls.</p>}
    {policy?.access === 'mfa' && <StaffMfa refresh={() => load()} explanation="Enter a current authenticator code to manage workspace data loss controls."/>}
    {policy?.access === 'verified' && <form className="release-form" onSubmit={save} key={policy.revision}>
      {Object.entries(dlpLabels).map(([category, label]) => <label key={category}>{label}
        <select name={category} aria-label={label} defaultValue={policy.rules[category as Category]}>
          <option value="allow">Allow</option><option value="warn">Warn before sending</option>
          <option value="block">Block</option><option value="redact">Redact</option>
        </select>
      </label>)}
      <div className="actions">
        <button className="primary" disabled={saving}>Save data loss rules</button>
        <button type="button" className="secondary" disabled={saving} onClick={() => void load()}>Refresh rules</button>
      </div>
    </form>}
    {notice && <p role="status">{notice}</p>}
    {error && <p role="alert" className="error">{error}</p>}
  </section>
}
