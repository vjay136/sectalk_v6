'use client'

import { useCallback, useEffect, useState } from 'react'
import { db } from '../lib/data'

type Action = 'view' | 'stage' | 'clear' | 'promote' | 'rollback' | 'evaluate'
type Version = { id: string; label: string; effect: string }
type Evaluation = { active: string; shadow: string; corpus: string; evaluated_at: string;
  active_counts: [number, number, number, number]; shadow_counts: [number, number, number, number]; disagreements: number }
type Registry = { owner: boolean; active: string; shadow: string | null; previous: string | null; generation: string; canPromote: boolean;
  versions: Version[]; evaluations: Evaluation[]; history: Array<{ id: number; action: string; version: string; at: string }> }

const messages: Partial<Record<Action, string>> = {
  stage: 'Shadow version staged.', clear: 'Shadow version cleared.', evaluate: 'Synthetic evaluation recorded.',
  promote: 'The evaluated version is now active.', rollback: 'The previous rule version is active again.',
}
const actionLabels: Record<string, string> = { stage: 'Staged', clear: 'Cleared', promote: 'Promoted', rollback: 'Rolled back to' }

export function ProfileRuleRegistry({ workspace }: { workspace: string }) {
  const [registry, setRegistry] = useState<Registry>()
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')

  const read = useCallback(async () => {
    const result = await db!.rpc('st_v7_workspace_rule_registry', { p_workspace: workspace })
    if (result.error || !result.data) throw new Error('Rule registry unavailable')
    return result.data as Registry
  }, [workspace])

  useEffect(() => {
    let closed = false
    void read().then(value => { if (!closed) setRegistry(value) })
      .catch(() => { if (!closed) setError('The rule registry could not be loaded.') })
    return () => { closed = true }
  }, [read])

  async function run(action: Action, version?: string) {
    if (busy || (action !== 'view' && !registry?.owner)) return
    setBusy(true)
    setNotice('')
    setError('')
    try {
      if (action === 'evaluate') {
        const { data } = await db!.auth.getSession()
        const response = await fetch('/api/workspaces/rule-registry', {
          method: 'POST', headers: { Authorization: 'Bearer ' + data.session?.access_token, 'Content-Type': 'application/json' },
          body: JSON.stringify({ workspace }),
        })
        if (!response.ok) throw new Error('Synthetic evaluation unavailable')
        setRegistry(await read())
      } else if (action === 'view') {
        setRegistry(await read())
      } else {
        const result = await db!.rpc('st_v7_workspace_rule_registry', {
          p_workspace: workspace, p_action: action, p_version: version, p_generation: registry?.generation,
        })
        if (result.error || !result.data) throw new Error('Registry update unavailable')
        setRegistry(result.data as Registry)
      }
      setNotice(messages[action] ?? '')
    } catch {
      setError('The rule registry action could not be completed. Refresh and try again.')
    } finally {
      setBusy(false)
    }
  }

  const evaluation = registry?.evaluations[0]
  return <section className="release-section" aria-label="Impersonation rule registry">
    <div className="panel-header"><h3>Impersonation rule registry</h3>
      <button className="secondary" type="button" disabled={busy} onClick={() => void run('view')}>Refresh rule registry</button>
    </div>
    <p>Shadow evaluation compares versions on fixed synthetic profile pairs. Workspace profiles stay in the browser.</p>
    {registry && <>
      <dl>
        <div><dt>Active</dt><dd>{registry.active}</dd></div>
        <div><dt>Shadow</dt><dd>{registry.shadow ?? 'None'}</dd></div>
        <div><dt>Rollback target</dt><dd>{registry.previous ?? 'None'}</dd></div>
      </dl>
      <ul>{registry.versions.map(version => <li key={version.id}>
        <strong>{version.label}</strong> {version.effect}
        {registry.owner && version.id !== registry.active && version.id !== registry.shadow &&
          <button className="secondary" type="button" disabled={busy} onClick={() => void run('stage', version.id)}>Stage {version.label} as shadow</button>}
      </li>)}</ul>
      {registry.owner && <div className="actions">
        {registry.shadow && <>
          <button className="secondary" type="button" disabled={busy} onClick={() => void run('evaluate')}>Run synthetic shadow evaluation</button>
          <button className="primary" type="button" disabled={busy || !registry.canPromote} onClick={() => void run('promote')}>Promote evaluated shadow</button>
          <button className="secondary" type="button" disabled={busy} onClick={() => void run('clear')}>Clear shadow</button>
        </>}
        {registry.previous && <button className="secondary" type="button" disabled={busy} onClick={() => void run('rollback')}>Roll back to prior version</button>}
      </div>}
      {evaluation && <div>
        <h4>Latest synthetic evaluation</h4>
        <p>{evaluation.disagreements} changed decisions on {evaluation.active_counts.reduce((total, item) => total + item, 0)} cases. Corpus {evaluation.corpus}.</p>
        <table aria-label="Synthetic evaluation counts">
          <thead><tr><th>Version</th><th>True positives</th><th>False positives</th><th>True negatives</th><th>False negatives</th></tr></thead>
          <tbody>{[[evaluation.active, evaluation.active_counts], [evaluation.shadow, evaluation.shadow_counts]].map(([name, items]) =>
            <tr key={String(name)}><th scope="row">{name}</th>{(items as number[]).map((count, index) => <td key={index}>{count}</td>)}</tr>)}</tbody>
        </table>
      </div>}
      {registry.history.length > 0 && <><h4>Recent changes</h4>
        <ul>{registry.history.map(item => <li key={item.id}>{actionLabels[item.action]} {item.version} <time dateTime={item.at}>{new Date(item.at).toLocaleString()}</time></li>)}</ul></>}
    </>}
    {notice && <p role="status">{notice}</p>}
    {error && <p role="alert">{error}</p>}
  </section>
}
