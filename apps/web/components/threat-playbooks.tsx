'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'

type Signal = 'detection' | 'attachment_inspection' | 'malware'
type Step = 'mark_reviewing' | 'verify_signal' | 'document_findings'
type SignalRow = { id: string; signal_type: Signal; severity: string; state: string; revision: number; detected_at: string }
type Grant = { scope: Signal; role: 'author' | 'approver' }
type Version = { id: string; signal_type: Signal; version: number; name: string; severity: string; actions: Step[] }
type Run = Pick<Version,'signal_type' | 'version' | 'name' | 'severity' | 'actions'> & {
  id: string; item: string; item_revision: number; own_request: boolean; can_decide: boolean;
  decision: null | 'executed' | 'rejected'; reason: string | null; requested_at: string; decided_at: string | null;
  effects: { step: Step; completed: string | null; occurred_at: string }[];
}
type Simulation = { version: Version; item: string; revision: number; matches: boolean; actions: Step[] }
const signalName: Record<Signal,string> = {
  detection: 'Detection rule', attachment_inspection: 'Attachment inspection', malware: 'Malware verdict',
}
const stepName: Record<Step,string> = {
  mark_reviewing: 'Move the signal to Reviewing', verify_signal: 'Verify the signal',
  document_findings: 'Document the review findings',
}

export function ThreatPlaybooks({ signals, refreshQueue }: { signals: SignalRow[]; refreshQueue: () => Promise<void> }) {
  const [grants,setGrants] = useState<Grant[]>([])
  const [catalog,setCatalog] = useState<Version[]>([])
  const [runs,setRuns] = useState<Run[]>([])
  const [edit,setEdit] = useState('')
  const [simulation,setSimulation] = useState<Simulation | null>(null)
  const [busy,setBusy] = useState(false)
  const [error,setError] = useState('')
  const [notice,setNotice] = useState('')
  const refresh = useCallback(async () => {
    const [definitions,requests] = await Promise.all([db!.rpc('st_v7_playbook_catalog'),db!.rpc('st_v7_playbook_runs')])
    if (definitions.error || requests.error) return
    setGrants(definitions.data.grants)
    setCatalog(definitions.data.versions)
    setRuns(requests.data)
  },[])
  useEffect(() => { void refresh() },[refresh])

  const authorScopes = grants.filter(grant => grant.role==='author').map(grant => grant.scope)
  const available = catalog.filter(version => authorScopes.includes(version.signal_type))
  const editing = available.find(version => version.id===edit)
  const allowedSignals = signals.filter(row => authorScopes.includes(row.signal_type))
  if (grants.length===0) return null

  async function operation(label: string, run: () => Promise<void>) {
    setBusy(true)
    setError('')
    setNotice('')
    try {
      await run()
      setNotice(label)
    } catch (failure) {
      setError(formatError(failure,'The playbook action could not be completed.'))
    } finally { setBusy(false) }
  }

  function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const fields = new FormData(event.currentTarget)
    void operation('Playbook version saved.',async () => {
      const result = await db!.rpc('st_v7_save_playbook',{
        p_id:editing?.id ?? null,p_version:editing?.version ?? 0,p_scope:editing?.signal_type ?? fields.get('scope'),
        p_name:fields.get('name'),p_severity:fields.get('severity'),p_actions:fields.getAll('step'),
      })
      if (result.error) throw result.error
      setEdit(result.data)
      setSimulation(null)
      await refresh()
    })
  }

  function simulate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const fields = new FormData(event.currentTarget)
    const version = available.find(value => value.id===fields.get('version'))
    const selected = allowedSignals.find(value => value.id===fields.get('item'))
    setSimulation(null)
    if (!version || !selected) return
    void operation('Simulation completed.',async () => {
      const result = await db!.rpc('st_v7_simulate_playbook',{
        p_id:version.id,p_version:version.version,p_item:selected.id,p_revision:selected.revision,p_request:false,
      })
      if (result.error) throw result.error
      setSimulation({ version,item:selected.id,revision:selected.revision,matches:result.data.matches,actions:result.data.actions })
    })
  }
  function submit() {
    if (!simulation?.matches) return
    void operation('Approval requested.',async () => {
      const result = await db!.rpc('st_v7_simulate_playbook',{
        p_id:simulation.version.id,p_version:simulation.version.version,p_item:simulation.item,p_revision:simulation.revision,p_request:true,
      })
      if (result.error) throw result.error
      setSimulation(null)
      await refresh()
    })
  }
  function decide(event: FormEvent<HTMLFormElement>, run: Run) {
    event.preventDefault()
    const fields = new FormData(event.currentTarget)
    const approve = fields.get('decision')==='approve'
    void operation(approve ? 'Playbook executed.' : 'Playbook request rejected.',async () => {
      const result = await db!.rpc('st_v7_decide_playbook',{p_run:run.id,p_approve:approve,p_reason:fields.get('reason')})
      if (result.error) throw result.error
      await Promise.all([refresh(),refreshQueue()])
    })
  }

  return <section className="release-section" aria-label="Threat playbooks">
    <h3>Threat playbooks</h3>
    <p>Simulate steps on a signal. A separate scoped reviewer must approve the exact version and signal revision before execution.</p>
    {authorScopes.length>0 && <>
      <label>Playbook version to edit<select aria-label="Playbook version to edit" value={edit}
        onChange={event => { setEdit(event.target.value); setSimulation(null) }}>
        <option value="">New playbook</option>{available.map(version => <option key={version.id} value={version.id}>
          {version.name} · version {version.version}</option>)}
      </select></label>
      <form key={(editing?.id ?? 'new') + ':' + (editing?.version ?? 0)} className="release-form" onSubmit={save}>
        <label>Playbook name<input name="name" required minLength={3} maxLength={80} defaultValue={editing?.name}/></label>
        <label>Playbook signal type<select aria-label="Playbook signal type" name="scope" disabled={Boolean(editing)} defaultValue={editing?.signal_type}>
          {authorScopes.map(type => <option key={type} value={type}>{signalName[type]}</option>)}</select></label>
        <label>Required severity<select aria-label="Required severity" name="severity" defaultValue={editing?.severity ?? 'any'}>
          <option value="any">Any</option><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option>
        </select></label>
        <fieldset><legend>Playbook steps</legend>
          {(Object.keys(stepName) as Step[]).map(step => <label key={step}>
            <input type="checkbox" name="step" value={step} defaultChecked={editing?.actions.includes(step)}/>{stepName[step]}
          </label>)}
        </fieldset>
        <button type="submit" disabled={busy}>Save playbook version</button>
      </form>
      {available.length>0 && allowedSignals.length>0 && <form className="release-form" onSubmit={simulate} onChange={() => setSimulation(null)}>
        <label>Playbook to simulate<select aria-label="Playbook to simulate" name="version" required>
          {available.map(version => <option key={version.id} value={version.id}>{version.name} · version {version.version}</option>)}
        </select></label>
        <label>Signal to simulate<select aria-label="Signal to simulate" name="item" required>
          {allowedSignals.map(row => <option key={row.id} value={row.id}>{signalName[row.signal_type]} · {row.severity} · {row.state} · {
            new Date(row.detected_at).toLocaleString()} · {row.id.slice(0,8)}</option>)}
        </select></label>
        <button type="submit" disabled={busy}>Simulate on signal</button>
      </form>}
      {simulation && <article className="release-board-item">
        <h4>{simulation.version.name} · Version {simulation.version.version} simulation</h4>
        <p>Signal {simulation.item.slice(0,8)} · revision {simulation.revision}</p>
        {simulation.matches ? <><ul>{simulation.actions.map(step => <li key={step}>{stepName[step]}</li>)}</ul>
          <button type="button" disabled={busy} onClick={submit}>Request playbook approval</button></> :
          <p>The signal does not meet the playbook conditions.</p>}
      </article>}
    </>}
    <button className="secondary" type="button" disabled={busy} onClick={() => void refresh()}>Refresh playbook requests</button>
    {runs.length===0 && <p>No playbook requests in your scope.</p>}
    {runs.map(run => <article className="release-board-item" key={run.id} data-playbook-run={run.id}>
      <h4>{run.name} · Version {run.version}</h4>
      <p>{signalName[run.signal_type]} {run.item.slice(0,8)} · signal revision {run.item_revision}</p>
      <p>{run.decision==='executed' ? 'Executed' : run.decision==='rejected' ? 'Rejected' : 'Awaiting approval'} · <time dateTime={run.requested_at}>
        {new Date(run.requested_at).toLocaleString()}</time></p>
      {run.reason && <p>{run.reason}</p>}
      <ul>{run.actions.map(step => <li key={step}>{stepName[step]}</li>)}</ul>
      {run.can_decide && <form className="release-form" onSubmit={event => decide(event,run)}>
        <label>Playbook decision<select aria-label="Playbook decision" name="decision" required defaultValue="">
          <option value="" disabled>Choose a decision</option><option value="approve">Approve and execute</option><option value="reject">Reject</option>
        </select></label>
        <label>Playbook decision reason<textarea name="reason" required minLength={10} maxLength={500}/></label>
        <button type="submit" disabled={busy}>Apply playbook decision</button>
      </form>}
      {run.effects.length>0 && <ul className="audit">{run.effects.map(effect => <li key={effect.step}>
        {stepName[effect.step]} · {effect.step==='mark_reviewing' ? 'Applied' : effect.completed ? 'Completed' : 'Open'}
        {effect.step!=='mark_reviewing' && !effect.completed && grants.some(grant => grant.scope===run.signal_type && grant.role==='approver') &&
          <button className="secondary" type="button" disabled={busy} onClick={() => void operation('Checklist step completed.',async () => {
            const result = await db!.rpc('st_v7_complete_playbook_step',{p_run:run.id,p_step:effect.step})
            if (result.error || result.data!==true) throw result.error ?? new Error('Checklist step could not be found.')
            await refresh()
          })}>Complete {stepName[effect.step].toLowerCase()}</button>}
      </li>)}</ul>}
    </article>)}
    {notice && <p role="status">{notice}</p>}
    {error && <p role="alert" className="error">{error}</p>}
  </section>
}
