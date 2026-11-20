'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db } from '../lib/data'
import { StaffMfa } from './staff-mfa'

type Access = 'none' | 'mfa' | 'verified'
type Source = 'operations' | 'login_anomalies'
type Mode = 'shadow' | 'enabled'
type Deployment = Mode | 'paused' | 'rollback'
type Trial = { recorded_windows: number; matched_windows: number; peak: number | null; latest_match: string | null }
type Rule = { id: string; label: string; latest_version: number; active_version: number | null; mode: Mode | null }
type Version = { version: number; source: Source; scope: string; metric: string; threshold: number; tested: Trial | null; deployed: boolean }
type Detail = Rule & {
  versions: Version[]
  matches: { id: number; version: number; mode: Mode; bucket: string; observed: number }[]
  history: { id: number; version: number; action: string; reason: string | null; occurred_at: string }[]
}
const operations: Record<string,string> = {
  file_upload: 'Upload attachment', file_publish: 'Publish attachment', file_download_grant: 'Authorize attachment download',
  file_download: 'Download attachment', call_ice: 'Direct call networking', meeting_token: 'Meeting media token',
  billing_action: 'Billing action', billing_webhook: 'Billing webhook',
}
const signals: Record<string,string> = {
  requests: 'Requests', client_errors: 'Client errors (4xx)', server_errors: 'Server errors (5xx)',
  throttled: 'Throttled requests (429)', unavailable: 'Unavailable responses (503)',
}
const actions: Record<Deployment,string> = {
  shadow: 'Run in shadow', enabled: 'Enable version', paused: 'Pause detection', rollback: 'Restore previous version',
}
const modeLabel = (mode: Mode | null) => mode === 'enabled' ? 'Enabled' : mode === 'shadow' ? 'Shadow' : 'No active version'

export function useDetectionRuleAccess() {
  const [access, setAccess] = useState<Access>('none')
  const refresh = useCallback(async () => {
    const { data, error } = await db!.rpc('st_v7_detection_rule_access')
    setAccess(!error && (data === 'mfa' || data === 'verified') ? data : 'none')
  }, [])
  useEffect(() => {
    void refresh()
    const timer = window.setInterval(refresh,15000)
    return () => window.clearInterval(timer)
  },[refresh])
  return { access, refresh }
}

export function DetectionRules({ access, refresh }: { access: Access; refresh: () => Promise<void> }) {
  if (access === 'none') return null
  if (access === 'mfa') return <StaffMfa refresh={refresh} explanation="Enter a current authenticator code to manage detection rules."/>
  return <Registry onAccessChanged={refresh}/>
}

function Registry({ onAccessChanged }: { onAccessChanged: () => Promise<void> }) {
  const [rules, setRules] = useState<Rule[] | null>(null)
  const [selection, setSelection] = useState<string | null>(null)
  const [picked, setPicked] = useState<number | null>(null)
  const [detail, setDetail] = useState<Detail | null>(null)
  const [decision, setDecision] = useState<Deployment | null>(null)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  const loadRules = useCallback(async () => {
    const { data, error } = await db!.rpc('st_v7_detection_rules')
    if (error) {
      setError('Could not load detection rules.')
      if (error.code === '42501') await onAccessChanged()
    } else setRules(data as Rule[])
  },[onAccessChanged])
  useEffect(() => { void loadRules() },[loadRules])

  const loadDetail = useCallback(async () => {
    if (!selection) return
    const { data, error } = await db!.rpc('st_v7_detection_rule_detail',{ p_rule:selection })
    if (error || !data) {
      setError('Could not load detection history.')
      if (error?.code === '42501') await onAccessChanged()
    } else setDetail(data as Detail)
  },[selection,onAccessChanged])
  useEffect(() => {
    if (!selection) return
    void loadDetail()
    const timer = window.setInterval(loadDetail,5000)
    return () => window.clearInterval(timer)
  },[selection,loadDetail])

  function open(id: string) {
    if (id !== selection) setDetail(null)
    setSelection(id)
    setPicked(null)
    setDecision(null)
    setError('')
    setMessage('')
  }

  const selected = detail?.id === selection ? detail : null
  const version = selected?.versions.find(item => item.version === picked) ?? selected?.versions[0]
  const selectedIsActive = selected?.active_version === version?.version

  async function save(fields: FormData, existing?: Detail) {
    if (busy) return
    setBusy(true)
    setError('')
    setMessage('')
    const source = String(fields.get('source') ?? '')
    const { data, error } = await db!.rpc('st_v7_save_detection_rule',{
      p_rule:existing?.id ?? null,p_expected:existing?.latest_version ?? null,p_label:fields.get('label'),
      p_source:source,p_scope:source === 'login_anomalies' ? 'platform' : fields.get('scope'),
      p_metric:source === 'login_anomalies' ? 'anomalies' : fields.get('metric'),p_threshold:Number(fields.get('threshold')),
    })
    if (error) {
      setError(error.message)
      if (error.code === '42501') await onAccessChanged()
    } else {
      open(String(data))
      setMessage(existing ? 'New draft version saved.' : 'Detection rule created.')
      await Promise.all([loadRules(),existing ? loadDetail() : Promise.resolve()])
    }
    setBusy(false)
  }

  async function test() {
    if (!selected || !version || busy) return
    setBusy(true)
    setError('')
    setMessage('')
    const { error } = await db!.rpc('st_v7_test_detection_rule',{ p_rule:selected.id,p_version:version.version })
    if (error) {
      setError(error.message)
      if (error.code === '42501') await onAccessChanged()
    } else {setMessage('Historical test recorded.'); await loadDetail()}
    setBusy(false)
  }

  async function deploy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!selected || !version || !decision || busy) return
    setBusy(true)
    setError('')
    setMessage('')
    const { error } = await db!.rpc('st_v7_deploy_detection_rule',{
      p_rule:selected.id,p_version:decision==='paused' ? selected.active_version : version.version,
      p_action:decision,p_reason:new FormData(event.currentTarget).get('reason'),
    })
    if (error) {
      setError(error.message)
      if (error.code === '42501') await onAccessChanged()
    } else {
      setDecision(null)
      setMessage('Deployment recorded.')
      await Promise.all([loadRules(),loadDetail()])
    }
    setBusy(false)
  }

  return <section className="panel release-panel" aria-label="Detection rules">
    <h2>Detection rules</h2>
    <p>Test versions against recorded five-minute windows from the last 24 hours. Activations count new events, and matches are recorded for review.</p>
    <details className="release-create"><summary>Create a detection rule</summary>
      <RuleForm busy={busy} submit={save}/>
    </details>
    {!rules && !error && <p role="status">Loading detection rules…</p>}
    {rules?.length === 0 && <p>No detection rules.</p>}
    <ul className="release-section">{rules?.map(rule => <li className="release-row" key={rule.id}>
      <button className="text-button" type="button" disabled={busy} onClick={() => open(rule.id)}>{rule.label}</button>
      <span className="pill">{modeLabel(rule.mode)}</span>
    </li>)}</ul>
    {selected && version && <article className="release-board-item">
      <h3>{selected.label}</h3>
      <p>{modeLabel(selected.mode)}{selected.active_version ? ' · Version ' + selected.active_version : ''}</p>
      <label>Rule version<select aria-label="Rule version" value={version.version} onChange={event => {
        setPicked(Number(event.target.value));setDecision(null);setMessage('');setError('')
      }}>
        {selected.versions.map(item => <option key={item.version} value={item.version}>Version {item.version}</option>)}
      </select></label>
      <p>{version.source==='operations' ? operations[version.scope] + ' · ' + signals[version.metric] : 'Native login anomalies · Platform'}
        {' · At least '}{version.threshold.toLocaleString()} per 5 minutes</p>
      {version.tested && <p>Recorded windows {version.tested.recorded_windows} · Matched windows {version.tested.matched_windows}
        {version.tested.peak !== null && ' · Peak ' + version.tested.peak}</p>}
      <div className="actions">
        <button className="secondary" type="button" disabled={busy} onClick={() => void test()}>Test against recent windows</button>
        {version.tested && (!selectedIsActive || selected.mode!=='shadow') &&
          <button className="secondary" type="button" disabled={busy} onClick={() => setDecision('shadow')}>{actions.shadow}</button>}
        {selectedIsActive && selected.mode==='shadow' &&
          <button className="secondary" type="button" disabled={busy} onClick={() => setDecision('enabled')}>{actions.enabled}</button>}
        {version.deployed && !selectedIsActive &&
          <button className="secondary" type="button" disabled={busy} onClick={() => setDecision('rollback')}>{actions.rollback}</button>}
        {selected.active_version && <button className="secondary" type="button" disabled={busy}
          onClick={() => setDecision('paused')}>{actions.paused}</button>}
      </div>
      {decision && <form className="release-form" key={decision} onSubmit={deploy}>
        <label>Deployment reason<textarea name="reason" required minLength={10} maxLength={240}/></label>
        <button className="primary" disabled={busy}>Confirm {actions[decision].toLowerCase()}</button>
        <button className="secondary" type="button" disabled={busy} onClick={() => setDecision(null)}>Cancel</button>
      </form>}
      <details className="release-create"><summary>Draft a new version</summary>
        <RuleForm key={selected.id + ':' + version.version} busy={busy} initial={version} submit={fields => save(fields,selected)}/>
      </details>
      <section aria-label="Detection matches">
        <h4>Recent matches</h4>
        {selected.matches.length === 0 ? <p>No matches recorded.</p> : <ul className="audit">
          {selected.matches.map(match => <li key={match.id}><strong>{modeLabel(match.mode)} match</strong>
            {' · Version ' + match.version + ' · Observed ' + match.observed + ' · '}
            <time dateTime={match.bucket}>{new Date(match.bucket).toLocaleString()}</time>
          </li>)}
        </ul>}
      </section>
      <details><summary>Rule history</summary><ul className="audit">
        {selected.history.map(entry => <li key={entry.id}>
          {entry.action} · Version {entry.version} · <time dateTime={entry.occurred_at}>{new Date(entry.occurred_at).toLocaleString()}</time>
          {entry.reason && <p>{entry.reason}</p>}
        </li>)}
      </ul></details>
    </article>}
    {message && <p role="status">{message}</p>}
    {error && <p className="error" role="alert">{error}</p>}
  </section>
}

function RuleForm({ initial,busy,submit }: { initial?: Version; busy: boolean; submit: (fields: FormData) => Promise<void> }) {
  const [source, setSource] = useState<Source>(initial?.source ?? 'operations')
  return <form className="release-form" aria-label={initial ? 'New detection version' : 'New detection rule'}
    onSubmit={event => {event.preventDefault();void submit(new FormData(event.currentTarget))}}>
    {!initial && <label>Rule name<input name="label" required minLength={3} maxLength={80}/></label>}
    <label>Signal source<select aria-label="Signal source" name="source" value={source} onChange={event => setSource(event.target.value as Source)}>
      <option value="operations">Operational metrics</option><option value="login_anomalies">Native login anomalies</option>
    </select></label>
    {source==='operations' && <>
      <label>Operation<select aria-label="Operation" name="scope" defaultValue={initial?.source==='operations' ? initial.scope : 'file_upload'}>
        {Object.entries(operations).map(([value,label]) => <option key={value} value={value}>{label}</option>)}
      </select></label>
      <label>Metric<select aria-label="Metric" name="metric" defaultValue={initial?.source==='operations' ? initial.metric : 'requests'}>
        {Object.entries(signals).map(([value,label]) => <option key={value} value={value}>{label}</option>)}
      </select></label>
    </>}
    <label>Threshold per 5 minutes<input key={source} name="threshold" type="number" step={1}
      min={source==='login_anomalies' ? 3 : 1} max={1000000} defaultValue={initial?.source===source ? initial.threshold : 3} required/></label>
    <button className="primary" disabled={busy}>{initial ? 'Save draft version' : 'Create rule'}</button>
  </form>
}
