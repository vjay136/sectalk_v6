'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'
import { SectionTabs } from './section-tabs'
import { StaffMfa } from './staff-mfa'
import { useFeature } from '../lib/use-feature'
import { isFreeRelease } from '../lib/release-scope'
import { WorkspaceScim } from './workspace-scim'
import { WorkspaceSsoSettings } from './workspace-sso-settings'

type CredentialTab = 'keys' | 'webhooks'
type IntegrationTab = CredentialTab | 'sso' | 'scim'
type Status = 'none' | 'upgrade' | 'sso' | 'mfa' | 'verified'
type Key = { id: string; label: string; display_prefix: string; scopes: string[]; expires_at: string; revoked_at: string | null }
type Endpoint = { id: string; label: string; destination: string; topics: string[]; revoked_at: string | null
  deliveries: { id: string; type: string; created_at: string; state: string; attempts: number; status: number | null }[] }

export function WorkspaceIntegrations({workspace, onManageDomains}: {workspace: string; onManageDomains: () => void}) {
  const [tab, setTab] = useState<IntegrationTab>('keys')
  return <section aria-label="Workspace integrations">
    <h2>Integrations</h2>
    <SectionTabs label="Integration sections" value={tab} onChange={setTab}
      options={ [['keys','API keys'], ['webhooks','Outbound webhooks'],
        ...(isFreeRelease ? [] : [['sso','Single sign-on']] as const), ['scim','SCIM']] }/>
    {tab === 'sso' ? <WorkspaceSsoSettings workspace={workspace} onManageDomains={onManageDomains}/> :
      tab === 'scim' ? <WorkspaceScim workspace={workspace} onManageDomains={onManageDomains}/> :
        <WorkspaceIntegrationCredentials key={tab} workspace={workspace} tab={tab}/>}
  </section>
}

function WorkspaceIntegrationCredentials({workspace, tab}: {workspace: string; tab: CredentialTab}) {
  const [status, setStatus] = useState<Status | null>(null)
  const [keys, setKeys] = useState<Key[]>([])
  const [webhooks, setWebhooks] = useState<Endpoint[]>([])
  const [revealed, setRevealed] = useState('')
  const [revoke, setRevoke] = useState<{ category: 'keys' | 'webhooks'; id: string; label: string } | null>(null)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const apiAvailable = useFeature('integration_api', workspace, status === 'verified' && tab === 'keys')

  const refresh = useCallback(async () => {
    const scope = { p_workspace: workspace }
    const auth = await db!.rpc('st_v6_integration_access', scope)
    if (auth.error) {
      setError('Could not verify integration access.')
      return
    }
    setStatus(auth.data as Status)
    if (auth.data !== 'verified') {
      setKeys([])
      setWebhooks([])
      setRevealed('')
      return
    }
    const [keys, endpoints] = await Promise.all([
      db!.rpc('st_v6_integration_key_list', scope), db!.rpc('st_v6_webhook_status', scope),
    ])
    if (keys.error || endpoints.error) setError('Could not load workspace integrations.')
    setKeys(keys.error ? [] : keys.data as Key[])
    setWebhooks(endpoints.error ? [] : endpoints.data as Endpoint[])
  }, [workspace])

  useEffect(() => {
    void refresh()
    const id = window.setInterval(() => void refresh(), 15000)
    return () => window.clearInterval(id)
  }, [refresh])

  async function action(category: 'keys' | 'webhooks', payload: Record<string, unknown>) {
    if (busy) return false
    setError('')
    setNotice('')
    setRevealed('')
    setBusy(true)
    try {
      const { data } = await db!.auth.getSession()
      if (!data.session) throw new Error('Sign in again to manage integrations.')
      const response = await fetch('/api/integrations/' + category, {
        method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + data.session.access_token },
        body: JSON.stringify({ workspace, ...payload }),
      })
      if (response.status === 204) {
        setRevoke(null)
        setNotice('Credential revoked.')
      } else {
        const result = await response.json().catch(() => null)
        if (!response.ok || !result) throw new Error(result?.error || 'Could not update the integration.')
        setRevealed(result.key ?? result.secret ?? '')
      }
      await refresh()
      return true
    } catch (cause) {
      setError(formatError(cause, 'Could not update the integration.'))
      return false
    } finally { setBusy(false) }
  }

  function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = event.currentTarget
    const fields = new FormData(form)
    const details = tab === 'keys'
      ? { scopes: fields.getAll('scope'), lifetime: Number(fields.get('expiry')) }
      : { destination: fields.get('destination'), topics: fields.getAll('topic') }
    void action(tab, { action: 'create', label: fields.get('label'), ...details }).then(ok => { if (ok) form.reset() })
  }

  if (status === 'mfa') return <StaffMfa refresh={refresh} explanation="Verify your authenticator to manage workspace credentials."/>
  return <>
    {error && <p className="error" role="alert">{error}</p>}
    {notice && <p role="status">{notice}</p>}
    {!status && !error && <p role="status">Checking integration access…</p>}
    {status === 'none' && <p>Integration access is unavailable.</p>}
    {status === 'upgrade' && <p>Workspace APIs and webhooks are available with Team and Enterprise.</p>}
    {status === 'sso' && <p role="status">Sign in with workspace single sign-on to manage API keys and webhooks.</p>}
    {status === 'verified' && <>
      {revealed && <div className="release-board-item">
        <p>Copy this credential now. The app shows it once.</p>
        <code style={{ overflowWrap: 'anywhere' }}>{revealed}</code>
        <div className="action-row"><button className="secondary" type="button" onClick={async () => {
          try { await navigator.clipboard.writeText(revealed); setNotice('Credential copied.') }
          catch { setError('Select the credential text to copy it manually.') }
        }}>Copy credential</button><button className="secondary" type="button" onClick={() => setRevealed('')}>Hide credential</button></div>
      </div>}
      {tab === 'keys' && apiAvailable === false && <p>Workspace API access is unavailable under the current feature settings.</p>}
      {(tab === 'webhooks' || apiAvailable === true) && <form onSubmit={create} className="release-form" key={tab}>
        <h3>{tab === 'keys' ? 'Create an API key' : 'Register a webhook'}</h3>
        <label>Label<input name="label" required maxLength={48}/></label>
        {tab === 'keys' ? <>
          <fieldset><legend>API scopes</legend>
            <label className="task-check"><input type="checkbox" name="scope" value="workspace:read" defaultChecked/>Read workspace metadata</label>
            <label className="task-check"><input type="checkbox" name="scope" value="rooms:read"/>Read discoverable rooms</label>
          </fieldset>
          <label>Expires after<select name="expiry" defaultValue="90"><option value="30">30 days</option>
            <option value="90">90 days</option><option value="365">365 days</option></select></label>
        </> : <>
          <label>Webhook endpoint URL<input name="destination" type="url" placeholder="https://your-service.example/webhooks" required maxLength={480}/></label>
          <fieldset><legend>Events</legend>
            <label className="task-check"><input type="checkbox" name="topic" value="room.created" defaultChecked/>Discoverable room created</label>
            <label className="task-check"><input type="checkbox" name="topic" value="membership.changed"/>Workspace membership changed</label>
          </fieldset>
        </>}
        <button className="primary" disabled={busy}>{tab === 'keys' ? 'Create API key' : 'Register webhook'}</button>
      </form>}
      {tab === 'keys' ? <>
        <p>Use the Bearer header with <code>/api/v1/workspace</code> or <code>/api/v1/rooms</code>.</p>
        {keys.map(key => <article className="release-board-item" key={key.id}>
          <h3>{key.label}</h3><p><code>{key.display_prefix}…</code> · {key.scopes.join(', ')}</p>
          <p>{key.revoked_at ? 'Revoked' : (Date.parse(key.expires_at) <= Date.now() ? 'Expired' : 'Expires ' + new Date(key.expires_at).toLocaleDateString())}</p>
          {!key.revoked_at && <button type="button" className="secondary"
            onClick={() => setRevoke({ category: 'keys', id: key.id, label: key.label })}>Revoke API key</button>}
        </article>)}
      </> : webhooks.map(endpoint => <article className="release-board-item" key={endpoint.id}>
        <h3>{endpoint.label}</h3><p style={{ overflowWrap: 'anywhere' }}>{endpoint.destination}</p>
        <p>{endpoint.topics.join(', ')}</p>
        {endpoint.revoked_at ? <p>Revoked</p> : <button type="button" className="secondary"
          onClick={() => setRevoke({ category: 'webhooks', id: endpoint.id, label: endpoint.label })}>Revoke webhook</button>}
        <details><summary>Recent deliveries</summary>
          {!endpoint.deliveries.length && <p>No deliveries yet.</p>}
          <ul>{endpoint.deliveries.map(delivery => <li key={delivery.id}>{delivery.type} · {delivery.state}
            {' · '}{delivery.attempts} attempts{delivery.status ? ' · HTTP ' + delivery.status : ''}</li>)}</ul>
        </details>
      </article>)}
      {revoke && <div className="release-board-item">
        <p>Revoke {revoke.label}?</p>
        <div className="action-row"><button type="button" className="danger" disabled={busy}
          onClick={() => void action(revoke.category, { action: 'revoke', [revoke.category === 'keys' ? 'key' : 'endpoint']: revoke.id })}>Confirm revocation</button>
          <button type="button" className="secondary" disabled={busy} onClick={() => setRevoke(null)}>Cancel</button></div>
      </div>}
    </>}
  </>
}
