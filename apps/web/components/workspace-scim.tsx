'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db } from '../lib/data'
import { StaffMfa } from './staff-mfa'

type ScimSettings = {
  access: 'none' | 'mfa' | 'verified'
  enterprise?: boolean
  domains?: string[]
  setup?: { domain: string; expires: string } | null
}

export function WorkspaceScim({ workspace, onManageDomains }: { workspace: string; onManageDomains: () => void }) {
  const [settings, setSettings] = useState<ScimSettings>()
  const [token, setToken] = useState('')
  const [endpoint, setEndpoint] = useState('')
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const load = useCallback(async () => {
    const result = await db!.rpc('st_v8_scim_settings', { p_workspace: workspace })
    if (result.error) setError('Provisioning settings are unavailable.')
    else setSettings(result.data)
  }, [workspace])
  useEffect(() => {
    setEndpoint(new URL('/api/scim/v2', window.location.origin).href)
    void load()
  }, [load])

  async function change(action: 'rotate' | 'revoke', domain?: string) {
    if (busy) return
    setBusy(true)
    setToken('')
    setError('')
    setNotice('')
    try {
      const result = await db!.rpc('st_v8_scim_settings', { p_workspace: workspace, p_action: action, p_domain: domain })
      if (result.error) throw result.error
      setSettings(result.data)
      if (result.data.access === 'verified') {
        setToken(result.data.token ?? '')
        setNotice(action === 'rotate' ? 'Provisioning token created.' : 'Provisioning token revoked.')
      }
    } catch {
      setError('The token could not be changed. Verify ownership, Enterprise access and the domain.')
    } finally {
      setBusy(false)
    }
  }
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    void change('rotate', String(new FormData(event.currentTarget).get('domain')))
  }
  return <section className="release-section" aria-label="Enterprise directory provisioning">
    <h3>Directory provisioning</h3>
    <p>Connect an identity provider using SCIM 2.0. Provisioning manages ordinary members and directory groups in this workspace.</p>
    {!settings && !error && <p role="status">Checking directory provisioning access…</p>}
    {settings?.access === 'none' && <p>Directory provisioning is unavailable.</p>}
    {settings?.access === 'mfa' &&
      <StaffMfa refresh={load} explanation="Verify your authenticator to manage provisioning credentials." />}
    {settings?.access === 'verified' && <>
      {!settings.enterprise && <p>An Enterprise workspace is required to issue a provisioning token.</p>}
      <label>SCIM base URL<input readOnly value={endpoint} /></label>
      <p>You can provision users and groups before signup. New users finish signup, then verify their organization email from Workspaces to claim access.</p>
      {settings.setup && <p>Token domain {settings.setup.domain}. Expires {new Date(settings.setup.expires).toLocaleDateString()}.</p>}
      {settings.enterprise && (settings.domains?.length ? <form className="release-form" onSubmit={submit}>
        <label>Verified domain<select required name="domain" defaultValue={settings.setup?.domain ?? ''}>
          <option value="">Select a verified domain</option>
          {settings.domains.map(domain => <option key={domain} value={domain}>{domain}</option>)}
        </select></label>
        {settings.setup && <p>Rotating the token revokes the previous token immediately.</p>}
        <button className="primary" disabled={busy}>{settings.setup ? 'Rotate provisioning token' : 'Create provisioning token'}</button>
      </form> : <p>Verify a domain in Organization settings before creating a token.</p>)}
      {settings.enterprise && <button type="button" className="secondary" onClick={onManageDomains}>Manage verified domains</button>}
      {settings.setup && <button type="button" className="secondary" disabled={busy}
        onClick={() => void change('revoke')}>Revoke provisioning token</button>}
      {token && <div className="release-form">
        <label>New provisioning token<input readOnly value={token} autoComplete="off" spellCheck={false} /></label>
        <p>Copy this token into your identity provider. SecTalk displays it only when issued.</p>
        <button type="button" className="secondary" onClick={() => setToken('')}>Hide provisioning token</button>
      </div>}
    </>}
    {notice && <p role="status">{notice}</p>}
    {error && <p role="alert">{error}</p>}
  </section>
}
