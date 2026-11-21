'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'
import { verifyAccountCredential } from '../lib/account-credential'
import { WorkspaceInvitationTemplates } from './workspace-invitation-templates'
import { WorkspaceResidency } from './workspace-residency'
import { WorkspaceOffboarding } from './workspace-offboarding'
import { organizationSsoMessage, useWorkspaceOrganizationAccess } from './workspace-organization-access'

const colors = { blue: '#2776bc', teal: '#097568', violet: '#7553a8', amber: '#a96509' }
const accentNames = { blue: 'Blue', teal: 'Teal', violet: 'Violet', amber: 'Amber' }
type Accent = keyof typeof colors
type Proof = { domain: string; challenge: string | null; expiresAt: string; verifiedAt: string | null }
type Settings = { name: string; accent: Accent; retentionDays: number; region: string; domains: Proof[] }
type Region = { location: string; reference: string }
type Step = { assurance: 'totp' | 'password'; perform: () => Promise<void> }

export function OrganizationBrand({ workspace, name, accent }: { workspace: string; name: string; accent?: Accent }) {
  const [state, setState] = useState<{ workspace: string; accent: Accent }>()
  useEffect(() => {
    const controller = new AbortController()
    void db!.from('st_v2_workspaces').select('brand_accent').eq('id', workspace).abortSignal(controller.signal).maybeSingle()
      .then(result => {
        if (!controller.signal.aborted && result.data?.brand_accent in colors) {
          setState({ workspace, accent: result.data!.brand_accent as Accent })
        }
      })
    return () => controller.abort()
  }, [workspace])
  const shown = accent ?? (state?.workspace === workspace ? state.accent : 'blue')
  return <h2><span aria-hidden="true" style={{ display: 'inline-block', borderRadius: '50%', backgroundColor: colors[shown],
    width: '0.7em', height: '0.7em', marginInlineEnd: '0.5em' }}/>{name}</h2>
}

export function OrganizationSettings({ workspace, onBrand }: {
  workspace: string; onBrand: (accent: Accent) => void
}) {
  const [settings, setSettings] = useState<Settings>()
  const [region, setRegion] = useState<Region | null>()
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [step, setStep] = useState<Step>()
  const organizationAccess=useWorkspaceOrganizationAccess(workspace)

  async function api(action: string, domain?: string, signal?: AbortSignal) {
    const { data } = await db!.auth.getSession()
    if (!data.session?.access_token) throw new Error('Sign in again.')
    const response = await fetch('/api/workspaces/organization', { signal, method: 'POST', headers: {
      Authorization: 'Bearer ' + data.session.access_token, 'Content-Type': 'application/json',
    }, body: JSON.stringify({ workspace, action, domain }) })
    const body = await response.json()
    if (!response.ok) throw new Error(body.error || 'Organization settings are unavailable.')
    return body
  }

  const rpc = useCallback(async (action: string, params?: Record<string, unknown>, signal?: AbortSignal) => {
    const request = db!.rpc('st_v7_org_settings', { p_workspace: workspace, p_action: action, ...params })
    const result = await (signal ? request.abortSignal(signal) : request)
    if (result.error) throw result.error
    return result.data as Settings
  }, [workspace])

  useEffect(() => {
    if(organizationAccess!=='allowed')return
    const controller = new AbortController()
    void rpc('read', undefined, controller.signal).then(data => {
      if (!controller.signal.aborted) setSettings(data)
    }).catch(() => {
      if (!controller.signal.aborted) setError('Could not load organization settings.')
    })
    void api('region', undefined, controller.signal).then(data => {
      if (!controller.signal.aborted) setRegion(data.attestation)
    }).catch(() => {
      if (!controller.signal.aborted) setRegion(null)
    })
    return () => controller.abort()
    // The workspace key scopes this request and the entire settings form.
  }, [organizationAccess, workspace, rpc])

  async function handle(perform: () => Promise<void>) {
    if(organizationAccess!=='allowed')return
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const assurance = await db!.rpc('st_v7_sensitive_action_status', { p_kind: 'room_role' })
      if (assurance.error) throw assurance.error
      if (assurance.data === 'verified') await perform()
      else if (assurance.data === 'password' || assurance.data === 'totp') setStep({ assurance: assurance.data, perform })
      else throw new Error('Sign in again with your registered credential to change organization settings.')
    } catch (cause) { setError(formatError(cause, 'Organization settings could not be updated.')) }
    finally { setBusy(false) }
  }

  async function confirm(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!step || busy || organizationAccess!=='allowed') return
    const credential = String(new FormData(event.currentTarget).get('credential') ?? '')
    setBusy(true)
    setError('')
    try {
      await verifyAccountCredential(credential, step.assurance === 'totp')
      await step.perform()
      setStep(undefined)
    } catch (cause) { setError(formatError(cause, 'Could not verify your current credential.')) }
    finally { setBusy(false) }
  }

  function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const values = new FormData(event.currentTarget)
    void handle(async () => {
      const updated = await rpc('save', { p_name: values.get('name'), p_accent: values.get('accent'),
        p_days: Number(values.get('days')), p_region: values.get('region') })
      setSettings(updated)
      onBrand(updated.accent)
      setNotice('Organization settings saved.')
    })
  }

  function changeDomain(action: 'start' | 'remove' | 'verify', domain: string) {
    void handle(async () => {
      if (action === 'verify') {
        await api('verify-domain', domain)
        setSettings(await rpc('read'))
        setNotice('Domain verified.')
      } else {
        setSettings(await rpc('domain.' + action, { p_domain: domain }))
        setNotice(action === 'start' ? 'DNS challenge ready.' : 'Domain removed.')
      }
    })
  }

  return <section className="release-section" aria-label="Organization settings">
    <h2>Organization settings</h2>
    {organizationAccess===undefined&&<p role="status">Checking organization settings access…</p>}
    {organizationAccess==='required'&&<p role="status">{organizationSsoMessage}</p>}
    {organizationAccess==='unavailable'&&<p role="alert">Organization settings are unavailable.</p>}
    {organizationAccess==='allowed'&&settings && <form className="release-form" onSubmit={save} key={[settings.name, settings.accent, settings.retentionDays, settings.region].join(':')}>
      <fieldset disabled={busy || !!step}>
        <legend>Branding, retention and region preference</legend>
        <label>Organization name<input name="name" required maxLength={64} defaultValue={settings.name}/></label>
        <label>Brand accent<select name="accent" defaultValue={settings.accent}>
          {Object.entries(accentNames).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select></label>
        <label>Default room retirement retention (days)<input type="number" min={7} max={3650} required name="days" defaultValue={settings.retentionDays}/></label>
        <p>Effective workspace default: {settings.retentionDays} days. This policy applies to room retirement eligibility and honors active preservation holds.</p>
        <label>Preferred data region<select name="region" defaultValue={settings.region}>
          <option value="none">No preference</option><option value="us">United States</option>
          <option value="eu">Europe</option><option value="apac">Asia Pacific</option>
        </select></label>
        <p>Saving a preference leaves data in its current location. A region change requires a separate migration.</p>
        <p>{region === undefined ? 'Checking deployment region…' : region ?
          <>Operator-attested deployment region <strong>{region.location}</strong> (reference {region.reference}).</> :
          'No deployment region attestation is configured.'}</p>
        <button type="submit" className="primary">Save organization settings</button>
      </fieldset>
    </form>}
    {organizationAccess==='allowed'&&settings && <section aria-label="Organization domains">
      <h3>Verified domains</h3>
      <p>DNS verification records control of a domain at the time of the check. Workspace invitation rules have their own settings.</p>
      <form className="release-form" onSubmit={event => {
        event.preventDefault()
        const value = String(new FormData(event.currentTarget).get('domain') ?? '').trim().toLowerCase()
        changeDomain('start', value)
      }}>
        <label>Domain name<input name="domain" placeholder="example.org" required maxLength={225} autoComplete="off" /></label>
        <button type="submit" className="secondary" disabled={busy || !!step}>Start DNS verification</button>
      </form>
      <ul>{settings.domains.map(entry => <li key={entry.domain}>
        <h4><bdi>{entry.domain}</bdi></h4>
        {entry.verifiedAt ? <p>Verified <time dateTime={entry.verifiedAt}>{new Date(entry.verifiedAt).toLocaleDateString()}</time></p> : <>
          <p>Publish this DNS TXT record. The challenge expires <time dateTime={entry.expiresAt}>{new Date(entry.expiresAt).toLocaleString()}</time>.</p>
          <p>Name <code>{'_sectalk-verification.' + entry.domain}</code></p>
          <p>Value <code>{'sectalk=' + entry.challenge}</code></p>
          <button type="button" className="secondary" disabled={busy || !!step}
            onClick={() => changeDomain(Date.parse(entry.expiresAt) <= Date.now() ? 'start' : 'verify', entry.domain)}>
            {Date.parse(entry.expiresAt) <= Date.now() ? 'Renew DNS challenge' : 'Check DNS record'}</button>
        </>}
        <button type="button" className="text-button" disabled={busy || !!step} onClick={() => changeDomain('remove', entry.domain)}>Remove domain</button>
      </li>)}</ul>
    </section>}
    {organizationAccess==='allowed'&&settings && <WorkspaceInvitationTemplates workspace={workspace} organization={settings.name} disabled={busy || !!step} authorize={handle}/> }
    {organizationAccess==='allowed'&&settings && <WorkspaceResidency key={workspace} workspace={workspace} disabled={busy || !!step} authorize={handle}/>}
    <WorkspaceOffboarding key={'offboarding-'+workspace} workspace={workspace}/>
    {organizationAccess==='allowed'&&step && <form className="release-form" aria-label="Verify current sign-in" onSubmit={event => void confirm(event)}>
      <label>{step.assurance === 'totp' ? 'Current authenticator code' : 'Current password'}
        <input name="credential" required type={step.assurance === 'password' ? 'password' : 'text'}
          inputMode={step.assurance === 'totp' ? 'numeric' : undefined}
          autoComplete={step.assurance === 'totp' ? 'one-time-code' : 'current-password'}/>
      </label>
      <button type="submit" className="primary" disabled={busy}>Verify and continue</button>
      <button type="button" className="text-button" disabled={busy} onClick={() => setStep(undefined)}>Cancel verification</button>
    </form>}
    {notice && <p role="status">{notice}</p>}
    {error && <p role="alert">{error}</p>}
  </section>
}
