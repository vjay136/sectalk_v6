'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { AuditSearch, type AuditWorkspace } from '../../web/components/audit-search'
import { AccountAdministration, type AccountOperatorAccess } from '../../web/components/account-administration'
import { DisclosureQueue } from '../../web/components/disclosure-queue'
import { ModerationQueue } from '../../web/components/moderation-queue'
import { QueueOperations } from '../../web/components/queue-operations'
import { SectionTabs } from '../../web/components/section-tabs'
import { SocResponseActions } from '../../web/components/soc-response-actions'
import { StaffMfa } from '../../web/components/staff-mfa'
import { ThreatTriage, type ThreatTriageAccess } from '../../web/components/threat-triage'
import { db } from '../../web/lib/data'
import { WorkspaceReports } from './workspace-reports'
import { OperatorOverview } from './operator-overview'
import type { FeatureCoverage } from '../lib/feature-coverage'

type Access = 'loading' | 'signed_out' | 'denied' | 'mfa' | 'verified' | 'unavailable'
type Area = 'overview' | 'moderation' | 'workspaceReports' | 'queue' | 'disclosures' | 'accounts' | 'triage' | 'responses' | 'audit'
type Assignment = 'none' | 'mfa' | 'verified'
const idleLimit = 15 * 60 * 1000

export function OperatorConsole({features}: {features: FeatureCoverage[]}) {
  const [access, setAccess] = useState<Access>('loading')
  const [staffModeration, setStaffModeration] = useState(false)
  const [queueAccess, setQueueAccess] = useState<Assignment>('none')
  const [disclosureAccess, setDisclosureAccess] = useState<Assignment>('none')
  const [workspaceAccess, setWorkspaceAccess] = useState<Assignment>('none')
  const [accountAccess, setAccountAccess] = useState<AccountOperatorAccess>('none')
  const [triageAccess, setTriageAccess] = useState<ThreatTriageAccess>({status:'none'})
  const [responseAccess, setResponseAccess] = useState(false)
  const [auditWorkspaces, setAuditWorkspaces] = useState<AuditWorkspace[]>([])
  const [area, setArea] = useState<Area>('overview')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  const request = useRef(0)
  const lastActivity = useRef(0)

  const signOut = useCallback(async () => {
    ++request.current
    setAccess('signed_out')
    setAuditWorkspaces([])
    lastActivity.current = 0
    const result = await db?.auth.signOut({scope: 'local'})
    if (result?.error) setNotice('Could not end your session. Close this browser window.')
  }, [])

  const refresh = useCallback(async () => {
    const version = ++request.current
    if (!db) {setAccess('unavailable'); return}
    const {data, error} = await db.auth.getSession()
    if (version !== request.current) return
    if (error || !data.session) {setAuditWorkspaces([]); setAccess('signed_out'); return}
    if (!lastActivity.current) lastActivity.current = Date.now()
    if (Date.now() - lastActivity.current >= idleLimit) {
      setNotice('Your console session ended after 15 minutes of inactivity.')
      await signOut()
      return
    }
    try {
      const result = await fetch('/api/operator/access', {
        cache: 'no-store', headers: {Authorization: 'Bearer ' + data.session.access_token},
      })
      const value = await result.json()
      if (version !== request.current) return
      const accounts = value.accounts === 'operator' || value.accounts === 'reviewer' || value.accounts === 'mfa' ? value.accounts : 'none'
      const triage = value.triage?.status === 'verified' || value.triage?.status === 'mfa' ? value.triage : {status:'none'}
      const responses = value.responses === true
      if (result.ok && (value.access === 'mfa' || (value.access === 'verified' &&
        (value.moderation === true || value.workspaceReports === 'verified' || accounts === 'operator' || accounts === 'reviewer' ||
          triage.status === 'verified' || responses)))) {
        setStaffModeration(value.moderation === true)
        setQueueAccess(value.queue === 'verified' || value.queue === 'mfa' ? value.queue : 'none')
        setDisclosureAccess(value.disclosures === 'verified' || value.disclosures === 'mfa' ? value.disclosures : 'none')
        setWorkspaceAccess(value.workspaceReports === 'verified' || value.workspaceReports === 'mfa' ? value.workspaceReports : 'none')
        setAccountAccess(accounts)
        setTriageAccess(triage)
        setResponseAccess(responses)
        if (value.access === 'verified') {
          const spaces = await db.rpc('st_v6_audit_workspaces')
          if (version !== request.current) return
          setAuditWorkspaces(!spaces.error && Array.isArray(spaces.data) ? spaces.data : [])
        } else setAuditWorkspaces([])
        setAccess(value.access)
      }
      else {setAuditWorkspaces([]); setAccess([401,403,423].includes(result.status) ? 'denied' : 'unavailable')}
    } catch {
      if (version === request.current) {setAuditWorkspaces([]); setAccess('unavailable')}
    }
  }, [signOut])

  useEffect(() => {
    if (!db) {setAccess('unavailable'); return}
    const activity = () => {
      if (lastActivity.current && Date.now() - lastActivity.current >= idleLimit) void refresh()
      else lastActivity.current = Date.now()
    }
    const check = () => {if (document.visibilityState === 'visible') void refresh()}
    let scheduled: ReturnType<typeof setTimeout>
    const {data} = db.auth.onAuthStateChange((event) => {
      if (event === 'SIGNED_IN') setAuditWorkspaces([])
      if (event === 'SIGNED_OUT') {
        ++request.current
        setAccess('signed_out')
        setAuditWorkspaces([])
      }
      clearTimeout(scheduled)
      scheduled = setTimeout(() => void refresh(), 0)
    })
    const poll = setInterval(() => void refresh(), 15000)
    for (const event of ['pointerdown','keydown']) window.addEventListener(event, activity)
    document.addEventListener('visibilitychange', check)
    return () => {
      ++request.current
      data.subscription.unsubscribe()
      clearTimeout(scheduled)
      clearInterval(poll)
      for (const event of ['pointerdown','keydown']) window.removeEventListener(event, activity)
      document.removeEventListener('visibilitychange', check)
    }
  }, [refresh])

  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy || !db) return
    const values = new FormData(event.currentTarget)
    setBusy(true)
    setNotice('')
    try {
      const response = await fetch('/api/auth/sign-in', {method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({email: values.get('email'), password: values.get('password')})})
      if (response.status === 429) {setNotice('Too many attempts. Wait before trying again.'); return}
      if (!response.ok) throw new Error('Sign-in failed')
      const credentials = await response.json()
      const result = await db.auth.setSession(credentials)
      if (result.error) throw result.error
      lastActivity.current = Date.now()
      await refresh()
    } catch {
      setNotice('Could not sign in. Check your email and password and try again.')
    } finally {setBusy(false)}
  }

  const sections: [Area, string][] = []
  if (staffModeration) sections.push(['overview', 'Overview'])
  if (staffModeration) sections.push(['moderation', 'Moderation'])
  if (staffModeration || workspaceAccess !== 'none') sections.push(['workspaceReports', 'Workspace reports'])
  if (queueAccess !== 'none') sections.push(['queue', 'Queue operations'])
  if (disclosureAccess !== 'none') sections.push(['disclosures', 'Vulnerability disclosures'])
  if (accountAccess !== 'none') sections.push(['accounts', 'Account administration'])
  if (triageAccess.status !== 'none') sections.push(['triage', 'Threat triage'])
  if (responseAccess) sections.push(['responses', 'Response actions'])
  if (auditWorkspaces.length) sections.push(['audit', 'Audit logs'])
  const selected = sections.some(([id]) => id === area) ? area : sections[0]?.[0]
  const needsAuthenticator = access === 'mfa' || (access === 'verified' && (
    (selected === 'queue' && queueAccess === 'mfa') || (selected === 'disclosures' && disclosureAccess === 'mfa') ||
    (selected === 'accounts' && accountAccess === 'mfa') || (selected === 'triage' && triageAccess.status === 'mfa')))

  return <main className="operator-shell">
    <header className="operator-header">
      <div><p className="operator-brand">SecTalk by Eagle Security</p><h1>Operator console</h1></div>
      {['mfa','denied','verified','unavailable'].includes(access) &&
        <button type="button" className="secondary" disabled={busy} onClick={() => {setNotice(''); void signOut()}}>Sign out</button>}
    </header>
    {notice && <p role="alert">{notice}</p>}
    {access === 'verified' && selected && <>
      <div className="operator-nav"><SectionTabs label="Operator sections" value={selected} onChange={setArea} options={sections}/></div>
      {selected === 'overview' && <OperatorOverview features={features} openModeration={() => setArea('moderation')}
        openAccounts={accountAccess !== 'none' ? () => setArea('accounts') : undefined}/>}
      {selected === 'moderation' && <ModerationQueue/>}
      {selected === 'workspaceReports' && <WorkspaceReports platform={staffModeration} workspace={workspaceAccess === 'verified'}/>}
      {selected === 'queue' && queueAccess === 'verified' && <QueueOperations onAccessChanged={refresh}/>}
      {selected === 'disclosures' && disclosureAccess === 'verified' && <DisclosureQueue access="verified" refresh={refresh}/>}
      {selected === 'accounts' && (accountAccess === 'operator' || accountAccess === 'reviewer') &&
        <AccountAdministration access={accountAccess} refresh={refresh}/>}
      {selected === 'triage' && triageAccess.status === 'verified' &&
        <ThreatTriage access={triageAccess} refresh={refresh} showResponseActions={false}/>}
      {selected === 'responses' && responseAccess && <SocResponseActions/>}
      {selected === 'audit' && auditWorkspaces.length > 0 &&
        <AuditSearch key={auditWorkspaces.map(space => space.id).join(',')} workspaces={auditWorkspaces}/>}
    </>}
    {needsAuthenticator ? <section className="operator-card" aria-label="Console authenticator">
      <StaffMfa refresh={refresh} heading="Verify your authenticator" verifyLabel="Verify code"
        explanation="Use the six-digit code for SecTalk from your authenticator app. If this is your first sign-in, set up an authenticator to get a QR code."/>
    </section> : access !== 'verified' && <section className="panel operator-card" aria-label="Console access">
      {access === 'loading' && <p role="status">Checking console access…</p>}
      {access === 'denied' && <><h2>Access unavailable</h2><p>This account does not currently have access to the operator console.</p></>}
      {access === 'unavailable' && <><h2>Could not check console access</h2>
        <button type="button" className="secondary" onClick={() => void refresh()}>Try again</button></>}
      {access === 'signed_out' && <><h2>Operator sign-in</h2><form onSubmit={login}>
        <label>Email<input name="email" type="email" autoComplete="username" maxLength={254} required/></label>
        <label>Password<input name="password" type="password" autoComplete="current-password" maxLength={256} required/></label>
        <button type="submit" disabled={busy}>Sign in</button>
      </form></>}
    </section>}
  </main>
}
