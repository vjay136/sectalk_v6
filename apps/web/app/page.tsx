'use client'

import { useEffect, useState } from 'react'
import type { Session } from '@supabase/supabase-js'
import { db } from '../lib/data'
import { Brand, Entry } from '../components/entry'
import { Inbox } from '../components/inbox'
import { useLocale } from '../components/locale-provider'
import { WorkspaceContextProvider } from '../components/workspace-context'
import { SignInMfa } from '../components/account-mfa'
import { DeviceLockScreen, useDeviceProtection } from '../components/device-lock-screen'
import { AccountLockdownScreen, type AccountLock } from '../components/login-anomalies'
import { LoginStepUp } from '../components/login-step-up'
import { unsubscribeBrowserPush } from '../components/web-push-settings'

type Access = { user: string; state: 'allowed' | 'challenge' | 'error'; lockdown?: AccountLock; risk?: 'email' | 'refresh' }

export default function Home() {
  const { t } = useLocale()
  const [session, setSession] = useState<Session | null>(null)
  const [loaded,setLoaded] = useState(!db)
  const [recovering, setRecovering] = useState(false)
  const [authenticatorReset, setAuthenticatorReset] = useState(false)
  const [startRecovery, setStartRecovery] = useState(false)
  const [access, setAccess] = useState<Access | null>(null)
  const [attempt, setAttempt] = useState(0)
  const user = session?.user.id
  const token = session?.access_token
  const protection = useDeviceProtection(user)
  useEffect(() => {
    if (!db) return
    const { data } = db.auth.onAuthStateChange((event, value) => {
      if (event === 'PASSWORD_RECOVERY') setRecovering(true)
      if (event === 'SIGNED_OUT') {
        setRecovering(false)
        void unsubscribeBrowserPush().catch(() => undefined)
      }
      if (!value) setAccess(null)
      else if (event === 'SIGNED_IN') {setAuthenticatorReset(false);setStartRecovery(false)}
      setSession(value)
      setLoaded(true)
    })
    return () => data.subscription.unsubscribe()
  }, [])

  useEffect(() => {
    if (!db || !user || !token || recovering) return
    let active = true
    const client = db
    void Promise.all([
      client.auth.mfa.getAuthenticatorAssuranceLevel(token),
      client.rpc('st_v7_current_session_valid'),
      client.rpc('st_v7_account_lock_status'),
      client.rpc('st_v7_login_risk_status'),
    ]).then(([assurance, validation, lockdown, risk]) => {
      if (!active) return
      if (!validation.error && validation.data === false) {
        void client.auth.signOut({scope:'local'})
        return
      }
      const {data,error}=assurance
      setAccess({ user, state: error || validation.error || lockdown.error || risk.error || !data.currentLevel ? 'error'
        : risk.data==='authenticator'||(data.nextLevel==='aal2'&&data.currentLevel!=='aal2') ? 'challenge' : 'allowed',
        lockdown:(lockdown.data as AccountLock|null)??undefined,
        risk:(risk.data==='email'||risk.data==='refresh')?risk.data:undefined })
    }).catch(() => { if (active) setAccess({ user, state: 'error' }) })
    return () => { active = false }
  }, [user, token, recovering, attempt])

  useEffect(() => {
    if (!db || !user || recovering) return
    const client = db
    let active = true
    const check = () => {
      if (document.visibilityState !== 'visible') return
      void client.rpc('st_v7_current_session_valid').then(({data,error})=>{
        if (active && !error && data === false) void client.auth.signOut({scope:'local'})
      })
    }
    const timer = window.setInterval(check,60000)
    document.addEventListener('visibilitychange',check)
    window.addEventListener('online',check)
    return () => {
      active = false
      window.clearInterval(timer)
      document.removeEventListener('visibilitychange',check)
      window.removeEventListener('online',check)
    }
  }, [user,recovering])

  const retry = () => setAttempt(value => value + 1)
  if (!loaded || (user && !recovering && (access?.user !== user || !protection.checked || protection.value?.wiped))) {
    return <main className="center-page"><Brand /><p role="status">{t('opening')}</p></main>
  }
  if (!user || recovering) return <Entry recovering={recovering} authenticatorReset={authenticatorReset} startRecovery={startRecovery} />
  if (access?.state === 'challenge') return <SignInMfa key={user} retry={retry} recovered={() => {
    setAuthenticatorReset(true)
    setSession(null)
    setAccess(null)
  }} />
  if (access?.state === 'error') return <main className="center-page"><Brand /><section className="panel mfa-panel account-mfa-challenge">
    <p role="alert">{t('authenticatorLoadError')}</p>
    <button type="button" onClick={retry}>{t('authenticatorRetry')}</button>
    <button type="button" className="secondary" onClick={() => void db!.auth.signOut({ scope: 'local' })}>{t('signOut')}</button>
  </section></main>
  if (access?.lockdown?.locked) return <AccountLockdownScreen status={access.lockdown} refresh={retry} startRecovery={()=>{
    setStartRecovery(true)
    void db!.auth.signOut({scope:'local'})
  }}/>
  if (access?.risk) return <LoginStepUp key={user} email={session?.user.email??null} refreshNeeded={access.risk==='refresh'}
    hasLocalDevice={Boolean(protection.value&&!protection.value.locked&&!protection.value.unavailable)} complete={retry}/>
  if (protection.value && (protection.value.locked || protection.value.unavailable))
    return <DeviceLockScreen device={protection.value.device} unavailable={protection.value.unavailable} refresh={protection.refresh}/>
  return <WorkspaceContextProvider key={user} user={user}><Inbox user={user} /></WorkspaceContextProvider>
}
