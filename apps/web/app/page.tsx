'use client'

import { useEffect, useState } from 'react'
import type { Session } from '@supabase/supabase-js'
import { db } from '../lib/data'
import { Brand, Entry } from '../components/entry'
import { Inbox } from '../components/inbox'
import { useLocale } from '../components/locale-provider'
import { WorkspaceContextProvider } from '../components/workspace-context'
import { SignInMfa } from '../components/account-mfa'
import { unsubscribeBrowserPush } from '../components/web-push-settings'

type Access = { user: string; state: 'allowed' | 'challenge' | 'error' }

export default function Home() {
  const { t } = useLocale()
  const [session, setSession] = useState<Session | null>(null)
  const [loaded,setLoaded] = useState(!db)
  const [recovering, setRecovering] = useState(false)
  const [authenticatorReset, setAuthenticatorReset] = useState(false)
  const [access, setAccess] = useState<Access | null>(null)
  const [attempt, setAttempt] = useState(0)
  const user = session?.user.id
  const token = session?.access_token
  useEffect(() => {
    if (!db) return
    const { data } = db.auth.onAuthStateChange((event, value) => {
      if (event === 'PASSWORD_RECOVERY') setRecovering(true)
      if (event === 'SIGNED_OUT') {
        setRecovering(false)
        void unsubscribeBrowserPush().catch(() => undefined)
      }
      if (!value) setAccess(null)
      else if (event === 'SIGNED_IN') setAuthenticatorReset(false)
      setSession(value)
      setLoaded(true)
    })
    return () => data.subscription.unsubscribe()
  }, [])

  useEffect(() => {
    if (!db || !user || !token || recovering) return
    let active = true
    void db.auth.mfa.getAuthenticatorAssuranceLevel(token).then(({ data, error }) => {
      if (!active) return
      setAccess({ user, state: error || !data.currentLevel ? 'error' : data.nextLevel === 'aal2' && data.currentLevel !== 'aal2' ? 'challenge' : 'allowed' })
    }).catch(() => { if (active) setAccess({ user, state: 'error' }) })
    return () => { active = false }
  }, [user, token, recovering, attempt])

  const retry = () => setAttempt(value => value + 1)
  if (!loaded || (user && !recovering && access?.user !== user)) {
    return <main className="center-page"><Brand /><p role="status">{t('opening')}</p></main>
  }
  if (!user || recovering) return <Entry recovering={recovering} authenticatorReset={authenticatorReset} />
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
  return <WorkspaceContextProvider key={user} user={user}><Inbox user={user} /></WorkspaceContextProvider>
}
