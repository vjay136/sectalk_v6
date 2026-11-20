'use client'

import { useEffect, useState, type FormEvent } from 'react'
import type { Factor } from '@supabase/supabase-js'
import { ShieldCheck } from 'lucide-react'
import { db } from '../lib/data'
import { Brand } from './entry'
import { useLocale } from './locale-provider'

type RecoveryStatus = 'staff' | 'ready' | 'missing'
type Setup = { id: string; qr: string; secret: string }
const authenticatorName = 'SecTalk account'

export function AccountMfa() {
  const { t } = useLocale()
  const [factors, setFactors] = useState<Factor[] | null>(null)
  const [status, setStatus] = useState<RecoveryStatus | null>(null)
  const [setup, setSetup] = useState<Setup | null>(null)
  const [generating, setGenerating] = useState(false)
  const [code, setCode] = useState('')
  const [codes, setCodes] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true
    void Promise.all([db!.auth.mfa.listFactors(), db!.rpc('st_v7_account_recovery_status')]).then(([list, recovery]) => {
      if (!active) return
      if (list.error || recovery.error) setError(t('authenticatorLoadError'))
      if (!list.error) setFactors(list.data.all)
      if (!recovery.error) setStatus(recovery.data)
    })
    return () => { active = false }
  }, [t])

  const verified = factors?.filter(factor => factor.status === 'verified') ?? []
  const totp = verified.find(factor => factor.factor_type === 'totp')

  async function beginSetup() {
    if (!factors || busy) return
    setBusy(true)
    setError('')
    try {
      const current = await db!.auth.mfa.listFactors()
      if (current.error) throw current.error
      for (const factor of current.data.all) {
        if (factor.status === 'unverified' && factor.factor_type === 'totp' && factor.friendly_name === authenticatorName) {
          const discarded = await db!.auth.mfa.unenroll({ factorId: factor.id })
          if (discarded.error && discarded.error.code !== 'mfa_factor_not_found') throw discarded.error
        }
      }
      const { data, error } = await db!.auth.mfa.enroll({ factorType: 'totp', issuer: 'SecTalk', friendlyName: authenticatorName })
      if (error) throw error
      setSetup({ id: data.id, qr: data.totp.qr_code, secret: data.totp.secret })
    } catch {
      setError(t('authenticatorSetupError'))
    } finally {
      setBusy(false)
    }
  }

  async function cancelSetup() {
    if (!setup) return
    setBusy(true)
    const { error } = await db!.auth.mfa.unenroll({ factorId: setup.id })
    setBusy(false)
    if (error && error.code !== 'mfa_factor_not_found') {
      setError(t('authenticatorSetupError'))
      return
    }
    setSetup(null)
    setCode('')
    setError('')
  }

  async function verify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const factorId = setup?.id ?? totp?.id
    if (!factorId || busy) return
    setBusy(true)
    setError('')
    try {
      const result = await db!.auth.mfa.challengeAndVerify({ factorId, code: code.trim() })
      if (result.error) {
        setError(t('authenticatorCodeError'))
        return
      }
      if (setup) {
        setSetup(null)
        const current = await db!.auth.mfa.listFactors()
        if (current.error) throw current.error
        setFactors(current.data.all)
      }
      if (status === 'missing' || status === 'ready') {
        const { data, error } = await db!.rpc('st_v7_generate_recovery_codes')
        if (error) throw error
        setCodes(data)
        setStatus('ready')
      }
      setGenerating(false)
    } catch {
      setError(t('recoveryGenerateError'))
    } finally {
      setCode('')
      setBusy(false)
    }
  }

  return <div className="panel mfa-panel">
    <div className="card-icon"><ShieldCheck size={22} /></div>
    <h2>{t('authenticatorTitle')}</h2>
    <p>{t(totp ? 'authenticatorEnabled' : 'authenticatorDescription')}</p>
    {factors && !totp && !setup && <button className="secondary" type="button" disabled={busy} onClick={() => void beginSetup()}>{t('authenticatorSetup')}</button>}
    {setup && <div className="mfa-setup">
      <img src={setup.qr} alt={t('authenticatorQr')} width={180} height={180} />
      <p>{t('authenticatorManualKey')}</p><code dir="ltr">{setup.secret}</code>
    </div>}
    {totp && status && status !== 'staff' && verified.length === 1 && !generating &&
      <button className="secondary" type="button" disabled={busy} onClick={() => { setGenerating(true); setCodes([]); setError('') }}>
        {t(status === 'ready' ? 'recoveryRegenerate' : 'recoveryGenerate')}
      </button>}
    {status === 'staff' && <p>{t('recoveryStaff')}</p>}
    {generating && status === 'ready' && <p>{t('recoveryReplaceWarning')}</p>}
    {(setup || generating) && <form onSubmit={verify}>
      <label>{t('authenticatorCode')}<input autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} required value={code} onChange={event => setCode(event.target.value)} /></label>
      <button disabled={busy}>{t(generating ? 'recoveryConfirmGenerate' : 'authenticatorVerify')}</button>
      <button className="secondary" type="button" disabled={busy} onClick={() => {
        if (setup) void cancelSetup()
        else { setGenerating(false); setCode(''); setError('') }
      }}>{t('authenticatorCancel')}</button>
    </form>}
    {codes.length > 0 && <div className="mfa-codes">
      <h3>{t('recoveryCodes')}</h3>
      <p>{t('recoverySave')}</p>
      <ul>{codes.map(value => <li key={value}><code dir="ltr">{value}</code></li>)}</ul>
      <button className="secondary" type="button" onClick={() => setCodes([])}>{t('recoveryCodesSaved')}</button>
    </div>}
    {error && <p role="alert">{error}</p>}
  </div>
}

export function SignInMfa({ retry, recovered }: { retry: () => void; recovered: () => void }) {
  const { t } = useLocale()
  const [factors, setFactors] = useState<Factor[]>([])
  const [factorId, setFactorId] = useState('')
  const [status, setStatus] = useState<RecoveryStatus | null>(null)
  const [recovery, setRecovery] = useState(false)
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true
    void Promise.all([db!.auth.mfa.listFactors(), db!.rpc('st_v7_account_recovery_status')]).then(([list, recoveryStatus]) => {
      if (!active) return
      if (list.error || !list.data.totp.length) setError(t('authenticatorLoadError'))
      if (!list.error) {
        setFactors(list.data.totp)
        setFactorId(list.data.totp[0]?.id ?? '')
      }
      if (!recoveryStatus.error) setStatus(recoveryStatus.data)
    })
    return () => { active = false }
  }, [t])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    setBusy(true)
    setError('')
    try {
      if (recovery) {
        const { data, error } = await db!.rpc('st_v7_recover_authenticator', { p_code: code })
        if (error || !data) {
          setError(t(error?.code === 'PT429' ? 'recoveryRateLimit' : 'recoveryCodeError'))
          return
        }
        recovered()
        const result = await db!.auth.signOut({ scope: 'local' })
        if (result.error) retry()
      } else {
        const { error } = await db!.auth.mfa.challengeAndVerify({ factorId, code: code.trim() })
        if (error) setError(t('authenticatorCodeError'))
        else retry()
      }
    } catch {
      setError(t(recovery ? 'recoveryCodeError' : 'authenticatorCodeError'))
    } finally {
      setCode('')
      setBusy(false)
    }
  }

  return <main className="center-page"><Brand /><section className="panel mfa-panel account-mfa-challenge">
    <h1>{t(recovery ? 'recoveryTitle' : 'authenticatorSignIn')}</h1>
    <p>{t(recovery ? 'recoveryResetWarning' : 'authenticatorSignInDescription')}</p>
    <form onSubmit={submit}>
      {!recovery && factors.length > 1 && <label>{t('authenticatorTitle')}<select value={factorId} onChange={event => setFactorId(event.target.value)}>
        {factors.map((factor, index) => <option value={factor.id} key={factor.id}>{factor.friendly_name || `${t('authenticatorTitle')} ${index + 1}`}</option>)}
      </select></label>}
      <label>{t(recovery ? 'recoveryCode' : 'authenticatorCode')}
        <input value={code} onChange={event => setCode(event.target.value)} autoComplete={recovery ? 'off' : 'one-time-code'} dir="ltr"
          inputMode={recovery ? 'text' : 'numeric'} pattern={recovery ? undefined : '[0-9]{6}'} maxLength={recovery ? 64 : 6} spellCheck={false} required />
      </label>
      <button disabled={busy || (!recovery && !factorId)}>{t(recovery ? 'recoveryReset' : 'authenticatorVerify')}</button>
    </form>
    {error && <p role="alert">{error}</p>}
    {status === 'staff' && <p>{t('recoveryStaff')}</p>}
    {status === 'ready' && <button type="button" className="secondary" disabled={busy} onClick={() => { setRecovery(!recovery); setCode(''); setError('') }}>
      {t(recovery ? 'authenticatorUseCode' : 'recoveryUseCode')}
    </button>}
    <button type="button" className="secondary" disabled={busy} onClick={() => void db!.auth.signOut({ scope: 'local' })}>{t('signOut')}</button>
  </section></main>
}
