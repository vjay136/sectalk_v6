'use client'

import { useEffect, useState, type FormEvent } from 'react'
import type { Factor } from '@supabase/supabase-js'
import { ShieldCheck } from 'lucide-react'
import { db, passkeysEnabled } from '../lib/data'
import { Brand } from './entry'
import { useLocale } from './locale-provider'
import { AccountSecurityChanges } from './account-security-changes'
import { LoginAnomalies } from './login-anomalies'
import { AccountPasskeys } from './account-passkeys'
import {PermissionCatalog} from './permission-catalog'
import { verifyAccountCredential } from '../lib/account-credential'

type RecoveryStatus = 'staff' | 'ready' | 'missing'
type Setup = { id: string; qr: string; secret: string }
const authenticatorName = 'SecTalk account'

function AccountRecoveryKey() {
  const [status, setStatus] = useState('')
  const [action, setAction] = useState<'issue'|'revoke'|null>(null)
  const [key, setKey] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => {
    let active=true
    void db!.rpc('st_v7_manage_recovery_key',{p_action:'status'}).then(result=>{
      if (active) setStatus(result.error ? 'unavailable' : result.data)
    })
    return ()=>{active=false}
  },[])
  async function submit(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!action || busy) return
    const form=event.currentTarget
    setBusy(true)
    setError('')
    try {
      await verifyAccountCredential(String(new FormData(form).get('recovery-key-otp') ?? ''),true)
      const {data,error}=await db!.rpc('st_v7_manage_recovery_key',{p_action:action})
      if (error || (action==='issue' ? !/^[0-9A-F]{64}$/.test(data) : data!=='revoked')) throw new Error()
      setKey(action==='issue' ? data : '')
      setStatus(action==='issue' ? 'configured' : 'missing')
      setAction(null)
    } catch {
      setError('Could not update your recovery key. Check your authenticator code.')
    } finally {
      form.reset()
      setBusy(false)
    }
  }
  if (status!=='missing' && status!=='configured') return null
  return <section className="panel mfa-panel" aria-label="Account recovery key">
    <h3>Account recovery key</h3>
    <p>{status==='configured' ? 'A recovery key is active.' : 'Create a key to recover access if you lose your authenticator.'}</p>
    {key && <div>
      <p>Save this key somewhere safe. It is shown only once.</p>
      <output aria-label="Your recovery key" dir="ltr">{key}</output>
      <button type="button" className="secondary" onClick={()=>setKey('')}>I saved my recovery key</button>
    </div>}
    {!action && !key && <div className="actions">
      <button type="button" className="secondary" onClick={()=>setAction('issue')}>{status==='configured'?'Replace recovery key':'Create recovery key'}</button>
      {status==='configured' && <button type="button" className="secondary" onClick={()=>setAction('revoke')}>Revoke recovery key</button>}
    </div>}
    {action && <form onSubmit={submit}>
      {status==='configured' && <p>This invalidates your previous key and cancels any pending recovery using it.</p>}
      <label>Authenticator code for recovery key<input name="recovery-key-otp" inputMode="numeric" pattern="[0-9]{6}"
        autoComplete="one-time-code" maxLength={6} required/></label>
      <button disabled={busy}>Verify and {action==='revoke'?'revoke':'save a new'} recovery key</button>
      <button className="secondary" type="button" disabled={busy} onClick={()=>setAction(null)}>Cancel key change</button>
    </form>}
    {error && <p role="alert">{error}</p>}
  </section>
}

export function AccountMfa({hints}: {hints: EventTarget}) {
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

  return <><div className="panel mfa-panel">
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
  </div><PermissionCatalog/>{passkeysEnabled && <AccountPasskeys/>}{factors && status && <>
    {totp && verified.length===1 && status!=='staff' && <AccountRecoveryKey/>}
    <AccountSecurityChanges hints={hints} hasAuthenticator={Boolean(totp)} staff={status === 'staff'}/>
    <LoginAnomalies hints={hints} hasFactor={Boolean(totp)}/>
  </>}</>
}

export function SignInMfa({ retry, recovered }: { retry: () => void; recovered: () => void }) {
  const { t } = useLocale()
  const [factors, setFactors] = useState<Factor[]>([])
  const [factorId, setFactorId] = useState('')
  const [status, setStatus] = useState<RecoveryStatus | null>(null)
  const [recovery, setRecovery] = useState<'code'|'key'|'device'|null>(null)
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [recoveryPending, setRecoveryPending] = useState('')

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
        const { data, error } = await db!.rpc('st_v7_recovery_security_reset', { p_code: recovery==='device'?'device-approval':code })
        if (error || data === 'unavailable') {
          setError(t(error?.code === 'PT429' ? 'recoveryRateLimit' : 'recoveryCodeError'))
          return
        }
        if (data === 'pending') {
          if (recovery==='device') {
            setRecoveryPending('Open Account security changes on your previously trusted device and approve the request. After 24 hours, sign in and continue with this method.')
            return
          }
          setRecoveryPending('Recovery can continue after the 24-hour cooling-off period. Sign in again and use the same recovery key or code.')
          return
        }
        if (data !== 'completed') return
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
      {recovery!=='device' && <label>{recovery==='key'?'Recovery key':t(recovery==='code'?'recoveryCode':'authenticatorCode')}
        <input value={code} onChange={event => setCode(event.target.value)} autoComplete={recovery ? 'off' : 'one-time-code'} dir="ltr"
          inputMode={recovery ? 'text' : 'numeric'} pattern={recovery ? undefined : '[0-9]{6}'} maxLength={recovery ? 64 : 6} spellCheck={false} required />
      </label>}
      <button disabled={busy || (!recovery && !factorId)}>{recovery==='device'?'Request or continue device recovery':t(recovery ? 'recoveryReset' : 'authenticatorVerify')}</button>
    </form>
    {error && <p role="alert">{error}</p>}
    {recoveryPending && <p role="status">{recoveryPending}</p>}
    {status === 'staff' && <p>{t('recoveryStaff')}</p>}
    {status && status!=='staff' && <div className="actions">
      {status==='ready' && recovery!=='code' && <button type="button" className="secondary" disabled={busy}
        onClick={()=>{setRecovery('code');setCode('');setError('');setRecoveryPending('')}}>{t('recoveryUseCode')}</button>}
      {recovery!=='key' && <button type="button" className="secondary" disabled={busy}
        onClick={()=>{setRecovery('key');setCode('');setError('');setRecoveryPending('')}}>Use a recovery key</button>}
      {recovery!=='device' && <button type="button" className="secondary" disabled={busy}
        onClick={()=>{setRecovery('device');setCode('');setError('');setRecoveryPending('')}}>Recover with a trusted device</button>}
      {recovery && <button type="button" className="secondary" disabled={busy}
        onClick={()=>{setRecovery(null);setCode('');setError('');setRecoveryPending('')}}>{t('authenticatorUseCode')}</button>}
    </div>}
    <button type="button" className="secondary" disabled={busy} onClick={() => void db!.auth.signOut({ scope: 'local' })}>{t('signOut')}</button>
  </section></main>
}
