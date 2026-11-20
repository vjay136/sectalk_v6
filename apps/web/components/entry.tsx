'use client'

import { useEffect, useRef, useState, type FormEvent } from 'react'
import Image from 'next/image'
import {
  ArrowLeft, ArrowRight, AudioLines, Check, Fingerprint, Flag, KeyRound,
  LockKeyhole, Mail, Phone, Send, Shield, ShieldCheck, Video,
} from 'lucide-react'
import { db, transientAuthClient } from '../lib/data'
import type { PlainMessageKey } from '../lib/locale'
import { LanguageSelect, useLocale } from './locale-provider'

export function Brand({ compact = false }: { compact?: boolean }) {
  return <div className={'brand' + (compact ? ' compact-brand' : '')}>
    <Image src="/sectalk-logo.webp" alt={compact ? 'SecTalk' : ''} width={44} height={44} className="brand-image" />
    {!compact && <span>SecTalk<small>EAGLE SECURITY</small></span>}
  </div>
}

type Step = 'sign-in' | 'sign-up' | 'confirm' | 'forgot' | 'recover' | 'new-password'

const steps = {
  'sign-in': ['signInTitle', 'signInDescription', 'signIn'],
  'sign-up': ['signUpTitle', 'signUpDescription', 'signUp'],
  confirm: ['confirmTitle', 'confirmDescription', 'backToSignIn'],
  forgot: ['forgotTitle', 'forgotDescription', 'sendRecoveryCode'],
  recover: ['recoverTitle', 'recoverDescription', 'verifyCode'],
  'new-password': ['newPasswordTitle', 'newPasswordDescription', 'updatePassword'],
} as const

function authMessage(error: { code?: string; status?: number }, step: Step): PlainMessageKey {
  if (error.code === 'over_email_send_rate_limit') return 'emailRateLimit'
  if (error.status === 429) return 'tooManyRequests'
  if (error.code === 'weak_password') return 'weakPassword'
  if (step === 'sign-in') return 'invalidSignIn'
  if (step === 'recover') return 'invalidRecoveryCode'
  if (step === 'new-password') return error.code === 'same_password' ? 'samePassword' : 'passwordUpdateFailed'
  return 'verificationSendFailed'
}

export function Entry({ recovering, authenticatorReset, startRecovery }: { recovering: boolean; authenticatorReset?: boolean; startRecovery?: boolean }) {
  const { t } = useLocale()
  const [step, setStep] = useState<Step>(startRecovery?'forgot':'sign-in')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [code, setCode] = useState('')
  const [recoveryFactor,setRecoveryFactor]=useState('')
  const [factorCode,setFactorCode]=useState('')
  const [busy, setBusy] = useState(false)
  const [alert, setAlert] = useState<PlainMessageKey | ''>('')
  const [info, setInfo] = useState<PlainMessageKey | ''>('')
  const recovery = useRef<ReturnType<typeof transientAuthClient>>(null)
  const heading = useRef<HTMLHeadingElement>(null)
  const current = recovering ? 'new-password' : step
  const [title, description, action] = steps[current]
  const passwordRequired = current === 'sign-in' || current === 'sign-up' || current === 'new-password'
  const newPassword = current === 'new-password' || current === 'sign-up'
  const codeRequired = current === 'recover'
  const checkEmail = current === 'confirm' || codeRequired
  const showEmail = current === 'sign-in' || current === 'sign-up' || current === 'forgot'

  function go(next: Step, message: PlainMessageKey | '' = '') {
    setStep(next)
    setPassword('')
    setConfirmation('')
    setCode('')
    if (next !== 'new-password') {setRecoveryFactor('');setFactorCode('')}
    setAlert('')
    setInfo(message)
  }

  useEffect(() => {
    if (current !== 'sign-in') heading.current?.focus({ preventScroll: true })
  }, [current])

  useEffect(() => {
    if (new URLSearchParams(window.location.search).get('mode') === 'signup') setStep('sign-up')
  }, [])

  useEffect(() => {
    if (!recovering) return
    let active=true
    void db?.auth.mfa.listFactors().then(({data,error})=>{
      if (active&&!error) setRecoveryFactor(data.totp.find(factor=>factor.status==='verified')?.id??'')
    })
    return ()=>{active=false}
  }, [recovering])

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (busy) return
    if (current === 'confirm') { await backToSignIn(); return }
    setAlert('')
    setInfo('')
    if (!db) { setAlert('signInUnavailable'); return }
    if (newPassword && password !== confirmation) { setAlert('passwordMismatch'); return }
    if (newPassword && (password.length < 12 || new TextEncoder().encode(password).length > 72)) {
      setAlert('invalidPasswordLength')
      return
    }
    setBusy(true)
    const address = email.trim()
    try {
      switch (current) {
        case 'sign-in': {
          const { error } = await db.auth.signInWithPassword({ email: address, password })
          if (error?.code === 'email_not_confirmed') {
            go('confirm', 'verificationReminder')
            return
          }
          if (error) throw error
          break
        }
        case 'sign-up': {
          const { error } = await db.auth.signUp({ email: address, password, options: { emailRedirectTo: window.location.origin + '/auth/confirm' } })
          if (error) throw error
          go('confirm')
          break
        }
        case 'forgot': {
          const { error } = await db.auth.resetPasswordForEmail(address, { redirectTo: window.location.origin })
          if (error) throw error
          go('recover')
          break
        }
        case 'recover': {
          const client = transientAuthClient()
          const result = await client!.auth.verifyOtp({ email: address, token: code, type: 'recovery' })
          if (result.error) throw result.error
          const factors=await client!.auth.mfa.listFactors()
          if (factors.error) throw factors.error
          setRecoveryFactor(factors.data.totp.find(factor=>factor.status==='verified')?.id??'')
          recovery.current = client
          go('new-password')
          break
        }
        case 'new-password': {
          const client = recovering ? db : recovery.current
          if (!client) { go('forgot'); return }
          if (recoveryFactor) {
            const assurance=await client.auth.mfa.challengeAndVerify({factorId:recoveryFactor,code:factorCode})
            if (assurance.error) {setAlert('authenticatorCodeError');return}
            setRecoveryFactor('')
            setFactorCode('')
          }
          const { error } = await client.auth.updateUser({ password })
          if (error) throw error
          await client.rpc('st_v7_note_lockdown_password_recovery')
          await client.auth.signOut({ scope: 'global' })
          recovery.current = null
          go('sign-in', 'passwordUpdated')
          break
        }
      }
    } catch (error) {
      setAlert(authMessage(error as { code?: string; status?: number }, current))
    } finally {
      setBusy(false)
    }
  }

  async function resend() {
    if (!db || busy) return
    setAlert('')
    setInfo('')
    setBusy(true)
    try {
      const address = email.trim()
      const result = current === 'confirm'
        ? await db.auth.resend({ type: 'signup', email: address, options: { emailRedirectTo: window.location.origin + '/auth/confirm' } })
        : await db.auth.resetPasswordForEmail(address, { redirectTo: window.location.origin })
      if (result.error) throw result.error
      setCode('')
      setInfo(current === 'confirm'
        ? 'verificationResent'
        : 'recoveryResent')
    } catch (error) {
      setAlert(authMessage(error as { code?: string; status?: number }, current === 'confirm' ? 'sign-up' : 'forgot'))
    } finally {
      setBusy(false)
    }
  }

  async function backToSignIn() {
    if (recovering) await db?.auth.signOut({ scope: 'local' })
    else if (recovery.current) await recovery.current.auth.signOut({ scope: 'local' })
    recovery.current = null
    go('sign-in')
  }

  return <main className="landing">
    <header className="site-header">
      <Brand />
      <LanguageSelect />
      <a className="header-link" href="#safety"><Shield size={16} /> {t('safetyPrivacy')}</a>
      <a className="header-cta" href="#account" onClick={() => { if (!busy) void backToSignIn() }}>{t('signIn')} <ArrowRight size={15} /></a>
    </header>
    <section className="access-layout">
      <div className="hero-copy">
        <div className="eyebrow"><span /> {t('eyebrow')}</div>
        <h1>{t('privateByDesign')}<br /><em>{t('yoursToControl')}</em></h1>
        <p>{t('heroDescription')}</p>
        <div className="threat-visual" aria-hidden="true">
          <div className="signal-orbit orbit-one" /><div className="signal-orbit orbit-two" />
          <Image src="/sectalk-logo.webp" alt="" width={180} height={180} className="hero-logo" priority />
          <div className="comms-preview">
            <div className="preview-head"><span className="preview-icon"><AudioLines size={16} /></span><div><b>Avery Morgan</b><small>{t('acceptedContact')}</small></div><Phone size={15} /><Video size={17} /></div>
            <div className="preview-messages"><span>{t('readyWhenYouAre')}</span><span>{t('letsTalk')} <Check size={13}/></span></div>
          </div>
        </div>
      </div>
      <section id="account" className="auth-shell" aria-label={t('yourAccount')}>
        <form className="auth-card access-card" onSubmit={submit}>
          {(current === 'sign-in' || current === 'sign-up') && <div className="auth-tabs" aria-label={t('accountAccess')}>
            <button type="button" disabled={busy} aria-pressed={current === 'sign-in'} onClick={() => go('sign-in')}>{t('signIn')}</button>
            <button type="button" disabled={busy} aria-pressed={current === 'sign-up'} onClick={() => go('sign-up')}>{t('signUp')}</button>
          </div>}
          <div className="card-icon">{checkEmail ? <Mail size={21} /> : current === 'new-password' ? <KeyRound size={21} /> : <LockKeyhole size={21} />}</div>
          <div className="auth-intro">
            <h2 ref={heading} tabIndex={-1}>{t(title)}</h2>
            <p>{t(description)}{checkEmail && <> <strong dir="ltr">{email}</strong>.</>}</p>
          </div>
          {showEmail && <label>{t('emailAddress')}<div className="input-icon"><Mail size={16} /><input dir="ltr" type="email" autoComplete="email" maxLength={254} required placeholder="you@example.com" value={email} onChange={event => setEmail(event.target.value)} /></div></label>}
          {passwordRequired && <label>{t('password')}<div className="input-icon"><KeyRound size={16} /><input key={current} type="password" autoComplete={newPassword ? 'new-password' : 'current-password'} minLength={newPassword ? 12 : undefined} maxLength={256} required placeholder={newPassword ? t('minimumPassword') : t('yourPassword')} value={password} onChange={event => setPassword(event.target.value)} /></div></label>}
          {newPassword && <label>{t('confirmPassword')}<div className="input-icon"><KeyRound size={16} /><input type="password" autoComplete="new-password" minLength={12} maxLength={256} required placeholder={t('reenterPassword')} value={confirmation} onChange={event => setConfirmation(event.target.value)} /></div></label>}
          {current==='new-password'&&recoveryFactor&&<label>{t('authenticatorCode')}<input name="recovery-authenticator"
            autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} required value={factorCode}
            onChange={event=>setFactorCode(event.target.value)}/></label>}
          {codeRequired && <label>{t('verificationCode')}<input dir="ltr" className="code-input" type="text" autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]{6,10}" maxLength={10} required placeholder={t('enterEmailCode')} value={code} onChange={event => setCode(event.target.value.replace(/\D/g, ''))} /></label>}
          {current === 'sign-in' && <button className="text-button forgot" type="button" disabled={busy} onClick={() => go('forgot')}>{t('forgotPassword')}</button>}
          {alert && <p className="form-message error" role="alert">{t(alert)}</p>}
          {info && <p className="form-message success" role="status">{t(info)}</p>}
          {authenticatorReset && current === 'sign-in' && <p className="form-message success" role="status">{t('authenticatorResetComplete')}</p>}
          <button className="primary submit-auth" disabled={busy}>{busy ? t('pleaseWait') : t(action)} <ArrowRight size={18} /></button>
          {current !== 'sign-in' && current !== 'sign-up' && <div className="form-links">
            {current !== 'confirm' && <button type="button" disabled={busy} onClick={() => void backToSignIn()}><ArrowLeft size={14} /> {t('backToSignIn')}</button>}
            {checkEmail && <button type="button" onClick={resend} disabled={busy}>{current === 'confirm' ? t('resendLink') : t('resendCode')}</button>}
          </div>}
          {current === 'confirm' && <p className="form-message">
            {t('alreadyVerified')} <button className="text-button" type="button" disabled={busy} onClick={() => go('forgot')}>{t('resetPasswordLink')}</button>.
          </p>}
        </form>
        <div className="auth-footnote"><Fingerprint size={16} /> {current === 'sign-up' || checkEmail ? t('verificationFootnote') : t('contactsFootnote')}</div>
      </section>
    </section>
    <section id="safety" className="benefits">
      <div><span className="benefit-icon"><ShieldCheck /></span><h2>{t('contactApproval')}</h2><p>{t('contactApprovalDescription')}</p></div>
      <div><span className="benefit-icon"><AudioLines /></span><h2>{t('liveConversations')}</h2><p>{t('liveConversationsDescription')}</p></div>
      <div><span className="benefit-icon"><Flag /></span><h2>{t('safetyControls')}</h2><p>{t('safetyControlsDescription')}</p></div>
    </section>
    <footer className="site-footer"><Brand />
      <nav aria-label="Public information">
        <a href="/about">Overview</a><a href="/pricing">Pricing</a><a href="/docs">Docs</a><a href="/legal/privacy">Privacy</a>
        <a href="/status">{t('serviceStatus')}</a><a href="/security">{t('securityDisclosures')}</a><a href="#account">{t('accountAccess')} <Send size={14}/></a>
      </nav>
    </footer>
  </main>
}
