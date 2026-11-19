'use client'

import { useEffect, useRef, useState, type FormEvent } from 'react'
import Image from 'next/image'
import {
  ArrowLeft, ArrowRight, AudioLines, Check, Fingerprint, Flag, KeyRound,
  LockKeyhole, Mail, Phone, Send, Shield, ShieldCheck, Video,
} from 'lucide-react'
import { db, recoveryClient } from '../lib/data'

export function Brand({ compact = false }: { compact?: boolean }) {
  return <div className={'brand' + (compact ? ' compact-brand' : '')}>
    <Image src="/sectalk-logo.webp" alt={compact ? 'SecTalk' : ''} width={44} height={44} className="brand-image" />
    {!compact && <span>SecTalk<small>EAGLE SECURITY</small></span>}
  </div>
}

type Step = 'sign-in' | 'sign-up' | 'confirm' | 'forgot' | 'recover' | 'new-password'

const steps = {
  'sign-in': ['Sign in to SecTalk', 'Use the email address and password for your account.', 'Sign in'],
  'sign-up': ['Create your account', 'Choose a password. We’ll email you a code to verify your address.', 'Create account'],
  confirm: ['Verify your email', 'Enter the verification code sent to', 'Verify email'],
  forgot: ['Reset your password', 'Enter your account email to receive a recovery code.', 'Send recovery code'],
  recover: ['Verify your recovery code', 'Enter the recovery code sent to', 'Verify code'],
  'new-password': ['Set a new password', 'Use a password you haven’t used for this account before.', 'Update password'],
} as const

function authMessage(error: { code?: string; status?: number }, step: Step) {
  if (error.status === 429 || error.code === 'over_email_send_rate_limit') return 'Too many requests. Wait a minute and try again.'
  if (error.code === 'weak_password') return 'Choose a stronger password with at least 12 characters.'
  if (step === 'sign-in') return 'Check your email and password, then try again.'
  if (step === 'confirm' || step === 'recover') return 'This code is invalid or expired. Request a new code and try again.'
  if (step === 'new-password') return error.code === 'same_password' ? 'Choose a password different from your current password.' : 'Your password could not be updated. If the recovery session expired, request a new code.'
  return 'We couldn’t send a verification email. Check the address and try again.'
}

export function Entry({ recovering }: { recovering: boolean }) {
  const [step, setStep] = useState<Step>('sign-in')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [alert, setAlert] = useState('')
  const [info, setInfo] = useState('')
  const recovery = useRef<ReturnType<typeof recoveryClient>>(null)
  const heading = useRef<HTMLHeadingElement>(null)
  const current = recovering ? 'new-password' : step
  const [title, description, action] = steps[current]
  const passwordRequired = current === 'sign-in' || current === 'sign-up' || current === 'new-password'
  const newPassword = current === 'new-password' || current === 'sign-up'
  const codeRequired = current === 'confirm' || current === 'recover'
  const showEmail = current === 'sign-in' || current === 'sign-up' || current === 'forgot'

  function go(next: Step, message = '') {
    setStep(next)
    setPassword('')
    setConfirmation('')
    setCode('')
    setAlert('')
    setInfo(message)
  }

  useEffect(() => {
    if (current !== 'sign-in') heading.current?.focus({ preventScroll: true })
  }, [current])

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (busy) return
    setAlert('')
    setInfo('')
    if (!db) { setAlert('Sign-in is unavailable until SecTalk is configured.'); return }
    if (newPassword && password !== confirmation) { setAlert('The passwords don’t match.'); return }
    if (newPassword && (password.length < 12 || new TextEncoder().encode(password).length > 72)) {
      setAlert('Use at least 12 characters and at most 72 bytes. Some characters count as more than one byte.')
      return
    }
    setBusy(true)
    const address = email.trim()
    try {
      switch (current) {
        case 'sign-in': {
          const { error } = await db.auth.signInWithPassword({ email: address, password })
          if (error?.code === 'email_not_confirmed') {
            go('confirm', 'Use your original signup code or request another one.')
            return
          }
          if (error) throw error
          break
        }
        case 'sign-up': {
          const { error } = await db.auth.signUp({ email: address, password, options: { emailRedirectTo: window.location.origin } })
          if (error) throw error
          go('confirm')
          break
        }
        case 'confirm': {
          const { error } = await db.auth.verifyOtp({ email: address, token: code, type: 'email' })
          if (error) throw error
          break
        }
        case 'forgot': {
          const { error } = await db.auth.resetPasswordForEmail(address, { redirectTo: window.location.origin })
          if (error) throw error
          go('recover')
          break
        }
        case 'recover': {
          const client = recoveryClient()
          const result = await client!.auth.verifyOtp({ email: address, token: code, type: 'recovery' })
          if (result.error) throw result.error
          recovery.current = client
          go('new-password')
          break
        }
        case 'new-password': {
          const client = recovering ? db : recovery.current
          if (!client) { go('forgot'); return }
          const { error } = await client.auth.updateUser({ password })
          if (error) throw error
          await client.auth.signOut({ scope: 'global' })
          recovery.current = null
          go('sign-in', 'Password updated. Sign in with your new password.')
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
        ? await db.auth.resend({ type: 'signup', email: address, options: { emailRedirectTo: window.location.origin } })
        : await db.auth.resetPasswordForEmail(address, { redirectTo: window.location.origin })
      if (result.error) throw result.error
      setCode('')
      setInfo('If the address is eligible, a new code is on its way.')
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
      <a className="header-link" href="#safety"><Shield size={16} /> Safety & privacy</a>
      <a className="header-cta" href="#account" onClick={() => { if (!busy) void backToSignIn() }}>Sign in <ArrowRight size={15} /></a>
    </header>
    <section className="access-layout">
      <div className="hero-copy">
        <div className="eyebrow"><span /> SECURE MESSAGING BY EAGLE SECURITY</div>
        <h1>Private by design.<br /><em>Yours to control.</em></h1>
        <p>Real-time messages, audio and video with the people you approve. Block unwanted contact and report abuse from the conversation.</p>
        <div className="threat-visual" aria-hidden="true">
          <div className="signal-orbit orbit-one" /><div className="signal-orbit orbit-two" />
          <Image src="/sectalk-logo.webp" alt="" width={180} height={180} className="hero-logo" priority />
          <div className="comms-preview">
            <div className="preview-head"><span className="preview-icon"><AudioLines size={16} /></span><div><b>Avery Morgan</b><small>Accepted contact</small></div><Phone size={15} /><Video size={17} /></div>
            <div className="preview-messages"><span>Ready when you are.</span><span>Let’s talk. <Check size={13}/></span></div>
          </div>
        </div>
      </div>
      <section id="account" className="auth-shell" aria-label="Your account">
        <form className="auth-card access-card" onSubmit={submit}>
          {(current === 'sign-in' || current === 'sign-up') && <div className="auth-tabs" aria-label="Account access">
            <button type="button" disabled={busy} aria-pressed={current === 'sign-in'} onClick={() => go('sign-in')}>Sign in</button>
            <button type="button" disabled={busy} aria-pressed={current === 'sign-up'} onClick={() => go('sign-up')}>Create account</button>
          </div>}
          <div className="card-icon">{codeRequired ? <Mail size={21} /> : current === 'new-password' ? <KeyRound size={21} /> : <LockKeyhole size={21} />}</div>
          <div className="auth-intro">
            <h2 ref={heading} tabIndex={-1}>{title}</h2>
            <p>{description}{codeRequired && <> <strong>{email}</strong>.</>}</p>
          </div>
          {showEmail && <label>Email address<div className="input-icon"><Mail size={16} /><input type="email" autoComplete="email" maxLength={254} required placeholder="you@example.com" value={email} onChange={event => setEmail(event.target.value)} /></div></label>}
          {passwordRequired && <label>Password<div className="input-icon"><KeyRound size={16} /><input key={current} type="password" autoComplete={newPassword ? 'new-password' : 'current-password'} minLength={newPassword ? 12 : undefined} maxLength={256} required placeholder={newPassword ? 'At least 12 characters' : 'Your password'} value={password} onChange={event => setPassword(event.target.value)} /></div></label>}
          {newPassword && <label>Confirm password<div className="input-icon"><KeyRound size={16} /><input type="password" autoComplete="new-password" minLength={12} maxLength={256} required placeholder="Re-enter password" value={confirmation} onChange={event => setConfirmation(event.target.value)} /></div></label>}
          {codeRequired && <label>Verification code<input className="code-input" type="text" autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]{6,10}" maxLength={10} required placeholder="Enter the email code" value={code} onChange={event => setCode(event.target.value.replace(/\D/g, ''))} /></label>}
          {current === 'sign-in' && <button className="text-button forgot" type="button" disabled={busy} onClick={() => go('forgot')}>Forgot password?</button>}
          {alert && <p className="form-message error" role="alert">{alert}</p>}
          {info && <p className="form-message success" role="status">{info}</p>}
          <button className="primary submit-auth" disabled={busy}>{busy ? 'Please wait…' : action} <ArrowRight size={18} /></button>
          {current !== 'sign-in' && current !== 'sign-up' && <div className="form-links">
            <button type="button" disabled={busy} onClick={() => void backToSignIn()}><ArrowLeft size={14} /> Back to sign in</button>
            {codeRequired && <button type="button" onClick={resend} disabled={busy}>Resend code</button>}
          </div>}
        </form>
        <div className="auth-footnote"><Fingerprint size={16} /> {current === 'sign-up' || codeRequired ? 'Email verification protects account access.' : 'Only approved contacts can message or call you.'}</div>
      </section>
    </section>
    <section id="safety" className="benefits">
      <div><span className="benefit-icon"><ShieldCheck /></span><h2>Contact approval</h2><p>Accept a request before someone can send messages or start a call.</p></div>
      <div><span className="benefit-icon"><AudioLines /></span><h2>Live conversations</h2><p>Move from messaging to one-to-one audio or video in the same workspace.</p></div>
      <div><span className="benefit-icon"><Flag /></span><h2>Safety controls</h2><p>Block contact and share selected evidence with a safety reviewer.</p></div>
    </section>
    <footer className="site-footer"><Brand /><span>SecTalk by Eagle Security</span><a href="#account">Account access <Send size={14}/></a></footer>
  </main>
}
