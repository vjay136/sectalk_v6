'use client'

import { useState, type FormEvent } from 'react'
import {
  ArrowDown, ArrowRight, AudioLines, Check, ChevronRight, Flag, LockKeyhole,
  Mail, MessageCircle, Phone, Send, Shield, ShieldCheck, UserRoundCheck, Video,
} from 'lucide-react'
import { db } from '../lib/data'

export function Brand() {
  return <div className="brand"><span className="brand-icon"><ShieldCheck size={23} strokeWidth={2.1} /></span>
    <span>SecTalk<small>EAGLE SECURITY</small></span></div>
}

export function Entry() {
  const [email, setEmail] = useState('')
  const [code, setCode] = useState('')
  const [step, setStep] = useState<'email' | 'code'>('email')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [info, setInfo] = useState('')

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (busy) return
    setBusy(true)
    setError('')
    setInfo('')
    try {
      if (!db) throw new Error('Sign-in is unavailable until Supabase is configured.')
      if (step === 'email') {
        const { error } = await db.auth.signInWithOtp({
          email: email.trim(), options: { shouldCreateUser: true },
        })
        if (error) throw error
        setStep('code')
      } else {
        const { error } = await db.auth.verifyOtp({ email: email.trim(), token: code, type: 'email' })
        if (error) throw error
      }
    } catch (error) {
      const status = (error as { status?: number }).status
      setError(status === 429 ? 'Please wait a minute before requesting another code.'
        : !db ? 'Sign-in is unavailable until Supabase is configured.'
        : step === 'code' ? 'This code is invalid or expired.' : 'Could not send a code. Check your email or try again shortly.')
    } finally {
      setBusy(false)
    }
  }

  async function resend() {
    if (!db || busy) return
    setBusy(true)
    setError('')
    setInfo('')
    const { error } = await db.auth.signInWithOtp({ email: email.trim(), options: { shouldCreateUser: true } })
    if (error) setError('Please wait before requesting another code.')
    else setInfo('A new code was sent.')
    setBusy(false)
  }

  return <main className="landing">
    <header className="site-header"><Brand /><a className="header-link" href="#safety"><Shield size={15} /> Safety <ChevronRight size={13} /></a><a className="header-cta" href="#join">Sign in <ArrowRight size={15} /></a></header>
    <section className="hero">
      <div className="hero-copy">
        <div className="eyebrow"><span /> PRIVATE COMMUNICATION</div>
        <h1>Stay connected.<br /><em>Stay in control.</em></h1>
        <p>Message and call the people you trust. Decide who can reach you, and get help when a conversation crosses a line.</p>
        <a href="#join" className="primary hero-button">Get started <ArrowRight size={17} /></a>
        <a href="#safety" className="learn">Explore safety features <ArrowDown size={15} /></a>
      </div>
      <div className="showcase" aria-label="Illustration of a SecTalk conversation">
        <div className="showcase-grid" />
        <div className="sample">
          <div className="sample-top"><span className="tiny-logo"><ShieldCheck size={16} /></span><b>Messages</b><span className="preview-label">PREVIEW</span></div>
          <div className="sample-person"><span className="avatar peach">AM</span><div><strong>Avery Morgan</strong><small><span className="status-dot" /> Accepted contact</small></div><Phone size={16} /><Video size={17} /></div>
          <div className="sample-feed"><span className="sample-date">TODAY</span><p>Hey! Still good for our call?</p><p className="sample-own">Yes, give me five minutes. <Check size={13} /></p>
            <div className="sample-call"><div><AudioLines size={18} /></div><span><strong>Audio call</strong><small>Ready when you are</small></span><Phone size={16} /></div>
          </div>
          <div className="sample-input">Write a message… <Send size={15} /></div>
        </div>
        <div className="safety-float"><span><ShieldCheck size={20} /></span><div><strong>You're in control</strong><small>Block or report at any time</small></div></div>
      </div>
    </section>
    <section id="safety" className="benefits">
      <div><UserRoundCheck /><h2>Accept contacts first</h2><p>New contacts need your approval before they can message or call.</p></div>
      <div><MessageCircle /><h2>Chat, audio and video</h2><p>Switch from live messages to a one-to-one call with an accepted contact.</p></div>
      <div><Flag /><h2>Report with context</h2><p>Block unwanted contact and choose which message to share with a safety reviewer.</p></div>
    </section>
    <section id="join" className="join-section">
      <div className="join-copy"><div className="eyebrow"><span /> YOUR ACCOUNT</div><h2>Make SecTalk yours.</h2><p>Use your email address to create an account or sign in.</p></div>
      <form className="auth-card" onSubmit={submit}>
        <div className="card-icon"><LockKeyhole size={20} /></div>
        <h2>{step === 'email' ? 'Continue with email' : 'Enter your email code'}</h2>
        {step === 'email' ? <label>Email address<div className="input-icon"><Mail size={17} /><input type="email" autoComplete="email" required maxLength={254} placeholder="you@example.com" value={email} onChange={e => setEmail(e.target.value)} /></div></label> :
          <><p>We sent a one-time code to <strong>{email}</strong>.</p><label>Verification code<input type="text" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6,10}" maxLength={10} required value={code} onChange={e => setCode(e.target.value.replace(/\D/g, ''))} /></label></>}
        {error && <p className="error" role="alert">{error}</p>}
        {info && <p role="status">{info}</p>}
        <button className="primary" disabled={busy}>{busy ? 'Please wait…' : step === 'email' ? 'Send verification code' : 'Verify and continue'} <ArrowRight size={17} /></button>
        {step === 'code' && <div className="form-links"><button type="button" onClick={() => { setStep('email'); setCode(''); setError(''); setInfo('') }} disabled={busy}>Change email</button><button type="button" onClick={resend} disabled={busy}>Resend code</button></div>}
      </form>
    </section>
    <footer className="site-footer"><Brand /><span>Private communication by Eagle Security</span><a href="#join">Sign in <ArrowRight size={15}/></a></footer>
  </main>
}
