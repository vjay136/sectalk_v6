'use client'

import { useEffect, useState, type FormEvent } from 'react'
import { ArrowRight, ShieldCheck } from 'lucide-react'
import { db } from '../lib/data'

const factorName = 'SecTalk Staff'

export function StaffMfa({ refresh, heading='Verify staff access', explanation = 'An authenticator code is required to review reports or change account restrictions.', verifyLabel = 'Verify access' }:
  { refresh: () => Promise<void>; heading?: string; explanation?: string; verifyLabel?: string }) {
  const [setup, setSetup] = useState<{ id: string; qr_code: string; secret: string } | null>(null)
  const [factor, setFactor] = useState('')
  const [loaded, setLoaded] = useState(false)
  const [pendingFactors, setPendingFactors] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [attempt, setAttempt] = useState(0)
  useEffect(() => {
    let active = true
    void db!.auth.mfa.listFactors().then(({ data, error }) => {
      if (!active) return
      if (error) setError('Could not read your authenticator settings.')
      else {
        setFactor(data.totp.find(item => item.status === 'verified')?.id || '')
        setPendingFactors(data.all.filter(item => item.factor_type === 'totp' && item.status === 'unverified' && item.friendly_name === factorName).map(item => item.id))
        setLoaded(true)
      }
    }).catch(() => {
      if (active) setError('Could not read your authenticator settings.')
    })
    return () => { active = false }
  }, [attempt])

  async function enroll() {
    if (busy || !loaded) return
    setBusy(true)
    setError('')
    try {
      for (const id of pendingFactors) {
        const { error } = await db!.auth.mfa.unenroll({ factorId: id })
        if (error && error.code !== 'mfa_factor_not_found') throw error
      }
      setPendingFactors([])
      const { data, error } = await db!.auth.mfa.enroll({ factorType: 'totp', issuer: 'SecTalk', friendlyName: factorName })
      if (error) throw error
      setSetup({ id: data.id, qr_code: data.totp.qr_code, secret: data.totp.secret })
      setFactor(data.id)
    } catch {
      setError('Could not enroll your authenticator. Try again.')
    } finally {
      setBusy(false)
    }
  }

  async function verify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy || !factor) return
    const form = event.currentTarget
    setBusy(true)
    setError('')
    const code = String(new FormData(form).get('code'))
    try {
      const { error } = await db!.auth.mfa.challengeAndVerify({ factorId: factor, code })
      if (error) { setError('The authenticator code is invalid or expired.'); return }
      setSetup(null)
      form.reset()
      await refresh()
    } catch {
      setError('Could not verify your authenticator. Try again.')
    } finally {
      setBusy(false)
    }
  }

  return <div className="panel mfa-panel"><div className="card-icon"><ShieldCheck size={22}/></div><h2>{heading}</h2><p>{explanation}</p>
    {setup && <div className="mfa-setup"><p>Scan this QR code in your authenticator app, then enter the new six-digit SecTalk code.</p>
      <img src={setup.qr_code} alt="Scan with your authenticator app" width={180} height={180}/><p>Manual setup key</p><code dir="ltr">{setup.secret}</code></div>}
    {loaded ? factor ? <form onSubmit={verify}><label>Authenticator code<input name="code" type="text" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required /></label><button className="primary" disabled={busy}>{verifyLabel} <ArrowRight size={16}/></button></form> :
      <button type="button" className="primary" disabled={busy} onClick={enroll}>Set up authenticator</button> :
      error ? <button type="button" className="secondary" onClick={() => { setError(''); setAttempt(value => value + 1) }}>Retry</button> :
        <p role="status">Checking your authenticator settings…</p>}
    {error && <p className="error" role="alert">{error}</p>}
  </div>
}
