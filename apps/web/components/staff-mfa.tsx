'use client'

import { useEffect, useState, type FormEvent } from 'react'
import { ArrowRight, ShieldCheck } from 'lucide-react'
import { db } from '../lib/data'

export function StaffMfa({ refresh, explanation = 'An authenticator code is required to review reports or change account restrictions.' }:
  { refresh: () => Promise<void>; explanation?: string }) {
  const [setup, setSetup] = useState<{ id: string; qr_code: string; secret: string } | null>(null)
  const [factor, setFactor] = useState('')
  const [loaded, setLoaded] = useState(false)
  const [pendingFactors, setPendingFactors] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => {
    void db!.auth.mfa.listFactors().then(({ data, error }) => {
      if (error) setError('Could not read your MFA settings.')
      else {
        setFactor(data.totp.find(item => item.status === 'verified')?.id || '')
        setPendingFactors(data.all.filter(item => item.factor_type === 'totp' && item.status === 'unverified').map(item => item.id))
        setLoaded(true)
      }
    })
  }, [])

  async function enroll() {
    setBusy(true)
    setError('')
    for (const id of pendingFactors) {
      const { error } = await db!.auth.mfa.unenroll({ factorId: id })
      if (error) { setError('Could not reset the unfinished authenticator setup.'); setBusy(false); return }
    }
    setPendingFactors([])
    const { data, error } = await db!.auth.mfa.enroll({ factorType: 'totp', issuer: 'SecTalk', friendlyName: 'SecTalk Staff' })
    if (error) setError('Could not enroll your authenticator.')
    else { setSetup({ id: data.id, ...data.totp }); setFactor(data.id) }
    setBusy(false)
  }

  async function verify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setError('')
    const code = String(new FormData(event.currentTarget).get('code'))
    const { error } = await db!.auth.mfa.challengeAndVerify({ factorId: factor, code })
    if (error) setError('The authenticator code is invalid or expired.')
    else await refresh()
    setBusy(false)
  }

  return <div className="panel mfa-panel"><div className="card-icon"><ShieldCheck size={22}/></div><h2>Verify staff access</h2><p>{explanation}</p>
    {setup && <div className="mfa-setup"><img src={setup.qr_code} alt="Scan with your authenticator app" width={180} height={180}/><p>Manual setup key</p><code>{setup.secret}</code></div>}
    {factor ? <form onSubmit={verify}><label>Authenticator code<input name="code" type="text" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required /></label><button className="primary" disabled={busy}>Verify access <ArrowRight size={16}/></button></form> :
      <button className="primary" disabled={busy || !loaded} onClick={enroll}>Set up authenticator</button>}
    {error && <p className="error" role="alert">{error}</p>}
  </div>
}
