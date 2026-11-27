'use client'

import { useEffect, useRef, useState } from 'react'
import { ArrowRight, CircleAlert, LoaderCircle, ShieldCheck } from 'lucide-react'
import { Brand } from '../../../components/entry'
import { transientAuthClient } from '../../../lib/data'

type State = 'loading' | 'ready' | 'verifying' | 'verified' | 'invalid' | 'unavailable'
type Confirmation = { tokenHash: string } | { accessToken: string; refreshToken: string }

const copy = {
  loading: ['Opening your confirmation link', 'SecTalk is preparing to verify your address.'],
  ready: ['Confirm your email address', 'Verify this address to finish creating your SecTalk account.'],
  verifying: ['Verifying your email', 'Checking your SecTalk confirmation link.'],
  verified: ['Your email is verified', 'You can now sign in to SecTalk with your email address and password.'],
  invalid: ['This link is invalid or expired', 'Go to sign in and enter your email and password to request a new verification link if your account still needs confirmation.'],
  unavailable: ['Verification is unavailable', 'Check your connection and try again.'],
} as const

export default function ConfirmEmailPage() {
  const [state, setState] = useState<State>('loading')
  const [signInUrl, setSignInUrl] = useState('')
  const started = useRef(false)
  const verifying = useRef(false)
  const credential = useRef<Confirmation | null>(null)

  useEffect(() => {
    if (started.current) return
    started.current = true
    const target = new URL(window.location.href)
    setSignInUrl(target.origin + '/#account')
    const fragment = new URLSearchParams(target.hash.slice(1))
    const tokenHash = fragment.get('token_hash')
    const accessToken = fragment.get('access_token')
    const refreshToken = fragment.get('refresh_token')
    if (target.hash) window.history.replaceState(null, '', target.pathname)
    if (tokenHash && /^[a-zA-Z0-9_-]{32,128}$/.test(tokenHash)) credential.current = { tokenHash }
    else if (fragment.get('type') === 'signup' && accessToken && refreshToken) credential.current = { accessToken, refreshToken }
    setState(credential.current ? 'ready' : 'invalid')
  }, [])

  async function verify() {
    const proof = credential.current
    if (!proof || verifying.current) return
    const client = transientAuthClient(10000)
    if (!client) { setState('unavailable'); return }
    verifying.current = true
    setState('verifying')
    try {
      const { data, error } = 'tokenHash' in proof
        ? await client.auth.verifyOtp({ token_hash: proof.tokenHash, type: 'email' })
        : await client.auth.setSession({ access_token: proof.accessToken, refresh_token: proof.refreshToken })
      if (error) {
        const invalid = [400, 401, 403, 422].includes(error.status ?? 0)
        if (invalid) credential.current = null
        setState(invalid ? 'invalid' : 'unavailable')
        return
      }
      credential.current = null
      if (data.session) void client.auth.signOut({ scope: 'local' }).catch(() => undefined)
      setState(data.user?.email_confirmed_at ? 'verified' : 'invalid')
    } catch {
      setState('unavailable')
    } finally {
      verifying.current = false
    }
  }

  const [title, description] = copy[state]
  return <main className="center-page confirmation-page">
    <Brand />
    <section className="auth-card access-card confirmation-card" aria-labelledby="confirmation-title" aria-live="polite">
      <div className={'card-icon confirmation-icon ' + state}>
        {state === 'loading' || state === 'verifying' ? <LoaderCircle size={27} /> : state === 'verified' || state === 'ready' ? <ShieldCheck size={29} /> : <CircleAlert size={27} />}
      </div>
      <div className="auth-intro">
        <h1 id="confirmation-title">{title}</h1>
        <p>{description}</p>
      </div>
      {state === 'ready' || state === 'unavailable' ? <button type="button" className="primary" onClick={() => void verify()}>
        {state === 'ready' ? 'Verify my email' : 'Try again'} <ArrowRight size={17}/>
      </button> : null}
      {state === 'verified' || state === 'invalid' ? <a className="primary" href="/#account">Go to SecTalk sign in <ArrowRight size={17}/></a> : null}
      {state === 'verified' && <span className="confirmation-url">{signInUrl}</span>}
    </section>
  </main>
}
