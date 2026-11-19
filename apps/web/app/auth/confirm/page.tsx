'use client'

import { useEffect, useRef, useState } from 'react'
import { ArrowRight, CircleAlert, LoaderCircle, ShieldCheck } from 'lucide-react'
import { Brand } from '../../../components/entry'
import { transientAuthClient } from '../../../lib/data'

type State = 'verifying' | 'verified' | 'invalid' | 'unavailable'

const copy = {
  verifying: ['Verifying your email', 'Checking your SecTalk confirmation link.'],
  verified: ['Your email is verified', 'You can now sign in to SecTalk with your email address and password.'],
  invalid: ['This link is invalid or expired', 'Go to sign in and enter your email and password to request a new verification link if your account still needs confirmation.'],
  unavailable: ['Verification is unavailable', 'Open the original link again when your connection is available.'],
} as const

export default function ConfirmEmailPage() {
  const [state, setState] = useState<State>('verifying')
  const [signInUrl, setSignInUrl] = useState('')
  const started = useRef(false)

  useEffect(() => {
    if (started.current) return
    started.current = true
    const target = new URL(window.location.href)
    setSignInUrl(target.origin + '/#account')
    const fragment = new URLSearchParams(target.hash.slice(1))
    const tokenHash = fragment.get('token_hash')
    const accessToken = fragment.get('access_token')
    const refreshToken = fragment.get('refresh_token')
    const legacy = fragment.get('type') === 'signup' && accessToken && refreshToken
    if (target.hash) window.history.replaceState(null, '', target.pathname)
    if (!legacy && (!tokenHash || !/^[a-zA-Z0-9_-]{32,128}$/.test(tokenHash))) {
      setState('invalid')
      return
    }
    const client = transientAuthClient()
    if (!client) { setState('unavailable'); return }
    async function verify() {
      try {
        const { data, error } = legacy
          ? await client!.auth.setSession({ access_token: accessToken!, refresh_token: refreshToken! })
          : await client!.auth.verifyOtp({ token_hash: tokenHash!, type: 'email' })
        if (error) {
          setState([400, 401, 403, 422].includes(error.status ?? 0) ? 'invalid' : 'unavailable')
          return
        }
        if (!data.user?.email_confirmed_at) { setState('invalid'); return }
        // The signup link proves ownership. A separate password sign-in starts the app session.
        if (data.session) void client!.auth.signOut({ scope: 'local' }).catch(() => undefined)
        setState('verified')
      } catch {
        setState('unavailable')
      }
    }
    void verify()
  }, [])

  const [title, description] = copy[state]
  return <main className="center-page confirmation-page">
    <Brand />
    <section className="auth-card access-card confirmation-card" aria-labelledby="confirmation-title" aria-live="polite">
      <div className={'card-icon confirmation-icon ' + state}>
        {state === 'verifying' ? <LoaderCircle size={27} /> : state === 'verified' ? <ShieldCheck size={29} /> : <CircleAlert size={27} />}
      </div>
      <div className="auth-intro">
        <h1 id="confirmation-title">{title}</h1>
        <p>{description}</p>
      </div>
      {state !== 'verifying' && <a className="primary" href="/#account">Go to SecTalk sign in <ArrowRight size={17}/></a>}
      {state === 'verified' && <span className="confirmation-url">{signInUrl}</span>}
    </section>
  </main>
}
