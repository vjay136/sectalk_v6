'use client'

import { useEffect, useState } from 'react'
import { db } from '../lib/data'
import { scimClaimAuth, scimClaimPath } from '../lib/scim-claim-auth'

export function PendingDirectoryMembership() {
  const [pending, setPending] = useState(false)
  const [busy, setBusy] = useState(false)
  const [sent, setSent] = useState(false)
  const [error, setError] = useState(false)
  useEffect(() => {
    let current = true
    void db!.rpc('st_v8_scim_claim').then(({ data }) => {
      if (current) setPending(data?.state === 'pending')
    })
    return () => { current = false }
  }, [])
  async function send() {
    if (busy) return
    setBusy(true)
    setError(false)
    try {
      const { data } = await db!.auth.getUser()
      if (!data.user?.email || !data.user.email_confirmed_at) throw new Error()
      const result = await scimClaimAuth().auth.signInWithOtp({
        email: data.user.email, options: { shouldCreateUser: false, emailRedirectTo: window.location.origin + scimClaimPath },
      })
      if (result.error) throw result.error
      setSent(true)
    } catch {
      setError(true)
    } finally {
      setBusy(false)
    }
  }
  if (!pending) return null
  return <section className="panel release-panel" aria-label="Pending directory membership">
    <h2>Join your provisioned workspace</h2>
    <p>Verify your email with a new link to accept your organization’s directory membership. Open the link in this browser.</p>
    <button type="button" className="primary" disabled={busy || sent} onClick={() => void send()}>
      {busy ? 'Sending…' : 'Send workspace verification link'}
    </button>
    {sent && <p role="status">Check your email for a workspace verification link.</p>}
    {error && <p role="alert">The verification link could not be sent. Try again in a moment.</p>}
  </section>
}
