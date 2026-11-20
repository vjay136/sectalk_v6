'use client'

import { useEffect, useRef, useState } from 'react'
import { scimClaimAuth, scimClaimPath } from '../../../lib/scim-claim-auth'

const statusCopy = {
  processing: 'Verifying your email and workspace membership…',
  joined: 'Your directory membership is ready.',
  error: 'The workspace could not be joined. Open Workspaces and request a new verification link.',
  seat_limit: 'This workspace has no available seats. Ask your workspace owner to free a seat.',
}

export default function ScimClaimPage() {
  const started = useRef(false)
  const [status, setStatus] = useState<keyof typeof statusCopy>('processing')
  useEffect(() => {
    if (started.current) return
    started.current = true
    const code = new URLSearchParams(window.location.search).get('code')
    window.history.replaceState(null, '', scimClaimPath)
    if (!code || !/^[a-f0-9-]{36}$/i.test(code)) { setStatus('error'); return }
    void (async () => {
      try {
        const proof = scimClaimAuth()
        const { data, error } = await proof.auth.exchangeCodeForSession(code)
        if (error || !data.session) throw new Error()
        try {
          const claimed = await proof.rpc('st_v8_scim_claim', { p_accept: true })
          if (claimed.error) throw claimed.error
          setStatus(claimed.data.state === 'joined' || claimed.data.state === 'seat_limit' ? claimed.data.state : 'error')
        } finally {
          await proof.auth.signOut({ scope: 'local' }).catch(() => undefined)
        }
      } catch {
        setStatus('error')
      }
    })()
  }, [])
  return <main className="center-page"><section className="auth-card" aria-labelledby="scim-claim-heading">
    <h1 id="scim-claim-heading">Workspace verification</h1>
    <p role={status === 'error' ? 'alert' : 'status'}>{statusCopy[status]}</p>
    {status !== 'processing' && <a className="primary" href="/">Return to SecTalk</a>}
  </section></main>
}
