'use client'

import { useEffect, useState } from 'react'
import { db } from '../lib/data'
import { verifyReputationBrowserLink } from '../lib/browser-reputation-link'

export function BrowserReputationLink() {
  const [linked, setLinked] = useState<boolean>()
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    let current = true
    void db!.rpc('st_v7_manage_browser_reputation_link', { p_action: 'status' }).then(result => {
      if (current && !result.error && typeof result.data?.linked === 'boolean') setLinked(result.data.linked)
    })
    return () => { current = false }
  }, [])

  async function change(next: boolean) {
    if (busy) return
    setBusy(true)
    setNotice('')
    setError('')
    try {
      if (next) await verifyReputationBrowserLink()
      else {
        const result = await db!.rpc('st_v7_manage_browser_reputation_link', { p_action: 'forget' })
        if (result.error || result.data?.linked !== false) throw new Error('Browser link could not be removed')
      }
      setLinked(next)
      setNotice(next ? 'Browser link verified.' : 'Browser link removed.')
    } catch {
      setError('Browser link unavailable. Verify this approved device and try again.')
    } finally {
      setBusy(false)
    }
  }

  return <section aria-label="Optional browser safety link">
    <h3>Optional browser safety link</h3>
    <p>Allow Safety reviewers to see whether another new or recently verified account opted in on the same browser. The link expires after 30 days and can be removed here.</p>
    <p>Reviewers see a match indicator. Message text and other account identities are excluded.</p>
    {linked !== undefined && <button type="button" className="secondary" disabled={busy} onClick={() => void change(!linked)}>
      {linked ? 'Remove browser safety link' : 'Opt in and verify browser link'}
    </button>}
    {notice && <p role="status">{notice}</p>}
    {error && <p role="alert">{error}</p>}
  </section>
}
