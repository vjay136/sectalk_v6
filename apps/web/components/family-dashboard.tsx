'use client'

import { useCallback, useEffect, useState, type ComponentProps } from 'react'
import { db, formatError } from '../lib/data'
import { ManagedAccounts } from './managed-accounts'
import { useSensitiveAction } from './sensitive-action'

type Policy = { id: string; supervisor: string; participant: string; consent: boolean; restricted: boolean; recentTrustedCheck: boolean }

export function FamilyDashboard(props: Omit<ComponentProps<typeof ManagedAccounts>, 'kind' | 'onChange'>) {
  const { workspace, actor, names } = props
  const [policies, setPolicies] = useState<Policy[]>()
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const { authorize, confirmation } = useSensitiveAction()

  const load = useCallback(async (signal?: AbortSignal) => {
    const request = db!.rpc('st_v7_family_file_policy', { p_workspace: workspace })
    const response = await (signal ? request.abortSignal(signal) : request)
    if (signal?.aborted) return
    if (response.error) setError('Family sharing protection is unavailable.')
    else setPolicies(response.data as Policy[])
  }, [workspace])

  useEffect(() => {
    const controller = new AbortController()
    void load(controller.signal)
    return () => controller.abort()
  }, [load])

  function update(id: string, action: 'agree' | 'withdraw' | 'set', restrict?: boolean) {
    if (busy) return
    setError('')
    setNotice('')
    void authorize('room_role', async () => {
      setBusy(true)
      try {
        const response = await db!.rpc('st_v7_family_file_policy', {
          p_workspace: workspace, p_link: id, p_action: action, p_restrict: restrict,
        })
        if (response.error) throw response.error
        setPolicies(response.data as Policy[])
        setNotice('Family file-link protection updated.')
      } catch (cause) { setError(formatError(cause, 'Could not update file-link protection.')) }
      finally { setBusy(false) }
    })
  }

  return <section className="release-section" aria-label="Family dashboard">
    <h2>Family dashboard</h2>
    <p>A Family guardian is a workspace owner or admin whose oversight the member has accepted. SecTalk verifies
      account access and workspace roles. The role does not establish legal guardianship.</p>
    <ManagedAccounts {...props} kind="family" onChange={() => void load()}/>
    <section aria-label="Family sharing and device health">
      <h3>Sharing protection and device health</h3>
      <p>Attachment-link protection blocks new public links and pauses access through existing links while enabled.
        Private attachments stay available to their original conversation participants. Old links can work again
        if protection ends and they have not expired or been revoked.</p>
      <p>The device check says only whether any trusted device signed in within the past seven days and still has an active session.</p>
      {!policies && !error && <p role="status">Loading Family protection…</p>}
      {policies?.length === 0 && <p>Accept an oversight proposal to view Family protection.</p>}
      {policies?.map(policy => {
        const guardian = actor === policy.supervisor
        return <article className="release-board-item" key={policy.id}>
          <h4>{names[guardian ? policy.participant : policy.supervisor] ?? 'Family workspace account'}</h4>
          <p>{policy.recentTrustedCheck ? 'Recent trusted-device sign-in' : 'No recent trusted-device sign-in'}</p>
          <p>{policy.restricted ? 'Public attachment links blocked' : policy.consent ?
            'Public attachment links allowed' : 'File-link protection has not been approved'}</p>
          {guardian && policy.consent && <button type="button" className="secondary" disabled={busy}
            onClick={() => update(policy.id, 'set', !policy.restricted)}>
            {policy.restricted ? 'Allow public attachment links' : 'Block public attachment links'}</button>}
          {!guardian && <button type="button" className="secondary" disabled={busy}
            onClick={() => update(policy.id, policy.consent ? 'withdraw' : 'agree')}>
            {policy.consent ? 'Withdraw file-link consent' : 'Enable Family file-link protection'}</button>}
        </article>
      })}
      {confirmation}
      {notice && <p role="status">{notice}</p>}
      {error && <p role="alert">{error}</p>}
    </section>
  </section>
}
