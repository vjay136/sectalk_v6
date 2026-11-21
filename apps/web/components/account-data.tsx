'use client'

import { useEffect, useRef, useState, type FormEvent } from 'react'
import { verifyAccountCredential } from '../lib/account-credential'
import { db, formatError } from '../lib/data'
import { saveDownload } from '../lib/chat-files'

const blockerText={
  workspace_owner:'You own a workspace. Its ownership or offboarding needs to be resolved first.',
  subscription:'Your paid subscription needs to be resolved in Billing.',
  retained_content:'Some workspace or group messages are retained under their workspace rules.',
  retained_files:'Some files or private storage records still need to be resolved.',
  retained_devices:'Your device records require review before the account can be deleted.',
}
type Deletion = { status: 'none' | 'needs_review' | 'deleted'; requestedAt: string | null; blockers?:Array<keyof typeof blockerText> }
type Cursor = { before: string; beforeId: string }

export function AccountData({ user }: { user: string }) {
  const [deletion, setDeletion] = useState<Deletion>()
  const [hasAuthenticator, setHasAuthenticator] = useState<boolean>()
  const [action, setAction] = useState<'export' | 'request' | 'retry' | 'cancel'>()
  const [cursor, setCursor] = useState<Cursor>()
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const verificationForm = useRef<HTMLFormElement>(null)
  const actionButton = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (action) verificationForm.current?.querySelector('input')?.focus()
    else if (actionButton.current) {
      actionButton.current.focus()
      actionButton.current = null
    }
  }, [action])

  useEffect(() => {
    let live = true
    void Promise.all([db!.rpc('st_v8_personal_deletion_status', { p_owner: user }),db!.auth.mfa.listFactors()]).then(([state, factors]) => {
      if (!live) return
      if (state.error || factors.error) setError('Could not open your data settings.')
      else {
        setDeletion(state.data as Deletion)
        setHasAuthenticator(factors.data?.totp.some(factor => factor.status === 'verified') ?? false)
      }
    })
    return () => { live = false }
  }, [user])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy || !action || hasAuthenticator === undefined) return
    const form = new FormData(event.currentTarget)
    setBusy(true)
    setNotice('')
    setError('')
    try {
      await verifyAccountCredential(String(form.get('credential') ?? ''), hasAuthenticator)
      if (action === 'export') {
        const response = await db!.rpc('st_v8_personal_data_export', {
          p_owner: user, p_before: cursor?.before, p_before_id: cursor?.beforeId,
        })
        if (response.error || !response.data) throw response.error ?? new Error('No account data')
        const {data:session}=await db!.auth.getSession()
        if (session.session?.user.id!==user) throw new Error('Sign in again to export your data.')
        saveDownload(new Blob([JSON.stringify(response.data,null,2)], { type: 'application/json' }),
          'sectalk-personal-data-' + new Date().toISOString().slice(0,10) + '.json')
        setCursor(response.data.next ?? undefined)
        setNotice('Personal data export downloaded.')
      } else {
        const response = await db!.rpc('st_v7_personal_deletion', { p_owner: user, p_action: action,
          p_confirmation: action === 'cancel' ? undefined : form.get('confirmation') })
        if (response.error || !response.data) throw response.error ?? new Error('Account deletion unavailable')
        const next = response.data as Deletion
        if (next.status === 'deleted') {
          await db!.auth.signOut({ scope: 'local' })
          window.location.assign('/')
          return
        }
        setDeletion(next)
        if (next.status === 'needs_review') {
          const details=await db!.rpc('st_v8_personal_deletion_status',{p_owner:user})
          if (!details.error && details.data) setDeletion(details.data as Deletion)
        }
        setNotice(action === 'cancel' ? 'Deletion request cancelled.' :
          action === 'retry' ? 'Your request is still pending because the account has retained records or dependencies.' : 'Deletion request saved.')
      }
      setAction(undefined)
    } catch (cause) {
      setError(formatError(cause, 'Could not complete the account data action.'))
    } finally {
      setBusy(false)
    }
  }

  function choose(next: typeof action, button?: HTMLButtonElement) {
    if (button) actionButton.current = button
    setError('')
    setNotice('')
    setAction(next)
  }

  return <section className="release-section" aria-label="Account privacy and data">
    <h2>Privacy and data</h2>
    <p>The JSON export includes your account settings, device metadata, saved searches and eligible messages you authored.</p>
    {deletion && <>
      <div className="actions"><button type="button" className="secondary" disabled={busy}
        onClick={event => choose('export', event.currentTarget)}>{cursor ? 'Download next export page' : 'Export my data'}</button>
      {deletion.status === 'needs_review' ?
        <>
          <button type="button" className="secondary" disabled={busy} onClick={event => choose('retry', event.currentTarget)}>Retry account deletion</button>
          <button type="button" className="secondary" disabled={busy} onClick={event => choose('cancel', event.currentTarget)}>Cancel deletion request</button>
        </> :
        <button type="button" className="danger" disabled={busy} onClick={event => choose('request', event.currentTarget)}>Delete my account</button>}
      </div>
      {deletion.status === 'needs_review' && <p>Your deletion request is pending because this account has retained records or dependencies.
        {deletion.requestedAt && <> Requested <time dateTime={deletion.requestedAt}>{new Date(deletion.requestedAt).toLocaleDateString()}</time>.</>}
        {' '}You can retry after the dependencies clear or cancel the request.</p>}
      {deletion.status==='needs_review' && Boolean(deletion.blockers?.length) && <ul aria-label="Deletion requirements">
        {deletion.blockers?.map(blocker=><li key={blocker}>{blockerText[blocker]}</li>)}
      </ul>}
    </>}
    {action && <form ref={verificationForm} className="release-form" onSubmit={event => void submit(event)} key={action}>
      {(action === 'request' || action === 'retry') && <>
        <p>Continuing permanently deletes an eligible account. Retained records and dependencies keep the request pending.</p>
        <label>Type DELETE ACCOUNT to confirm<input name="confirmation" required pattern="DELETE ACCOUNT" autoComplete="off" /></label>
      </>}
      <label>{hasAuthenticator ? 'Current authenticator code' : 'Current password'}<input
        type={hasAuthenticator ? 'text' : 'password'} autoComplete={hasAuthenticator ? 'one-time-code' : 'current-password'}
        inputMode={hasAuthenticator ? 'numeric' : undefined} name="credential" required /></label>
      <button type="submit" className={action === 'request' || action === 'retry' ? 'danger' : 'primary'} disabled={busy}>
        {action === 'cancel' ? 'Confirm cancellation' : action === 'export' ? 'Verify and download export' : 'Confirm account deletion'}
      </button>
      <button className="text-button" type="button" disabled={busy} onClick={() => choose(undefined)}>Back to data settings</button>
    </form>}
    {notice && <p role="status">{notice}</p>}
    {error && <p role="alert">{error}</p>}
  </section>
}
