'use client'

import { useEffect, useState, type FormEvent } from 'react'
import { db } from '../lib/data'
import { defaultInvitationCopy, renderWorkspaceInvitation, type InvitationTemplate } from '../lib/workspace-invitation-template'

type Revision = InvitationTemplate & { version: number; createdAt: string }
type State = { organization: string; active: number; versions: Revision[] }

export function WorkspaceInvitationTemplates({ workspace, organization, disabled, authorize }: {
  workspace: string; organization: string; disabled: boolean; authorize: (action: () => Promise<void>) => Promise<void>
}) {
  const [state, setState] = useState<State>()
  const [draft, setDraft] = useState(defaultInvitationCopy)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [selected, setSelected] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    void db!.rpc('st_v7_workspace_email_template', { p_workspace: workspace }).abortSignal(controller.signal).then(result => {
      if (controller.signal.aborted) return
      if (result.error || !result.data) setError('Could not load the invitation email template.')
      else {
        const current = result.data as State
        setState(current)
        setDraft(current.versions.find(item => item.version === current.active) ?? defaultInvitationCopy)
      }
    })
    return () => controller.abort()
  }, [workspace])

  function edit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const candidate = { ...draft }
    void change({ p_action: 'publish', p_subject: candidate.subject, p_body: candidate.body })
  }

  async function change(action: { p_action: 'publish'; p_subject: string; p_body: string } | { p_action: 'activate'; p_version: number }) {
    setError('')
    setMessage('')
    await authorize(async () => {
      const result = await db!.rpc('st_v7_workspace_email_template', { p_workspace: workspace, ...action })
      if (result.error) throw result.error
      const current = result.data as State
      setState(current)
      setDraft(current.versions.find(item => item.version === current.active) ?? defaultInvitationCopy)
      setMessage(action.p_action === 'publish' ? 'Invitation email version published.' : 'Invitation email version restored.')
    })
  }

  const preview = renderWorkspaceInvitation(draft, organization, 'https://example.invalid/invite#link=sample',
    new Date('2030-01-01T00:00:00Z'))
  return <section className="release-section" aria-label="Workspace invitation email template">
    <h3>Invitation email template</h3>
    <p>This template applies to workspace invitation emails. SecTalk supplies the sender, invitation URL, and expiry.
      Account sign-in, recovery, and personal notification emails use deployment templates.</p>
    {state && <>
      <p>Active template {state.active === 0 ? 'SecTalk default' : 'version ' + state.active}</p>
      <form className="release-form" onSubmit={edit}>
        <fieldset disabled={disabled}>
          <legend>Invitation copy</legend>
          <p>Use plain text. Write <code>{'{{organization}}'}</code> to insert this organization’s name.</p>
          <label>Invitation subject<input required maxLength={100} value={draft.subject}
            onChange={event => setDraft({ ...draft, subject: event.target.value })}/></label>
          <label>Invitation message<textarea required maxLength={1500} rows={5} value={draft.body}
            onChange={event => setDraft({ ...draft, body: event.target.value })}/></label>
          <button type="submit" className="primary">Publish invitation template</button>
        </fieldset>
      </form>
      <section aria-label="Invitation email preview">
        <h4>Live preview</h4>
        <p><strong>{preview.subject}</strong></p>
        <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{preview.text}</pre>
      </section>
      <form className="release-form" onSubmit={event => {
        event.preventDefault()
        void change({ p_action: 'activate', p_version: selected })
      }}>
        <label>Restore a version<select value={selected} onChange={event => setSelected(Number(event.target.value))}>
          <option value={0}>SecTalk default</option>
          {state.versions.map(item => <option key={item.version} value={item.version}>
            Version {item.version} · {new Date(item.createdAt).toLocaleString()}
          </option>)}
        </select></label>
        <button type="submit" className="secondary" disabled={disabled || selected === state.active}>Restore invitation template</button>
      </form>
    </>}
    {message && <p role="status">{message}</p>}
    {error && <p role="alert">{error}</p>}
  </section>
}
