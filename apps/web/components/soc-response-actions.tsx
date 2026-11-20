'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'

type Action = 'quarantine_message' | 'quarantine_file' | 'suspend_user' | 'force_logout' | 'revoke_device' | 'block_domain' | 'block_url' | 'lock_room' | 'quarantine_room_post' | 'quarantine_channel_post'
type Grant = { action: Action; workspace: string | null; role: 'requester' | 'approver'; name: string | null }
type Request = { id: string; action: Action; workspace: string | null; case_id: string | null; domain: string | null;
  target: string | null; reason: string; requested_at: string; decision: 'executed' | 'rejected' | null;
  decision_reason: string | null; decided_at: string | null; can_decide: boolean }
type Target = { id: string; name: string }
const actions: Record<Action,string> = {
  quarantine_message: 'Quarantine reported message', quarantine_file: 'Quarantine reported attachment',
  suspend_user: 'Suspend reported account for 24 hours', force_logout: 'End all reported account sessions',
  revoke_device: 'Revoke a reported account device', block_domain: 'Block a domain for seven days',
  block_url: 'Block an exact URL path for seven days', lock_room: 'Lock a room',
  quarantine_room_post: 'Quarantine a reported room post',
  quarantine_channel_post: 'Quarantine a reported channel message',
}
const notes: Record<Action,string> = {
  quarantine_message: 'Hides the reported message. The consented report copy remains in the evidence record.',
  quarantine_file: 'Closes ordinary downloads, previews, and share links. Consented report evidence remains available to authorized reviewers.',
  suspend_user: 'Uses the reported account restriction and ends ongoing calls.',
  force_logout: 'Ends native sessions. The account can sign in again.',
  revoke_device: 'Permanently blocks the selected device identity and ends its native sessions.',
  block_domain: 'Applies to SecTalk features that enforce the platform domain blocklist.',
  block_url: 'Blocks the selected scheme, domain, and exact case-sensitive path in URL inspection and managed message links.',
  lock_room: 'Applies the room’s normal posting lock within the selected workspace.',
  quarantine_room_post: 'Hides the exact reported post and preserves the copy the reporter agreed to share with workspace reviewers.',
  quarantine_channel_post: 'Hides the exact reported message. Authorized channel reviewers keep access to the consented evidence.',
}
const uuid = '[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}'
const isCase = (action: Action) => action!=='block_domain' && action!=='block_url' && action!=='lock_room'
const grantKey = (grant: Grant) => grant.action + ':' + (grant.workspace ?? '')

export function SocResponseActions({ report, roomCase = false, channelCase = false }: {
  report?: string; roomCase?: boolean; channelCase?: boolean
}) {
  const [grants,setGrants] = useState<Grant[]>([])
  const [requests,setRequests] = useState<Request[]>([])
  const [selection,setSelection] = useState('')
  const [caseId,setCaseId] = useState(report ?? '')
  const [targets,setTargets] = useState<Target[] | null>(null)
  const [busy,setBusy] = useState(false)
  const [error,setError] = useState('')
  const [notice,setNotice] = useState('')
  const [evidence,setEvidence] = useState('')
  const refresh = useCallback(async () => {
    const catalog = await db!.rpc('st_v7_soc_response_catalog')
    if (catalog.error) return
    setGrants(catalog.data)
    if (!report && catalog.data.length) {
      const queue = await db!.rpc('st_v7_soc_response_queue')
      if (!queue.error) setRequests(queue.data)
    }
  },[report])
  useEffect(() => { void refresh() },[refresh])
  const roomEvidenceAccess = roomCase && grants.some(grant => grant.action==='quarantine_room_post')
  const reportAction = roomCase ? 'quarantine_room_post' : channelCase ? 'quarantine_channel_post' : ''
  const choices = grants.filter(grant => grant.role==='requester' && (!report ||
    (reportAction ? grant.action===reportAction : isCase(grant.action) &&
      grant.action!=='quarantine_room_post' && grant.action!=='quarantine_channel_post')))
  const selected = choices.find(grant => grantKey(grant)===selection) ?? (reportAction && choices.length===1 ? choices[0] : undefined)
  if (report ? choices.length===0 && !roomEvidenceAccess : grants.length===0) return null

  async function operation(message: string, work: () => Promise<void>) {
    if (busy) return
    setBusy(true)
    setError('')
    setNotice('')
    try {
      await work()
      if (message) setNotice(message)
    } catch (failure) {
      setError(formatError(failure,'The response action could not be completed.'))
    } finally { setBusy(false) }
  }

  function pickTargets() {
    if (!selected) return
    void operation('',async () => {
      const result = await db!.rpc('st_v7_soc_response_targets',{
        p_workspace:selected.workspace,p_case:selected.action==='revoke_device' ? caseId.trim() : null,
      })
      if (result.error) throw result.error
      setTargets(result.data)
    })
  }

  function propose(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!selected) return
    const fields = new FormData(event.currentTarget)
    void operation('Response sent for separate approval.',async () => {
      const submittedAddress = fields.get('domain')
      let address = submittedAddress
      if (selected.action==='block_url' && typeof submittedAddress==='string') {
        const parsed = new URL(submittedAddress)
        if (parsed.username || parsed.password || parsed.port) throw new Error('Enter a standard web address without credentials.')
        address = parsed.origin + parsed.pathname
      }
      const result = await db!.rpc('st_v7_request_soc_response',{
        p_action:selected.action,p_workspace:selected.workspace,p_case:isCase(selected.action) ? caseId.trim() : null,
        p_target:fields.get('target'),p_domain:address,p_reason:fields.get('reason'),
      })
      if (result.error) throw result.error
      setSelection('')
      setTargets(null)
      await refresh()
    })
  }

  function resolve(event: FormEvent<HTMLFormElement>, id: string) {
    event.preventDefault()
    const fields = new FormData(event.currentTarget)
    const approve = fields.get('decision')==='approve'
    void operation(approve ? 'Response executed.' : 'Response rejected.',async () => {
      const result = await db!.rpc('st_v7_decide_soc_response',{p_id:id,p_approve:approve,p_reason:fields.get('reason')})
      if (result.error) throw result.error
      await refresh()
    })
  }

  const needsTarget = selected?.action==='revoke_device' || selected?.action==='lock_room'
  return <section className="release-section" aria-label={report ? 'Reported case response request' : 'SOC response requests'}>
    <h3>{report ? 'Request a case response' : 'SOC response requests'}</h3>
    <p>Each action requires a reason and an independent reviewer with current authenticator verification.</p>
    {roomEvidenceAccess && report && <button className="secondary" type="button" disabled={busy}
      onClick={() => void operation('',async () => {
        const result = await db!.rpc('st_v7_read_room_quarantine_evidence',{p_report:report})
        if (result.error) throw result.error
        if (typeof result.data==='string') setEvidence(result.data)
        else setNotice('No retained room evidence is available to this role.')
      })}>View retained room evidence</button>}
    {evidence && <blockquote aria-label="Retained room evidence">{evidence}</blockquote>}
    {choices.length>0 && <form className="release-form" onSubmit={propose}>
      <label>Response action<select aria-label="Response action" value={selected ? grantKey(selected) : ''} onChange={event => {
        setSelection(event.target.value); setTargets(null); setError(''); setNotice('')
      }}>
        <option value="">Choose an action</option>{choices.map(grant => <option key={grantKey(grant)} value={grantKey(grant)}>
          {actions[grant.action]}{grant.name ? ' · ' + grant.name : ''}
        </option>)}
      </select></label>
      {selected && <div className="release-form" key={selection}>
        <p>{notes[selected.action]}</p>
        {isCase(selected.action) && !report && <label>Open report ID<input value={caseId} required pattern={uuid}
          onChange={event => { setCaseId(event.target.value); setTargets(null) }}/></label>}
        {selected.action==='block_domain' && <label>Domain to block<input name="domain" required maxLength={253}/></label>}
        {selected.action==='block_url' && <label>URL path to block<input name="domain" type="url" required maxLength={1500}/></label>}
        {needsTarget && <>
          <button className="secondary" type="button" disabled={busy || selected.action==='revoke_device' && !new RegExp('^'+uuid+'$').test(caseId)}
            onClick={pickTargets}>{selected.action==='lock_room' ? 'Load eligible rooms' : 'Load eligible devices'}</button>
          {targets?.length===0 && <p>No eligible targets.</p>}
          {targets && targets.length>0 && <label>Response target<select aria-label="Response target" name="target" required defaultValue="">
            <option value="" disabled>Choose a target</option>{targets.map(target => <option key={target.id} value={target.id}>
              {target.name}{selected.action==='revoke_device' ? ' · ' + target.id.slice(0,8) : ''}
            </option>)}
          </select></label>}
        </>}
        <label>Request reason<textarea name="reason" required minLength={10} maxLength={240}/></label>
        <button type="submit" disabled={busy || needsTarget && !targets?.length}>Request SOC response</button>
      </div>}
    </form>}
    {!report && <>
      <button className="secondary" type="button" disabled={busy} onClick={() => void refresh()}>Refresh response requests</button>
      {requests.length===0 && <p>No response requests in your scope.</p>}
      {requests.map(request => <article className="release-board-item" key={request.id} data-soc-response={request.id}>
        <h4>{actions[request.action]}</h4>
        <p>{request.decision==='executed' ? 'Executed' : request.decision==='rejected' ? 'Rejected' : 'Awaiting approval'} · <time dateTime={request.requested_at}>
          {new Date(request.requested_at).toLocaleString()}</time></p>
        {request.case_id && <p>Report <code>{request.case_id}</code></p>}
        {request.workspace && <p>Workspace <code>{request.workspace}</code></p>}
        {request.domain ? <p>{request.action==='block_url' ? 'URL path' : 'Domain'} <code>{request.domain}</code></p> :
          request.target && <p>Target <code>{request.target}</code></p>}
        <p>{request.reason}</p>
        {request.decision_reason && request.decided_at && <p>{request.decision_reason} · <time dateTime={request.decided_at}>
          {new Date(request.decided_at).toLocaleString()}</time></p>}
        {request.can_decide && <form className="release-form" onSubmit={event => resolve(event,request.id)}>
          <label>Response decision<select aria-label="Response decision" name="decision" required defaultValue="">
            <option value="" disabled>Choose a decision</option><option value="approve">Approve and execute</option><option value="reject">Reject</option>
          </select></label>
          <label>Decision reason<textarea name="reason" required minLength={10} maxLength={240}/></label>
          <button type="submit" disabled={busy}>Apply response decision</button>
        </form>}
      </article>)}
    </>}
    {notice && <p role="status">{notice}</p>}
    {error && <p role="alert" className="error">{error}</p>}
  </section>
}
