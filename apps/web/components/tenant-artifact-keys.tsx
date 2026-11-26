'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'
import { isFreeRelease } from '../lib/release-scope'

type KeyState = {
  access: 'none' | 'mfa' | 'owner' | 'admin'; enterprise: boolean;
  active: { version: number; custody: 'managed' | 'byok' | null; destroyed_at: string | null } | null;
  reviewer: boolean; can_request_destroy: boolean;
  pending: { id: string; reason: string; version: number } | null;
  audit: { id: number; event: string; reason: string | null; occurred_at: string; version: number }[];
}
type RotationSchedule = { schedule?: { days: number; paused: boolean; next: string } | null }
type ProviderErasure = {canVerify:boolean;held:boolean;sourceDeletion:'unverified';backupErasure:'unverified';
  versions:{version:number;eventTime:string|null;eventDigest:string|null}[]}
const providerMessages:Record<string,string>={
  active:'The provider key is active.',disabled:'The provider key is disabled.',
  pending_deletion:'The provider reports pending deletion.',pending_replica_deletion:'The provider is waiting for replica deletion.',
  unavailable:'A provider deletion event could not be verified.',deleted_event:'Provider deletion event verified.',
}
const labels: Record<string,string> = {
  provisioned:'Managed key provisioned',rotated:'New key version activated',destroy_requested:'Key destruction requested',
  destroyed:'Managed key copies destroyed',rejected:'Destruction request rejected',
  rotation_schedule_set:'Rotation schedule saved',rotation_schedule_disabled:'Rotation schedule disabled',
  scheduled_rotation:'Scheduled rotation activated',
}

export function TenantArtifactKeys({ workspace }: { workspace: string }) {
  const [state,setState]=useState<KeyState | null>(null)
  const [schedule,setSchedule]=useState<RotationSchedule | null>(null)
  const [provider,setProvider]=useState<ProviderErasure|null>(null)
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [notice,setNotice]=useState('')
  const refresh=useCallback(async()=>{
    const [response,scheduled,erasure]=await Promise.all([
      db!.rpc('st_v7_tenant_key_status',{p_workspace:workspace}),
      db!.rpc('st_v8_tenant_rotation_schedule',{p_workspace:workspace}),
      isFreeRelease ? null : db!.rpc('st_v8_tenant_provider_erasure_status',{p_workspace:workspace}),
    ])
    if (response.error) { setError('Could not load workspace key state.');return }
    setState(response.data as KeyState)
    setSchedule(scheduled.error ? null : scheduled.data as RotationSchedule)
    setProvider(!erasure || erasure.error ? null : erasure.data as ProviderErasure|null)
  },[workspace])
  useEffect(()=>{void refresh()},[refresh])

  async function run(event: FormEvent<HTMLFormElement>, action: 'rotate' | 'schedule' | 'request' | 'decide' | 'verify-provider' | 'export-provider') {
    event.preventDefault()
    if (busy) return
    const form=event.currentTarget
    const fields=new FormData(form)
    setBusy(true);setNotice('');setError('')
    try {
      if (action==='rotate') {
        const {data:{session}}=await db!.auth.getSession()
        if (!session) throw new Error('Sign in again to manage keys.')
        const response=await fetch('/api/tenant-keys',{
          method:'POST',headers:{Authorization:'Bearer '+session.access_token,'Content-Type':'application/json'},
          body:JSON.stringify({workspace,custody:fields.get('custody'),reason:fields.get('key-reason')}),
        })
        const result=await response.json()
        if (!response.ok) throw new Error(result.error || 'Could not rotate the workspace key.')
        setNotice('Workspace key version '+result.version+' is active.')
      } else if (action==='verify-provider') {
        const {data:{session}}=await db!.auth.getSession()
        if (!session) throw new Error('Sign in again to verify provider key evidence.')
        const response=await fetch('/api/tenant-keys/provider-erasure',{
          method:'POST',headers:{Authorization:'Bearer '+session.access_token,'Content-Type':'application/json'},
          body:JSON.stringify({workspace,version:Number(fields.get('provider-version')),confirmation:fields.get('provider-confirmation')}),
        })
        const result=await response.json()
        if (!response.ok) throw new Error(result.error || 'Could not verify provider key evidence.')
        setNotice(providerMessages[result.state] ?? providerMessages.unavailable)
      } else if (action==='export-provider') {
        const version=Number(fields.get('export-provider-version'))
        const result=await db!.rpc('st_v8_export_provider_key_evidence',{p_workspace:workspace,p_version:version,
          p_confirmation:String(fields.get('export-provider-confirmation')).trim()})
        if (result.error) throw result.error
        const url=URL.createObjectURL(new Blob([result.data.json],{type:'application/json'}))
        const link=document.createElement('a')
        link.href=url
        link.download='sectalk-provider-key-evidence-v'+version+'.json'
        link.click()
        window.setTimeout(()=>URL.revokeObjectURL(url),1000)
        setNotice('Provider evidence downloaded. Record this SHA-256 in the operations log. '+result.data.sha256)
      } else if (action==='schedule') {
        const days=Number(fields.get('rotation-days'))
        const response=await db!.rpc('st_v8_tenant_rotation_schedule',{p_workspace:workspace,p_days:days})
        if (response.error) throw response.error
        setNotice(days ? 'Managed-key rotation schedule saved.' : 'Managed-key rotation schedule disabled.')
      } else {
        const reason=fields.get('key-reason')
        const confirmation=fields.get('workspace-confirmation')
        const response=action==='request' ? await db!.rpc('st_v7_request_tenant_key_destroy',{
          p_workspace:workspace,p_confirmation:confirmation,p_reason:reason,
        }) : await db!.rpc('st_v7_decide_tenant_key_destroy',{
          p_request:state?.pending?.id,p_approve:fields.get('destruction-decision')==='approve',p_confirmation:confirmation,p_reason:reason,
        })
        if (response.error) throw response.error
        setNotice(action==='request' ? 'Destruction requested. A separate reviewer must decide.' :
          response.data==='destroyed' ? 'Managed key copies have been destroyed.' : 'Destruction request rejected.')
      }
      form.reset()
      await refresh()
    } catch (failure) { setError(formatError(failure,'The workspace key operation could not be completed.')) }
    finally { setBusy(false) }
  }

  if (state?.access==='none') return null
  const active=state?.active
  const canRotate=state?.access==='owner' && !active?.destroyed_at
  const canSchedule=canRotate && active?.custody==='managed'
  return <section className="release-section" aria-label="Managed artifact keys">
    <h3>Managed artifact keys</h3>
    <p>These workspace keys protect new compliance bundles and evidence vault captures.</p>
    {error && <p role="alert" className="error">{error}</p>}
    {notice && <p role="status">{notice}</p>}
    {!state && !error && <p role="status">Loading workspace keys…</p>}
    {state?.access==='mfa' && <p>Refresh authenticator verification before managing keys.</p>}
    {state && state.access!=='mfa' && <p>{!active ? 'No key has been created.' : active.destroyed_at
      ? 'Managed key copies destroyed.' : 'Version '+active.version+' · '+(active.custody==='byok' ? 'Enterprise external custody' : 'Managed custody')}</p>}
    {canRotate && <form className="release-form" onSubmit={event=>void run(event,'rotate')}>
      <label>Key custody<select name="custody" aria-label="Key custody"><option value="managed">Managed custody</option>
        {!isFreeRelease&&state.enterprise && <option value="byok">Configured Enterprise external custody</option>}
      </select></label>
      <label>Key rotation reason<textarea name="key-reason" minLength={15} maxLength={240} required/></label>
      <button type="submit" disabled={busy}>{active ? 'Rotate workspace key' : 'Create workspace key'}</button>
    </form>}
    {schedule && (state?.access==='owner' || state?.access==='admin') && <details>
      <summary>Automatic managed-key rotation</summary>
      <p>{!schedule.schedule ? 'Automatic rotation is off.' : schedule.schedule.paused ? 'Automatic rotation is paused.' :
        <>Every {schedule.schedule.days} days · Next due <time dateTime={schedule.schedule.next}>
          {new Date(schedule.schedule.next).toLocaleDateString()}</time></>}</p>
      {state.access==='owner' && (canSchedule || schedule.schedule) && <form key={schedule.schedule?.days ?? 0}
        className="release-form" onSubmit={event=>void run(event,'schedule')}>
        <label>Rotation interval<select name="rotation-days" defaultValue={schedule.schedule?.days ?? 0}>
          <option value="0">Off</option>
          {[30,60,90].map(days=><option key={days} value={days} disabled={!canSchedule}>Every {days} days</option>)}
        </select></label>
        <button type="submit" disabled={busy}>Save rotation schedule</button>
      </form>}
    </details>}
    <button className="secondary" type="button" disabled={busy} onClick={()=>void refresh()}>Refresh key status</button>
    {!isFreeRelease&&provider && provider.versions.length>0 && <details>
      <summary>Provider key erasure evidence</summary>
      <p>Workspace source deletion is unverified. Backup erasure is unverified.</p>
      {provider.held && <p>Active preservation holds pause provider verification.</p>}
      <ul className="audit">{provider.versions.map(({version,eventTime,eventDigest})=><li key={version}>
        Version {version} · {eventTime ? <>Provider deletion event verified on <time dateTime={eventTime}>
          {new Date(eventTime).toLocaleString()}</time>{eventDigest && <> · <code>{eventDigest}</code></>}</> : 'Awaiting provider evidence'}
      </li>)}</ul>
      {provider.canVerify && provider.versions.some(item=>!item.eventTime) && <form className="release-form"
        onSubmit={event=>void run(event,'verify-provider')}>
        <p>Workspace ID <code>{workspace}</code></p>
        <label>External key version<select name="provider-version" required defaultValue="">
          <option value="" disabled>Choose a key version</option>
          {provider.versions.filter(item=>!item.eventTime).map(item=><option key={item.version} value={item.version}>Version {item.version}</option>)}
        </select></label>
        <label>Confirm workspace for provider evidence<input name="provider-confirmation" required autoComplete="off"/></label>
        <button type="submit" disabled={busy}>Verify provider deletion event</button>
      </form>}
      {provider.canVerify && provider.versions.some(item=>item.eventTime) && <form className="release-form"
        onSubmit={event=>void run(event,'export-provider')}>
        <p>Download the scoped provider receipt for comparison with an independently verified backup generation.</p>
        <label>Verified external key version<select name="export-provider-version" required defaultValue="">
          <option value="" disabled>Choose a key version</option>
          {provider.versions.filter(item=>item.eventTime).map(item=><option key={item.version} value={item.version}>Version {item.version}</option>)}
        </select></label>
        <label>Confirm workspace for evidence export<input name="export-provider-confirmation" required maxLength={36} autoComplete="off"/></label>
        <button type="submit" disabled={busy}>Download provider key evidence</button>
      </form>}
    </details>}
    {(state?.pending || state?.can_request_destroy) && <details>
      <summary>Managed key destruction</summary>
      <p>Destroying the stored managed keys makes protected artifacts unreadable through this service. Active legal holds and external key custody block destruction.</p>
      {state.pending && <p>Pending version {state.pending.version} · {state.pending.reason}</p>}
      {(state.can_request_destroy && !state.pending || state.reviewer && state.pending) &&
        <form className="release-form" onSubmit={event=>void run(event,state.pending ? 'decide' : 'request')}>
          <p>Workspace ID <code>{workspace}</code></p>
          {state.pending && <label>Key destruction decision<select name="destruction-decision" aria-label="Key destruction decision" required defaultValue="">
            <option value="" disabled>Choose a decision</option><option value="reject">Reject request</option>
            <option value="approve">Destroy managed keys</option></select></label>}
          <label>Confirm the workspace ID<input name="workspace-confirmation" required autoComplete="off"/></label>
          <label>Key destruction reason<textarea name="key-reason" minLength={15} maxLength={240} required/></label>
          <button type="submit" disabled={busy}>{state.pending ? 'Apply key destruction decision' : 'Request managed key destruction'}</button>
        </form>}
    </details>}
    {state && state.audit?.length>0 && <details>
      <summary>Key audit history</summary>
      <ul className="audit">{state.audit.map(event=><li key={event.id}>
        {labels[event.event]} · Version {event.version} · <time dateTime={event.occurred_at}>{new Date(event.occurred_at).toLocaleString()}</time>
        {event.reason && <p>{event.reason}</p>}
      </li>)}</ul>
    </details>}
  </section>
}
