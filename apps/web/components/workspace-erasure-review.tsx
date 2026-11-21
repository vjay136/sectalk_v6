'use client'

import {useCallback,useEffect,useRef,useState,type FormEvent} from 'react'
import {db,formatError} from '../lib/data'

const labels:Record<string,string>={
  workspace:'Workspace record',members:'Workspace members',channels:'Channels',rooms:'Rooms',
  workspaceItems:'Workspace items',channelPosts:'Channel posts',roomPosts:'Room messages',roomTasks:'Room tasks',
  managedChannelPayloads:'Managed channel payloads',managedRoomPayloads:'Managed room payloads',
  roomReports:'Room reports',channelReports:'Channel reports',managedRoomEvidence:'Managed room evidence',
  preservedVersions:'Preserved message versions',holds:'Legal hold records',meetings:'Meetings',
  meetingRecordings:'Meeting recording records',tenantKeyVersions:'Tenant key versions',tenantKeyState:'Tenant key state',
  artifactEnvelopes:'Protected artifact envelopes',
  residencyRecoveryFileReceipts:'Regional recovery file receipts',residencyDestinationRetirements:'Regional destination retirement receipts',
  residencySourceReactivations:'Regional source reactivation receipts',residencyRecoveryPaths:'Private regional recovery Storage paths',
  workspaceTaskReceipts:'Workspace task deletion receipts',channelPostReceipts:'Channel post deletion receipts',
  roomPostReceipts:'Room message deletion receipts',roomTaskReceipts:'Room task deletion receipts',batchReceipts:'Batch deletion receipts',
  roomThreadReceipts:'Complete thread deletion receipts',workspaceRegistrationReceipts:'Workspace file registration removal receipts',
  archivedChannelReceipts:'Verified archived channel removal receipts',archivedChannelMessageReceipts:'Verified archived channel message removals',
  archivedRoomReceipts:'Verified archived room removal receipts',archivedChannelReceiptFindings:'Archived channel receipts needing attention',
  archivedRoomReceiptFindings:'Archived room receipts needing attention',
  roomRegistrationReceipts:'Room file registration removal receipts',workspaceFileCopyReceipts:'Verified workspace file copies',
  roomFileCopyReceipts:'Verified room file copies',workspaceFileRecoveryReviews:'Independently verified retained workspace files',
  roomFileRecoveryReviews:'Independently verified retained room files',
  workspaceRetiredPathsPresent:'Retired workspace file paths present again',roomRetiredPathsPresent:'Retired room file paths present again',
  published:'Published objects',retained:'Retained objects',removed:'Registered records with no listed object',
  pending:'Pending uploads',missing:'Missing objects',mismatch:'Metadata mismatches',untracked:'Untracked objects',
  storageMetadata:'Storage metadata records',workspaceRootReferences:'Direct workspace references',
  content:'Content containers',access:'Membership and access',preservation:'Audit and preservation',billing:'Billing and orders',
  integrations:'Integrations and routing',policies:'Workspace policies',operations:'Operational records',unclassified:'Unclassified references',
  cascade:'Would be removed automatically',restrict:'Prevent workspace record removal',setNull:'Would lose their workspace link',
  setDefault:'Would receive the configured default link'
}

type RootDependencies={categories:Record<string,number>;deleteActions:Record<string,number>;
  unsupportedConstraints:number;unclassifiedConstraints:number;overflowFamilies:number;directReferencesClear:boolean}
type Status={
  plan:string|null;sha256:string|null;observedAt:string|null;reviewedAt:string|null;expiresAt:string|null;
  current:boolean;held:boolean;archiveReviewInvalidated?:boolean;summary:{nativeRows:Record<string,number>;verifiedDeletionReceipts:Record<string,number>;
    archiveFindings?:Record<string,number>;workspaceRootDependencies?:RootDependencies;recoveryEvidence?:Record<string,number>;
    storageMetadata:Record<string,number>;overflow:string[]}
}

export function WorkspaceErasureReview({workspace,role}:{workspace:string;role:'owner'|'reviewer'}) {
  const [open,setOpen]=useState(false)
  const [status,setStatus]=useState<Status>()
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const revision=useRef(0)

  const load=useCallback(async()=>{
    const request=++revision.current
    const response=await db!.rpc('st_v8_offboarding_reconciliation',{p_workspace:workspace})
    if(request!==revision.current) return
    if(response.error) {
      setStatus(undefined)
      setError(formatError(response.error,'The reconciliation could not be loaded.'))
      return
    }
    setStatus(response.data)
    setError('')
  },[workspace])

  useEffect(()=>{
    if(!open) return
    void load()
    const timer=window.setInterval(()=>{if(document.visibilityState==='visible') void load()},30000)
    return ()=>{++revision.current;window.clearInterval(timer)}
  },[load,open])

  async function review(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if(busy||!status) return
    const form=event.currentTarget
    const reviewing=role==='reviewer'
    const confirmation=String(new FormData(form).get('workspace')).trim()
    const request=++revision.current
    setBusy(true)
    setError('')
    try {
      const result=await db!.rpc('st_v8_offboarding_reconciliation',{
        p_workspace:workspace,p_action:reviewing?'confirm':'capture',p_confirmation:confirmation,
        ...(reviewing?{p_plan:status.plan,p_sha256:status.sha256}:{})
      })
      if(result.error) throw result.error
      if(request===revision.current) {
        setStatus(result.data)
        form.reset()
      }
    } catch(cause) {
      if(request===revision.current) setError(formatError(cause,'The reconciliation action could not be completed.'))
    } finally {setBusy(false)}
  }

  function counts(title:string,values:Record<string,number>) {
    return <section aria-label={title}>
      <h5>{title}</h5>
      <dl>{Object.entries(values).map(([name,count])=><div key={name}>
        <dt>{labels[name]??name}</dt><dd>{count}</dd>
      </div>)}</dl>
    </section>
  }

  const archiveFindings=status?.summary.archiveFindings
  const blockedByArchives=Object.values(archiveFindings??{}).some(count=>count>0)
  const root=status?.summary.workspaceRootDependencies
  return <details className="release-create" onToggle={event=>setOpen(event.currentTarget.open)}>
    <summary>Source erasure reconciliation</summary>
    <section aria-label="Source erasure reconciliation">
      <p>Review the live records still present, scoped deletion receipts, verified copies, and current Storage metadata.</p>
      <p>Provider bytes, backups, and full tenant erasure are unverified.</p>
      {error&&<p role="alert" className="error">{error}</p>}
      {status&&<>
        {status.held&&<p>Active preservation holds block reconciliation approval.</p>}
        {blockedByArchives&&<p role="status">Archive receipt findings block capture and approval.</p>}
        {!blockedByArchives&&status.archiveReviewInvalidated&&<p role="status">A previous archive finding invalidated this review. Capture and confirm a fresh reconciliation.</p>}
        {(status.summary.storageMetadata.workspaceRetiredPathsPresent??0)+(status.summary.storageMetadata.roomRetiredPathsPresent??0)>0
          &&<p role="status">Previously retired paths are present again in Storage metadata.</p>}
        {!!status.summary.overflow.length&&<p role="status">Some counts are lower bounds. Approval is blocked for {status.summary.overflow.map(name=>labels[name]??name).join(', ')}.</p>}
        {status.plan&&<>
          <p>Captured digest <code>{status.sha256}</code></p>
          {status.observedAt&&<p>Captured <time dateTime={status.observedAt}>{new Date(status.observedAt).toLocaleString()}</time></p>}
          {status.reviewedAt&&<p>Reviewed <time dateTime={status.reviewedAt}>{new Date(status.reviewedAt).toLocaleString()}</time></p>}
          <p role="status">{!status.current?'Reconciliation changed, expired, or is blocked.':status.reviewedAt
            ?'Current reconciliation independently confirmed.':'Current reconciliation awaits independent review.'}</p>
        </>}
        {counts('Covered database records',status.summary.nativeRows)}
        {root&&<details>
          <summary>Workspace record removal preflight</summary>
          <p>These counts cover direct foreign-key references. A record can count more than once if it has several references.</p>
          <p>{root.directReferencesClear?'This snapshot found no direct references to the workspace record.'
            :'Workspace record removal requires disposition of the remaining references and preservation records.'}</p>
          {root.unsupportedConstraints>0&&<p role="status">{root.unsupportedConstraints} foreign-key constraints could not be evaluated. Capture and approval are blocked.</p>}
          {root.unclassifiedConstraints>0&&<p>{root.unclassifiedConstraints} foreign-key constraints still need a retention classification.</p>}
          {counts('Direct references by data family',root.categories)}
          {counts('Effect of removing the workspace record',root.deleteActions)}
        </details>}
        {counts('Verified scoped deletion receipts',status.summary.verifiedDeletionReceipts)}
        {archiveFindings&&counts('Archive receipt findings',archiveFindings)}
        {status.summary.recoveryEvidence&&counts('Verified copy and recovery evidence',status.summary.recoveryEvidence)}
        {counts('Current Storage metadata',status.summary.storageMetadata)}
        {!status.held&&!blockedByArchives&&!root?.unsupportedConstraints&&!status.summary.overflow.length
          &&(role==='owner'||(status.current&&!status.reviewedAt))&&<form className="release-form" onSubmit={event=>void review(event)}>
            <p>Enter workspace ID <code>{workspace}</code> to confirm.</p>
            <label>Confirm reconciliation workspace ID<input name="workspace" required maxLength={36} autoComplete="off"/></label>
            <button className="secondary" disabled={busy}>{role==='owner'?'Capture current source reconciliation':'Confirm exact source reconciliation'}</button>
          </form>}
      </>}
      <button type="button" className="secondary" disabled={busy} onClick={()=>void load()}>Refresh source reconciliation</button>
    </section>
  </details>
}
