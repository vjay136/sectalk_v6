'use client'

import {useCallback,useEffect,useRef,useState,type FormEvent} from 'react'
import {db,formatError} from '../lib/data'
import {isFreeRelease} from '../lib/release-scope'
import {StaffMfa} from './staff-mfa'
import {WorkspaceContentExport} from './workspace-content-export'
import {WorkspaceErasureReview} from './workspace-erasure-review'
import {WorkspaceFileRegistrationCleanup} from './workspace-file-registration-cleanup'
import {WorkspaceOffboardingCustody} from './workspace-offboarding-custody'
import {WorkspaceSourceBatch} from './workspace-source-batch'
import {WorkspaceSourceDeletion} from './workspace-task-deletion'
import {WorkspaceReviewedRemoval} from './workspace-reviewed-removal'
import {WorkspaceThreadDeletion} from './workspace-thread-deletion'

type Inventory={name:string;regionPreference:string;inventory:{members:number;rooms:number;channels:number;workspaceItems:number}}
type IntegrationShutdown={at:string;apiKeys:number;webhooks:number;webhookJobs:number;scimTokens:number}
type Request={id:string;state:'requested'|'approved'|'read_only';sha256:string;case:string|null;
  artifact:boolean;expired:boolean;downloaded:boolean;snapshot:Inventory;manifestSha256:string|null;reason:string;
  integrationShutdown?:IntegrationShutdown|null}
type State={access:'mfa'|'verified';role:'owner'|'reviewer';held:boolean;request:Request|null}
type StoragePlan={plan:string|null;sha256:string|null;reviewedAt:string|null;held:boolean;clean:boolean;current:boolean;
  limitExceeded:boolean;counts:Record<'published'|'retained'|'removed'|'pending'|'missing'|'mismatch'|'untracked',number>}
const labels={requested:'Awaiting independent approval',approved:'Inventory export approved',read_only:'Read-only offboarding staged'}
const commands={requested:'Request offboarding inventory',approved:'Approve exact inventory',withdrawn:'Withdraw offboarding request',
  read_only:'Stage workspace read-only'} as const
type Command=keyof typeof commands

export function WorkspaceOffboarding({workspace,reviewOnly=false}:{workspace:string;reviewOnly?:boolean}) {
  const [state,setState]=useState<State>()
  const [storagePlan,setStoragePlan]=useState<StoragePlan>()
  const [storageCopies,setStorageCopies]=useState<{workspace?:number;room?:number}>()
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [ack,setAck]=useState('')
  const pending=useRef<{reason:string;id:string}|null>(null)
  const load=useCallback(async(signal?:AbortSignal)=>{
    const query=db!.rpc('st_v8_workspace_offboarding',{p_workspace:workspace})
    const result=await (signal?query.abortSignal(signal):query)
    if(signal?.aborted)return
    setStorageCopies(undefined)
    if(result.error) {
      setState(undefined)
      setStoragePlan(undefined)
      if(result.error.code!=='42501')setError('Could not load workspace offboarding.')
      return
    }
    setState(result.data)
    if(result.data?.access==='verified'&&result.data.request?.state==='read_only') {
      const query=db!.rpc('st_v8_offboarding_storage_plan',{p_workspace:workspace})
      const plan=await (signal?query.abortSignal(signal):query)
      if(!signal?.aborted) {
        setStoragePlan(plan.error?undefined:plan.data)
        if(plan.error&&plan.error.code!=='42501')setError('Could not load Storage review.')
      }
      if(!plan.error&&plan.data?.plan&&plan.data.current&&plan.data.reviewedAt&&!plan.data.held) {
        const args={p_workspace:workspace,p_plan:plan.data.plan}
        const reads=[db!.rpc('st_v8_offboarding_storage_copies',args),db!.rpc('st_v8_offboarding_room_storage_copies',args)]
        const [workspaceCopies,roomCopies]=await Promise.all(reads.map(read=>signal?read.abortSignal(signal):read))
        if(!signal?.aborted)setStorageCopies({workspace:workspaceCopies.error?undefined:workspaceCopies.data?.verifiedCopies?.length,
          room:roomCopies.error?undefined:roomCopies.data?.verifiedCopies?.length})
      } else if(!signal?.aborted)setStorageCopies(undefined)
    } else {
      setStoragePlan(undefined)
      setStorageCopies(undefined)
    }
  },[workspace])
  useEffect(()=>{
    const controller=new AbortController()
    void load(controller.signal)
    return ()=>controller.abort()
  },[load])

  async function run(operation:()=>Promise<void>) {
    if(busy)return
    setBusy(true);setError('');setAck('')
    try {await operation();await load()}
    catch(cause) {setError(formatError(cause,'Could not complete this offboarding action.'));await load()}
    finally {setBusy(false)}
  }
  function submit(action:Command,event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const values=new FormData(event.currentTarget)
    const reason=String(values.get('reason')??'').trim()
    let id=state?.request?.id
    if(action==='requested') {
      if(pending.current?.reason!==reason)pending.current={reason,id:crypto.randomUUID()}
      id=pending.current.id
    }
    if(!id)return
    void run(async()=>{
      const result=await db!.rpc('st_v8_workspace_offboarding_change',{p_workspace:workspace,p_id:id,p_action:action,
        p_confirmation:String(values.get('confirmation')??'').trim(),p_reason:reason||null})
      if(result.error)throw result.error
      pending.current=null
    })
  }
  function form(action:Command) {
    return <details className="release-create">
      <summary>{commands[action]}</summary>
      <form className="release-form" onSubmit={event=>submit(action,event)}>
        {action==='requested'&&<label>Offboarding purpose<textarea name="reason" minLength={15} maxLength={500} required/></label>}
        {action==='read_only'&&<p>Staging revokes workspace API and SCIM credentials, disables outbound webhooks and cancels pending deliveries.</p>}
        <p>To confirm, enter workspace ID <code>{workspace}</code>.</p>
        <label>Confirm workspace ID<input name="confirmation" required autoComplete="off" maxLength={36}/></label>
        <button className="secondary" disabled={busy}>{commands[action]}</button>
      </form>
    </details>
  }
  function exportInventory(method:'POST'|'GET') {
    const caseId=state?.request?.case
    if(!caseId)return
    void run(async()=>{
      const {data}=await db!.auth.getSession()
      if(!data.session)throw new Error('Sign in again.')
      const response=await fetch('/api/compliance-exports/'+caseId,{method,headers:{Authorization:'Bearer '+data.session.access_token}})
      if(!response.ok)throw new Error('The approved inventory export is unavailable for this session.')
      if(method==='GET') {
        const url=URL.createObjectURL(await response.blob())
        const link=document.createElement('a')
        link.href=url;link.download='sectalk-workspace-inventory.json';link.click()
        window.setTimeout(()=>URL.revokeObjectURL(url),1000)
      }
      setAck(method==='GET'?'Workspace inventory downloaded.':'Workspace inventory ready to download.')
    })
  }

  function submitStorage(action:'capture'|'confirm',event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const confirmation=String(new FormData(event.currentTarget).get('confirmation')??'').trim()
    void run(async()=>{
      const result=await db!.rpc('st_v8_offboarding_storage_plan',{p_workspace:workspace,p_action:action,
        p_confirmation:confirmation,p_plan:storagePlan?.plan,p_sha256:storagePlan?.sha256})
      if(result.error)throw result.error
      setAck(action==='capture'?'Current Storage inventory captured.':'Exact Storage inventory confirmed.')
    })
  }

  if(!state)return !reviewOnly&&error?<p role="alert">{error}</p>:null
  if(reviewOnly&&state.role!=='reviewer')return null
  const request=state.request
  return <section className="release-section" aria-label="Workspace offboarding">
    <h3>Workspace offboarding</h3>
    {isFreeRelease&&<p role="status">Permanent workspace erasure is planned for a future release. Use the available export, preservation, and offboarding review controls.</p>}
    <p>The inventory includes workspace settings and record counts. Message content, files, personal accounts and other workspaces stay out of this export.</p>
    <p>Read-only staging preserves the workspace. Permanent deletion and key destruction are separate from this workflow.</p>
    {state.access==='mfa'&&<StaffMfa refresh={load} explanation="Verify your authenticator to manage workspace offboarding."/>}
    {error&&<p role="alert">{error}</p>}
    {ack&&<p role="status">{ack}</p>}
    {state.access==='verified'&&<>
      {!request&&state.role==='owner'&&form('requested')}
      {!request&&state.role==='reviewer'&&<p>No offboarding request awaits review.</p>}
      {request&&<>
        <p role="status">{labels[request.state]}</p>
        <p>{request.reason}</p>
        <dl>
          <dt>Workspace inventory</dt><dd>{request.snapshot.name}</dd>
          <dt>Active memberships</dt><dd>{request.snapshot.inventory.members}</dd>
          <dt>Rooms</dt><dd>{request.snapshot.inventory.rooms}</dd>
          <dt>Channels</dt><dd>{request.snapshot.inventory.channels}</dd>
          <dt>Workspace items</dt><dd>{request.snapshot.inventory.workspaceItems}</dd>
          <dt>Inventory SHA-256</dt><dd><code>{request.sha256}</code></dd>
          {request.manifestSha256&&<><dt>Approved manifest SHA-256</dt><dd><code>{request.manifestSha256}</code></dd></>}
        </dl>
        {request.integrationShutdown&&<dl aria-label="Offboarding integration receipt">
          <dt>Integration shutdown</dt><dd><time dateTime={request.integrationShutdown.at}>{new Date(request.integrationShutdown.at).toLocaleString()}</time></dd>
          <dt>API keys revoked</dt><dd>{request.integrationShutdown.apiKeys}</dd>
          <dt>Webhook endpoints disabled</dt><dd>{request.integrationShutdown.webhooks}</dd>
          <dt>Webhook deliveries cancelled</dt><dd>{request.integrationShutdown.webhookJobs}</dd>
          <dt>SCIM credentials revoked</dt><dd>{request.integrationShutdown.scimTokens}</dd>
        </dl>}
        {storagePlan&&request.state==='read_only'&&<section className="release-section" aria-label="Offboarding Storage review">
          <h4>Offboarding Storage review</h4>
          <p>Review the workspace file bucket before arranging permanent deletion. The review records current object metadata. Provider versions, backups and other data stores require their own evidence.</p>
          <dl>
            <dt>Published objects</dt><dd>{storagePlan.counts.published}</dd>
            <dt>Retained objects</dt><dd>{storagePlan.counts.retained}</dd>
            <dt>Already removed</dt><dd>{storagePlan.counts.removed}</dd>
            <dt>Pending uploads</dt><dd>{storagePlan.counts.pending}</dd>
            <dt>Missing published objects</dt><dd>{storagePlan.counts.missing}</dd>
            <dt>Object metadata mismatches</dt><dd>{storagePlan.counts.mismatch}</dd>
            <dt>Untracked objects</dt><dd>{storagePlan.counts.untracked}</dd>
            {storagePlan.sha256&&<><dt>Storage inventory SHA-256</dt><dd><code>{storagePlan.sha256}</code></dd></>}
            {storageCopies?.workspace!==undefined&&<><dt>Verified workspace file copies</dt><dd>{storageCopies.workspace}</dd></>}
            {storageCopies?.room!==undefined&&<><dt>Verified room file copies</dt><dd>{storageCopies.room}</dd></>}
          </dl>
          {storagePlan.held&&<p role="status">An active legal hold blocks Storage review.</p>}
          {storagePlan.limitExceeded&&<p role="status">The workspace exceeds the 500-record Storage review limit. These counts show a sample.</p>}
          {storagePlan.plan&&!storagePlan.current&&<p role="status">Capture a new inventory. The previous capture changed or expired.</p>}
          {storagePlan.reviewedAt&&storagePlan.current&&!storagePlan.held&&<p role="status">Current Storage inventory independently confirmed.</p>}
          {!storagePlan.held&&!storagePlan.limitExceeded&&(state.role==='owner'||(storagePlan.current&&storagePlan.clean&&!storagePlan.reviewedAt))&&
            <form className="release-form" onSubmit={event=>submitStorage(state.role==='owner'?'capture':'confirm',event)}>
              <p>To confirm, enter workspace ID <code>{workspace}</code>.</p>
              <label>Confirm Storage workspace ID<input name="confirmation" required autoComplete="off" maxLength={36}/></label>
              <button className="secondary" disabled={busy}>{state.role==='owner'?'Capture workspace Storage inventory':'Confirm exact Storage inventory'}</button>
            </form>}
        </section>}
        {state.held&&<p>Active legal holds prevent read-only staging.</p>}
        {request.expired&&<p>The approved inventory export has expired.</p>}
        {state.role==='reviewer'&&request.state==='requested'&&form('approved')}
        {state.role==='owner'&&<>
          {request.state==='approved'&&!request.expired&&!request.artifact&&
            <button type="button" className="secondary" disabled={busy} onClick={()=>exportInventory('POST')}>Build inventory export</button>}
          {request.artifact&&<button type="button" className="secondary" disabled={busy} onClick={()=>exportInventory('GET')}>Download inventory export</button>}
          {request.state==='approved'&&request.downloaded&&!request.expired&&!state.held&&form('read_only')}
          {request.state!=='read_only'&&form('withdrawn')}
        </>}
      </>}
      <button type="button" className="secondary" disabled={busy} onClick={()=>void load()}>Refresh offboarding status</button>
      <WorkspaceContentExport workspace={workspace} storagePlan={storagePlan?.current&&storagePlan.reviewedAt&&!storagePlan.held
        ?storagePlan.plan??undefined:undefined} onStorageCopy={()=>void load()}/>
      {request?.state==='read_only'&&<>
        <WorkspaceSourceDeletion key={workspace+'-task'} workspace={workspace} role={state.role} kind="task"/>
        <WorkspaceSourceDeletion key={workspace+'-post'} workspace={workspace} role={state.role} kind="post"/>
        <WorkspaceSourceDeletion key={workspace+'-room-post'} workspace={workspace} role={state.role} kind="roomPost"/>
        <WorkspaceSourceDeletion key={workspace+'-room-task'} workspace={workspace} role={state.role} kind="roomTask"/>
        <WorkspaceReviewedRemoval key={workspace+'-archived-channel'} workspace={workspace} role={state.role} kind="channel"/>
        <WorkspaceReviewedRemoval key={workspace+'-archived-room'} workspace={workspace} role={state.role} kind="room"/>
        <WorkspaceReviewedRemoval key={workspace+'-revoked-api-key'} workspace={workspace} role={state.role} kind="key"/>
        <WorkspaceReviewedRemoval key={workspace+'-revoked-webhook'} workspace={workspace} role={state.role} kind="endpoint"/>
        <WorkspaceReviewedRemoval key={workspace+'-declined-invitation'} workspace={workspace} role={state.role} kind="invitation"/>
        <WorkspaceReviewedRemoval key={workspace+'-expired-invitation-link'} workspace={workspace} role={state.role} kind="link"/>
        <WorkspaceReviewedRemoval key={workspace+'-archived-group'} workspace={workspace} role={state.role} kind="group"/>
        <WorkspaceReviewedRemoval key={workspace+'-withdrawn-enterprise-quote'} workspace={workspace} role={state.role} kind="order"/>
        <WorkspaceReviewedRemoval key={workspace+'-rejected-seat-change'} workspace={workspace} role={state.role} kind="change"/>
        <WorkspaceReviewedRemoval key={workspace+'-suspended-membership'} workspace={workspace} role={state.role} kind="member"/>
        <WorkspaceThreadDeletion key={workspace+'-thread'} workspace={workspace} role={state.role}/>
        <WorkspaceSourceBatch key={workspace} workspace={workspace} role={state.role}/>
        <WorkspaceOffboardingCustody key={workspace+'-audit-custody'} workspace={workspace} role={state.role} kind="audit"/>
        <WorkspaceErasureReview key={workspace+'-erasure-review'} workspace={workspace} role={state.role}/>
        {!isFreeRelease&&<WorkspaceOffboardingCustody key={workspace+'-external-key-retirement'} workspace={workspace} role={state.role} kind="provider"/>}
        <WorkspaceOffboardingCustody key={workspace+'-workflow-custody'} workspace={workspace} role={state.role} kind="workflow"/>
        <WorkspaceFileRegistrationCleanup key={workspace+'-room-file-cleanup'} workspace={workspace} role={state.role} scope="room"/>
        <WorkspaceFileRegistrationCleanup key={workspace+'-workspace-file-cleanup'} workspace={workspace} role={state.role} scope="workspace"/>
      </>}
    </>}
  </section>
}
