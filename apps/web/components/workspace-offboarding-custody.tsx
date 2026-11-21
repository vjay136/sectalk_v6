'use client'

import {useCallback,useEffect,useRef,useState,type FormEvent} from 'react'
import {db,formatError} from '../lib/data'

type Action='capture'|'approve'|'detach'
type Custody={
  plan:string|null;sha256:string|null;held:boolean;linked:boolean;current:boolean;approvedAt:string|null;
  auditSha256?:string|null;eventCount?:number;verified?:boolean;
  requestSha256?:string;inventorySha256?:string;ready?:boolean;provider?:ProviderStatus
}

type ProviderStatus={
  state:'no-recorded-key-history'|'unresolved-key-history'|'exact-provider-key-evidence'|'native-markers-retired';
  plan:string|null;planSha256:string|null;sha256:string;held:boolean;approvedAt:string|null;
  versions:number;matched:number;retiredVersions:number;receiptSha256:string|null
}

function providerCustody(provider:ProviderStatus,ready:boolean):Custody {
  const linked=provider.state==='exact-provider-key-evidence'||provider.state==='unresolved-key-history'
  return {plan:provider.plan,sha256:provider.planSha256,held:provider.held,linked,ready,
    current:ready&&!!provider.plan,approvedAt:provider.approvedAt,provider}
}

const scopes={
  audit:{
    title:'Workspace audit custody',rpc:'st_v8_offboarding_workspace_audit_custody',refresh:12000,
    terminal:'detach',
    description:'Preserve the original workspace audit events and chain before releasing their link to the live workspace. A new audit event restores the link and requires a new review.',
    linked:'Audit remains linked to the live workspace.',
    retained:'Audit retained independently of the live workspace.',
    held:'Active preservation holds block release of the audit link.',
    blocked:'The current audit could not be verified within the supported scope.',
    stale:'Capture a new plan for the current audit.',
    review:'Awaiting independent audit review.',
    approved:'Audit custody independently approved.',
    confirm:'Confirm audit custody workspace ID',
    retention:'I confirm the original audit events and chain will be retained.',
    reload:'Refresh audit custody status',
    commands:{capture:'Capture audit custody plan',approve:'Approve exact audit custody',detach:'Release approved audit link'}
  },
  workflow:{
    title:'Offboarding records custody',rpc:'st_v8_offboarding_workflow_custody',refresh:30000,
    terminal:'detach',
    description:'Keep the original offboarding request and approved inventory case with their evidence. Complete workspace audit custody and confirm the current source reconciliation before reviewing these two links.',
    linked:'Offboarding records remain linked to the live workspace.',
    retained:'Offboarding records retained independently of the live workspace.',
    held:'Active preservation holds block release of the offboarding record links.',
    blocked:'Complete current workspace audit custody and independent source reconciliation with a valid downloaded inventory.',
    stale:'Capture a new plan for the current offboarding records.',
    review:'Awaiting independent offboarding records review.',
    approved:'Offboarding records custody independently approved.',
    confirm:'Confirm offboarding records workspace ID',
    retention:'I confirm the original offboarding request and approved inventory case will be retained.',
    reload:'Refresh offboarding records custody',
    commands:{capture:'Capture offboarding records plan',approve:'Approve exact offboarding records custody',detach:'Release approved offboarding record links'}
  },
  provider:{
    title:'External key records retirement',rpc:'st_v8_offboarding_provider_key_retirement',refresh:30000,
    terminal:'retire',
    description:'Retire the native references to external key versions after the designated reviewer verifies every provider receipt in Artifact keys and confirms the current source reconciliation.',
    linked:'External key references remain in the workspace database.',
    retained:'External key references retired. The provider receipts and key audit are retained.',
    held:'Active preservation holds block external key record retirement.',
    blocked:'Verify every provider key receipt and confirm the latest source reconciliation before continuing.',
    stale:'Capture a fresh retirement plan for the current external key records.',
    review:'Awaiting independent external key retirement review.',
    approved:'External key record retirement independently approved.',
    confirm:'Confirm external key retirement workspace ID',
    retention:'I confirm the reviewed key references will be permanently removed from the database and the provider receipts will be retained.',
    reload:'Refresh external key retirement status',
    commands:{capture:'Capture external key retirement plan',approve:'Approve exact external key retirement',detach:'Retire approved external key records'}
  }
}

export function WorkspaceOffboardingCustody({workspace,role,kind}:{
  workspace:string;role:'owner'|'reviewer';kind:keyof typeof scopes
}) {
  const scope=scopes[kind]
  const [open,setOpen]=useState(false)
  const [custody,setCustody]=useState<Custody>()
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const latest=useRef(0)
  const submitting=useRef(false)
  const refresh=useCallback(async()=>{
    if(submitting.current)return
    const request=++latest.current
    const result=await db!.rpc(scope.rpc,{p_workspace:workspace})
    if(request!==latest.current)return
    if(result.error) {
      setCustody(undefined)
      setError(formatError(result.error,'Could not load '+scope.title.toLowerCase()+'.'))
      return
    }
    if(kind==='provider') {
      const provider:ProviderStatus=result.data
      let ready=false
      if(provider.state==='exact-provider-key-evidence'&&!provider.held) {
        const reconciliation=await db!.rpc('st_v8_offboarding_reconciliation',{p_workspace:workspace})
        if(request!==latest.current)return
        if(reconciliation.error) {
          setCustody(providerCustody(provider,false))
          setError(formatError(reconciliation.error,'Could not load the current source reconciliation.'))
          return
        }
        ready=reconciliation.data?.current===true&&!!reconciliation.data?.reviewedAt
      }
      setCustody(providerCustody(provider,ready))
    } else {
      setCustody(result.data)
    }
    setError('')
  },[workspace,scope,kind])

  useEffect(()=>{
    if(!open)return
    void refresh()
    const interval=window.setInterval(()=>{if(document.visibilityState==='visible')void refresh()},scope.refresh)
    return ()=>{++latest.current;window.clearInterval(interval)}
  },[open,refresh,scope.refresh])

  const eligible=custody&&(kind==='audit'?custody.verified:custody.ready)
  const action:Action|undefined=custody?.linked&&eligible&&!custody.held
    ? role==='owner'
      ? custody.current&&custody.approvedAt?'detach':custody.current?undefined:'capture'
      : custody.current&&custody.plan&&!custody.approvedAt?'approve':undefined
    : undefined
  const canRecapture=kind==='provider'&&role==='owner'&&custody?.linked&&eligible&&!custody.held&&action!=='capture'
  const actions:Action[]=canRecapture?(action?[action,'capture']:['capture']):action?[action]:[]

  async function submit(event:FormEvent<HTMLFormElement>,action:Action) {
    event.preventDefault()
    if(submitting.current||!custody)return
    const form=event.currentTarget
    const value=String(new FormData(form).get('workspace')).trim()
    if(value!==workspace) {
      setError('Enter the exact workspace ID.')
      return
    }
    const request=++latest.current
    submitting.current=true
    setBusy(true)
    setError('')
    try {
      const result=await db!.rpc(scope.rpc,{
        p_workspace:workspace,p_action:action==='detach'?scope.terminal:action,p_confirmation:value,
        ...(action==='capture'?{}:{p_plan:custody.plan,p_sha256:custody.sha256})
      })
      if(result.error)throw result.error
      if(request===latest.current)setCustody(kind==='provider'?providerCustody(result.data,!!custody.ready):result.data)
      form.reset()
    } catch(cause) {
      if(request===latest.current)setError(formatError(cause,'Could not complete the custody action.'))
    } finally {
      submitting.current=false
      setBusy(false)
    }
  }

  return <details className="release-create" onToggle={event=>setOpen(event.currentTarget.open)}>
    <summary>{scope.title}</summary>
    <section aria-label={scope.title}>
      <p>{scope.description}</p>
      {error&&<p role="alert" className="error">{error}</p>}
      {custody&&<>
        <p role="status">{custody.provider?.state==='no-recorded-key-history'
          ?'No tenant key history is recorded for this workspace.'
          :custody.linked?scope.linked:scope.retained}</p>
        {custody.held&&<p>{scope.held}</p>}
        {custody.provider&&<p>Physical Storage erasure, backup erasure, and full workspace deletion remain unverified.</p>}
        <dl>
          {typeof custody.eventCount==='number'&&<>
            <dt>Audit events</dt><dd>{custody.eventCount>10000?'More than 10,000':custody.eventCount}</dd>
          </>}
          {custody.auditSha256&&<><dt>Audit SHA-256</dt><dd><code>{custody.auditSha256}</code></dd></>}
          {custody.requestSha256&&<><dt>Offboarding request SHA-256</dt><dd><code>{custody.requestSha256}</code></dd></>}
          {custody.inventorySha256&&<><dt>Approved inventory case SHA-256</dt><dd><code>{custody.inventorySha256}</code></dd></>}
          {custody.provider&&<>
            <dt>Native tenant key versions</dt><dd>{custody.provider.versions}</dd>
            <dt>Matched provider receipts</dt><dd>{custody.provider.retiredVersions||custody.provider.matched}</dd>
            <dt>Retired external key versions</dt><dd>{custody.provider.retiredVersions}</dd>
            <dt>Key disposition SHA-256</dt><dd><code>{custody.provider.sha256}</code></dd>
            {custody.provider.receiptSha256&&<><dt>Retirement receipt SHA-256</dt><dd><code>{custody.provider.receiptSha256}</code></dd></>}
          </>}
          {custody.sha256&&<><dt>Review plan SHA-256</dt><dd><code>{custody.sha256}</code></dd></>}
        </dl>
        {!eligible&&custody.linked&&!custody.held&&<p>{scope.blocked}</p>}
        {kind==='workflow'&&!custody.linked&&!custody.current&&!custody.held&&<p>Refresh workspace audit custody before continuing offboarding.</p>}
        {custody.plan&&custody.linked&&eligible&&<p>{!custody.current?scope.stale: custody.approvedAt?scope.approved:scope.review}</p>}
        {actions.map(action=><form key={action+custody.sha256} className="release-form" onSubmit={event=>void submit(event,action)}>
          <p>Enter workspace ID <code>{workspace}</code>.</p>
          <label>{canRecapture&&action==='capture'&&actions.length>1?'Confirm workspace ID for a fresh key retirement plan':scope.confirm}
            <input name="workspace" required maxLength={36} autoComplete="off"/></label>
          {action==='detach'&&<label className="task-check">
            <input type="checkbox" required/> {scope.retention}
          </label>}
          <button type="submit" className="secondary" disabled={busy}>{scope.commands[action]}</button>
        </form>)}
      </>}
      <button type="button" className="secondary" disabled={busy} onClick={()=>void refresh()}>{scope.reload}</button>
    </section>
  </details>
}
