'use client'

import {useCallback,useEffect,useState,type FormEvent} from 'react'
import {db,formatError} from '../lib/data'
import {WorkspaceResidencyReconciliation} from './workspace-residency-reconciliation'
import {WorkspaceResidencyStructure} from './workspace-residency-structure'
import {WorkspaceResidencyRoomTasks} from './workspace-residency-room-tasks'
import {WorkspaceResidencySourcePause} from './workspace-residency-source-pause'

type Cell={id:string;region:'us'|'eu'|'apac';label:string;environment:'deployment'|'fixture'}
type Placement={id:string;region:Cell['region'];label:string;requestedAt:string;state:keyof typeof placementStates}
type Status={eligible:boolean;request:Placement|null;cells:Cell[]}
type TaskImport={approval:string;manifestSha256:string;taskCount:number;importedAt:string|null}
const regions={us:'United States',eu:'Europe',apac:'Asia Pacific'}
const placementStates={
  pending_verification:'Target verification pending',
  independent_review_required:'Independent review pending',
  fixture_target_verified:'Synthetic target verified',
  provider_target_verified:'Provider and dedicated target configuration verified',
  needs_verification:'Target needs fresh verification',
  unavailable:'Target is no longer authorized',
  paused:'Enterprise eligibility ended',
}

export function WorkspaceResidency({workspace,disabled,authorize}:{
  workspace:string;disabled:boolean;authorize:(perform:()=>Promise<void>)=>Promise<void>
}) {
  const [state,setState]=useState<Status>()
  const [target,setTarget]=useState('')
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [taskImport,setTaskImport]=useState<TaskImport|null>(null)
  const [roomsRevision,setRoomsRevision]=useState(0)
  const [confirmation,setConfirmation]=useState('')
  const [importError,setImportError]=useState('')
  const load=useCallback(async(signal?:AbortSignal)=>{
    const request=db!.rpc('st_v8_workspace_residency',{p_workspace:workspace})
    const result=await (signal?request.abortSignal(signal):request)
    if(signal?.aborted)return
    if(result.error){setState(undefined);setError(formatError(result.error,'Could not check residency targets.'))}
    else {setState(result.data);setError('')}
  },[workspace])

  useEffect(()=>{
    const controller=new AbortController()
    void load(controller.signal)
    void db!.rpc('st_v8_residency_task_import',{p_workspace:workspace}).abortSignal(controller.signal).then(({data,error})=>{
      if(!controller.signal.aborted&&!error)setTaskImport(data)
    })
    return ()=>controller.abort()
  },[load,workspace])

  function importTasks(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if(!taskImport||confirmation!==workspace)return
    void authorize(async()=>{
      setBusy(true);setImportError('')
      try {
        const {data,error}=await db!.rpc('st_v8_residency_task_import',{
          p_workspace:workspace,p_approval:taskImport.approval,p_confirmation:confirmation,
        })
        if(error)throw error
        setTaskImport(data)
        setConfirmation('')
      } catch(cause) {setImportError(formatError(cause,'Could not import the approved workspace tasks.'))}
      finally {setBusy(false)}
    })
  }

  function change(cell:string|null,event?:FormEvent<HTMLFormElement>) {
    event?.preventDefault()
    void authorize(async()=>{
      setBusy(true);setError('')
      try {
        const result=await db!.rpc('st_v8_workspace_residency_change',{p_workspace:workspace,p_cell:cell})
        if(result.error)throw result.error
        setTarget('')
        await load()
      } catch(cause) {setError(formatError(cause,'Could not update residency selection.'))}
      finally {setBusy(false)}
    })
  }

  return <section aria-label="Enterprise data residency" className="release-section">
    <h3>Enterprise data residency</h3>
    <p>Dedicated workspace placement is unconfirmed. The current deployment continues to serve this workspace.</p>
    {!state&&!error&&<p role="status">Checking dedicated targets…</p>}
    {error&&<p role="alert">{error}</p>}
    {state&&!state.eligible&&<p>Dedicated target selection is available with an Enterprise entitlement.</p>}
    {state?.request&&<>
      <p>{state.request.label} · {regions[state.request.region]}</p>
      <p role="status">{placementStates[state.request.state]}</p>
      <p>Request reference <code>{state.request.id}</code></p>
      <p>A confirmed placement also requires a verified migration and traffic cutover.</p>
      <WorkspaceResidencySourcePause key={state.request.id} workspace={workspace} request={state.request.id}
        verified={state.request.state==='fixture_target_verified'||state.request.state==='provider_target_verified'}
        disabled={busy||disabled} authorize={authorize}/>
      <button type="button" className="secondary" disabled={busy||disabled} onClick={()=>change(null)}>Withdraw residency request</button>
      <button type="button" className="secondary" disabled={busy||disabled} onClick={()=>void load()}>Refresh placement status</button>
    </>}
    {state?.eligible&&!state.request&&(state.cells.length
      ?<form className="release-form" onSubmit={event=>change(target,event)}>
        <label>Authorized residency target<select aria-label="Authorized residency target" required value={target}
          onChange={event=>setTarget(event.target.value)} disabled={busy||disabled}>
          <option value="">Choose a dedicated target</option>
          {state.cells.map(cell=><option key={cell.id} value={cell.id}>
            {regions[cell.region]} · {cell.label}{cell.environment==='fixture'?' (synthetic fixture)':''}
          </option>)}
        </select></label>
        <button className="secondary" disabled={!target||busy||disabled}>Request dedicated placement</button>
      </form>
      :<p>No dedicated target is authorized for this workspace.</p>)}
    {!!taskImport?.taskCount&&<section aria-label="Approved workspace task import">
      <h4>Approved workspace task import</h4>
      <p>Approved manifest <code>{taskImport.manifestSha256}</code></p>
      {taskImport.importedAt?<p role="status">{taskImport.taskCount} workspace tasks imported. Open Board to view them.</p>:
        <form className="release-form" onSubmit={importTasks}>
          <p>{taskImport.taskCount} approved tasks are ready. They will record your account as the importer.</p>
          <label>Confirm destination workspace ID<input autoComplete="off" value={confirmation}
            onChange={event=>setConfirmation(event.target.value)} disabled={disabled||busy} required/></label>
          <button className="secondary" disabled={disabled||busy||confirmation!==workspace}>Import approved tasks</button>
        </form>}
      {importError&&<p role="alert">{importError}</p>}
    </section>}
    <WorkspaceResidencyStructure key={workspace+'-channel'} workspace={workspace} kind="channel" disabled={disabled} authorize={authorize}/>
    <WorkspaceResidencyStructure key={workspace+'-room'} workspace={workspace} kind="room" disabled={disabled} authorize={authorize}
      onImported={()=>setRoomsRevision(value=>value+1)}/>
    <WorkspaceResidencyRoomTasks key={workspace+'-room-tasks'} workspace={workspace} revision={roomsRevision}
      disabled={disabled} authorize={authorize} onRestored={()=>setRoomsRevision(value=>value+1)}/>
    {taskImport&&<WorkspaceResidencyReconciliation key={`${taskImport.approval}:${taskImport.importedAt}:${roomsRevision}`} workspace={workspace} approval={taskImport.approval}
      disabled={disabled} authorize={authorize}/>}
  </section>
}
