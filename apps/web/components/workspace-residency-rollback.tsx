'use client'

import {useEffect,useState,type FormEvent} from 'react'
import {verifyAccountCredential} from '../lib/account-credential'
import {db,formatError} from '../lib/data'
import {WorkspaceResidencyRollbackManifest} from './workspace-residency-rollback-manifest'

type Rollback={state:'inactive'|'ready'|'held';side?:'source'|'destination';approval?:string}

export function WorkspaceResidencyRollback({workspace,onRollbackHeld}:{workspace:string;onRollbackHeld?:()=>void}) {
  const [state,setState]=useState<Rollback>()
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)

  useEffect(()=>{
    const controller=new AbortController()
    void db!.rpc('st_v8_residency_rollback_hold',{p_workspace:workspace}).abortSignal(controller.signal).then(result=>{
      if(!controller.signal.aborted&&!result.error)setState(result.data as Rollback)
    })
    return ()=>controller.abort()
  },[workspace])

  async function hold(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    if(state?.state!=='ready'||!state.approval||busy)return
    const form=event.currentTarget
    const fields=new FormData(form)
    const confirmation=String(fields.get('workspace')||'')
    setBusy(true);setError('')
    try {
      if(confirmation!==workspace)throw new Error('Enter the exact workspace ID shown above.')
      const assurance=await db!.rpc('st_v7_sensitive_action_status',{p_kind:'room_role'})
      if(assurance.error)throw assurance.error
      if(assurance.data!=='verified'){
        const code=String(fields.get('code')||'')
        if(!code)throw new Error('Enter a current authenticator code.')
        await verifyAccountCredential(code,true)
      }
      const result=await db!.rpc('st_v8_residency_rollback_hold',{
        p_workspace:workspace,p_action:state.side==='destination'?'hold_destination':'suspend_source_route',
        p_approval:state.approval,p_confirmation:confirmation,
      })
      if(result.error)throw result.error
      setState(result.data as Rollback)
      onRollbackHeld?.()
    } catch(cause){setError(formatError(cause,'Could not prepare the workspace for rollback review.'))}
    finally{setBusy(false)}
  }

  if(!state||state.state==='inactive')return null
  const destination=state.side==='destination'
  return <section className="release-section" aria-label="Residency rollback preparation">
    <h4>Residency rollback preparation</h4>
    {state.state==='held'?<p role="status">{destination?
      'Guarded destination writes are held for rollback review.':
      'Member routing is suspended. Guarded source writes remain held.'}</p>:
      <form className="release-form" onSubmit={event=>void hold(event)}>
        <p>{destination?'Hold guarded destination writes while reviewers reconcile changes made since activation.':
          'Suspend the member link while reviewers reconcile the destination. Guarded source writes remain held.'}</p>
        <p>Workspace ID <code>{workspace}</code></p>
        <label>Confirm rollback workspace ID<input name="workspace" autoComplete="off" required disabled={busy}/></label>
        <label>Authenticator code if prompted<input name="code" autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]{6}" disabled={busy}/></label>
        <button type="submit" className="secondary" disabled={busy}>{destination?'Hold guarded destination writes':'Suspend destination member link'}</button>
      </form>}
    {state.state==='held'&&<WorkspaceResidencyRollbackManifest workspace={workspace}/>}
    {error&&<p role="alert">{error}</p>}
  </section>
}
