'use client'

import {useEffect,useRef,useState,type FormEvent} from 'react'
import {verifyAccountCredential} from '../lib/account-credential'
import {db,formatError,onReconnect} from '../lib/data'
import {WorkspaceResidencyActivation} from './workspace-residency-activation'
import {WorkspaceResidencyRollback} from './workspace-residency-rollback'

type Phase='inactive'|'ready'|'standby'|'cancelled'|'held'|'restored'|'activated'
type Action='prepare'|'cancel'|'hold'|'restore'
type Handoff={phase:Phase;side?:'source'|'destination';approval?:string;linkCurrent:boolean;proof?:{payload:string;signature:string}}
const phaseText:Record<Exclude<Phase,'inactive'>,string>={
  ready:'The workspace is paired for a guarded write handoff.',
  standby:'Guarded destination writes are on standby.',
  cancelled:'The destination handoff is cancelled. Guarded destination writes remain disabled.',
  held:'Guarded source writes are held beyond the temporary pause.',
  restored:'Source write authority was restored. Any separate workspace restrictions still apply.',
  activated:'Guarded destination writes are active. Any separate workspace restrictions still apply.',
}

export function WorkspaceResidencyWriteHandoff({workspace,onRollbackHeld}:{workspace:string;onRollbackHeld?:()=>void}) {
  const [state,setState]=useState<Handoff>()
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)
  const changing=useRef(false)
  const version=useRef(0)

  useEffect(()=>{
    const abort=new AbortController()
    const refresh=()=>{
      if(changing.current)return
      const attempt=++version.current
      void db!.rpc('st_v8_residency_write_handoff',{p_workspace:workspace}).abortSignal(abort.signal).then(result=>{
        if(abort.signal.aborted||result.error||attempt!==version.current)return
        const next=result.data as Handoff
        setState(previous=>previous?.phase===next.phase&&previous.approval===next.approval?{...next,proof:previous.proof}:next)
      })
    }
    refresh()
    const reconnect=onReconnect(refresh)
    const timer=window.setInterval(refresh,10000)
    return ()=>{abort.abort();reconnect();window.clearInterval(timer)}
  },[workspace])

  async function submit(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    if(changing.current||!state?.approval)return
    const form=event.currentTarget, fields=new FormData(form, (event.nativeEvent as SubmitEvent).submitter)
    const action=fields.get('command') as Action
    changing.current=true;++version.current
    setBusy(true);setError('')
    try {
      const proof=state.side==='source'?JSON.parse(String(fields.get('proof')||'')):null
      if(state.side==='source'&&(typeof proof?.payload!=='string'||typeof proof?.signature!=='string'))
        throw new Error('Paste the exact destination write handoff proof.')
      const assurance=await db!.rpc('st_v7_sensitive_action_status',{p_kind:'room_role'})
      if(assurance.error)throw assurance.error
      if(assurance.data!=='verified'){
        const code=String(fields.get('code')||'')
        if(!code)throw new Error('Enter a current authenticator code.')
        await verifyAccountCredential(code,true)
      }
      const result=await db!.rpc('st_v8_residency_write_handoff',{
        p_workspace:workspace,p_approval:state.approval,p_action:action,p_confirmation:String(fields.get('workspace')||''),p_proof:proof,
      })
      if(result.error)throw result.error
      setState(result.data as Handoff)
      form.reset()
    } catch(cause){setError(formatError(cause,'Could not change the guarded write handoff.'))}
    finally{changing.current=false;setBusy(false)}
  }

  if(!state||state.phase==='inactive')return null
  const source=state.side==='source'
  return <section className="release-section" aria-label="Migration write handoff">
    <h3>Migration write handoff</h3>
    <p role="status">{phaseText[state.phase]}</p>
    {!state.linkCurrent&&state.phase!=='activated'&&<p role="alert">Renew the paired migration credential to continue the handoff or recovery.</p>}
    {state.linkCurrent&&state.phase!=='restored'&&state.phase!=='activated'&&<form className="release-form" onSubmit={event=>void submit(event)}>
      <p>Workspace ID <code>{workspace}</code></p>
      <label>Confirm handoff workspace ID<input name="workspace" autoComplete="off" required disabled={busy}/></label>
      {source&&<label>Paste destination write handoff proof<textarea name="proof" rows={3} maxLength={1800} required disabled={busy}/></label>}
      <label>Authenticator code if prompted<input name="code" autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]{6}" disabled={busy}/></label>
      {source&&state.phase==='ready'&&<button className="secondary" name="command" value="hold" disabled={busy}>Hold guarded source writes</button>}
      {source&&state.phase==='held'&&<button className="secondary" name="command" value="restore" disabled={busy}>Restore guarded source writes</button>}
      {!source&&state.phase==='ready'&&<button className="secondary" name="command" value="prepare" disabled={busy}>Put destination on standby</button>}
      {!source&&state.phase==='standby'&&<>
        <button className="secondary" name="command" value="prepare" disabled={busy}>Renew standby proof</button>
        <button className="secondary" name="command" value="cancel" disabled={busy}>Cancel destination handoff</button>
      </>}
      {!source&&state.phase==='cancelled'&&<button className="secondary" name="command" value="cancel" disabled={busy}>Renew cancellation proof</button>}
    </form>}
    {state.proof&&<label className="release-form">Destination write handoff proof
      <textarea readOnly rows={4} value={JSON.stringify(state.proof)} onFocus={event=>event.currentTarget.select()}/>
      <span>Share this proof with the source owner within five minutes.</span>
    </label>}
    {(state.phase==='standby'||state.phase==='held')&&<WorkspaceResidencyActivation workspace={workspace}
      onActivated={()=>setState(previous=>previous?{...previous,phase:'activated',proof:undefined}:previous)}/>}
    {(state.phase==='held'||state.phase==='activated')&&<WorkspaceResidencyRollback key={workspace+state.phase}
      workspace={workspace} onRollbackHeld={onRollbackHeld}/>}
    {error&&<p role="alert">{error}</p>}
  </section>
}
