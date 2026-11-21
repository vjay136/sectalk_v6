'use client'

import {useCallback,useEffect,useState,type FormEvent} from 'react'
import {db,formatError} from '../lib/data'
import {StaffMfa} from './staff-mfa'

type Claim={id:string;workspace:string;name:string;manifestSha256:string}
type Claims={access:'mfa'|'verified';claims:Claim[]}

export function WorkspaceResidencyClaim({onClaimed}:{onClaimed:(workspace:string)=>Promise<void>}) {
  const [state,setState]=useState<Claims>()
  const [selected,setSelected]=useState('')
  const [confirmation,setConfirmation]=useState('')
  const [verify,setVerify]=useState(false)
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const load=useCallback(async(signal?:AbortSignal)=>{
    const request=db!.rpc('st_v8_residency_workspace_claim')
    const result=await (signal?request.abortSignal(signal):request)
    if(!signal?.aborted)setState(result.error?undefined:result.data)
  },[])

  useEffect(()=>{
    const controller=new AbortController()
    void load(controller.signal)
    return ()=>controller.abort()
  },[load])

  const claim=state?.claims.find(item=>item.id===selected)??state?.claims[0]
  if(!state||!claim)return null

  async function accept(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if(!claim||confirmation!==claim.workspace||busy)return
    if(state?.access!=='verified'){setVerify(true);return}
    setBusy(true);setError('')
    try {
      const {data,error}=await db!.rpc('st_v8_residency_workspace_claim',{
        p_claim:claim.id,p_confirmation:confirmation,
      })
      if(error)throw error
      setConfirmation('')
      await onClaimed(data.workspace)
      await load()
    }catch(cause){
      setError(formatError(cause,'Could not claim the approved destination workspace.'))
      await load()
    }finally{setBusy(false)}
  }

  return <section className="panel release-panel" aria-label="Approved destination workspace">
    <h2>Approved destination workspace</h2>
    {state.claims.length>1&&<label>Workspace to claim<select value={claim.id} disabled={busy||verify}
      onChange={event=>{setSelected(event.target.value);setConfirmation('');setError('')}}>
      {state.claims.map(item=><option key={item.id} value={item.id}>{item.name}</option>)}
    </select></label>}
    <p>{claim.name} · <code>{claim.workspace}</code></p>
    <p>Approved manifest <code>{claim.manifestSha256}</code></p>
    {verify&&state?.access!=='verified'?<StaffMfa heading="Verify destination owner"
      explanation="Confirm a fresh authenticator code to claim this workspace."
      refresh={async()=>{await load();setVerify(false)}}/>:
      <form className="release-form" onSubmit={accept}>
        <label>Confirm approved workspace ID<input value={confirmation} autoComplete="off" required disabled={busy}
          onChange={event=>setConfirmation(event.target.value)}/></label>
        <button className="primary" disabled={busy||confirmation!==claim.workspace}>Claim destination workspace</button>
      </form>}
    {error&&<p role="alert">{error}</p>}
  </section>
}
