'use client'

import {useCallback,useEffect,useState,type FormEvent} from 'react'
import {verifyAccountCredential} from '../lib/account-credential'
import {db,formatError} from '../lib/data'

type Admission={admitted:boolean;side?:'source'|'destination';approval?:string}

export function WorkspaceResidencyActivation({workspace,onActivated}:{workspace:string;onActivated:()=>void}) {
  const [admission,setAdmission]=useState<Admission>()
  const [proof,setProof]=useState('')
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')

  const refresh=useCallback(async(signal?:AbortSignal)=>{
    const query=db!.rpc('st_v8_residency_cutover',{p_workspace:workspace})
    const {data,error}=await (signal?query.abortSignal(signal):query)
    if(!signal?.aborted)setAdmission(error?undefined:data as Admission)
  },[workspace])

  useEffect(()=>{
    const abort=new AbortController()
    void refresh(abort.signal)
    return ()=>abort.abort()
  },[refresh])

  const destination=admission?.side==='destination'
  async function apply(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    if(busy||!admission?.approval)return
    const form=event.currentTarget,values=new FormData(form)
    setBusy(true);setError('');setProof('')
    try {
      const supplied=destination?JSON.parse(String(values.get('proof')||'')):null
      if(destination&&(typeof supplied?.payload!=='string'||typeof supplied?.signature!=='string'))
        throw new Error('Paste the exact source activation proof.')
      const assurance=await db!.rpc('st_v7_sensitive_action_status',{p_kind:'room_role'})
      if(assurance.error)throw assurance.error
      if(assurance.data!=='verified'){
        const code=String(values.get('code')||'')
        if(!code)throw new Error('Enter a current authenticator code.')
        await verifyAccountCredential(code,true)
      }
      const result=await db!.rpc('st_v8_residency_cutover',{
        p_workspace:workspace,p_action:destination?'activate':'issue',p_approval:admission.approval,
        p_confirmation:String(values.get('workspace')||''),p_proof:supplied,
      })
      if(result.error)throw result.error
      form.reset()
      if(destination)onActivated()
      else setProof(JSON.stringify(result.data.proof))
    } catch(cause){setError(formatError(cause,'The approved write activation is unavailable.'))}
    finally{setBusy(false)}
  }

  return <section className="release-section" aria-label="Guarded destination activation">
    <h4>Guarded destination activation</h4>
    {admission?.admitted===false&&<p>Waiting for an approved transfer and recovery plan on this installation.</p>}
    <button type="button" className="secondary" disabled={busy} onClick={()=>void refresh()}>Refresh activation approval</button>
    {admission?.admitted&&<form className="release-form" onSubmit={event=>void apply(event)}>
      <p>{destination?'Activating ends standby. Further rollback requires independent reconciliation of destination changes.':
        'Issue a short-lived proof after the current independent comparison matches every approved record.'}</p>
      <label>Confirm activation workspace ID<input name="workspace" autoComplete="off" required disabled={busy}/></label>
      {destination&&<label>Paste source activation proof<textarea name="proof" rows={3} maxLength={2400} required disabled={busy}/></label>}
      <label>Authenticator code if prompted<input name="code" autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]{6}" disabled={busy}/></label>
      <button type="submit" className="secondary" disabled={busy}>{destination?'Activate guarded destination writes':'Create source activation proof'}</button>
    </form>}
    {proof&&<label className="release-form">Source activation proof<textarea readOnly rows={4} value={proof}
      onFocus={event=>event.currentTarget.select()}/><span>Share this proof with the destination owner within five minutes.</span></label>}
    {error&&<p role="alert">{error}</p>}
  </section>
}
