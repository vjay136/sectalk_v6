'use client'

import {useCallback,useEffect,useState,type FormEvent} from 'react'
import {verifyAccountCredential} from '../lib/account-credential'
import {db,formatError} from '../lib/data'

type Rehearsal={status:'inactive'|'ready'|'pending'|'active';role?:'owner'|'reviewer';rehearsal?:string;until?:string}
type Action='request'|'approve'|'end'
type PublishedRoute={status:'inactive'|'ready'|'active'|'unavailable';side?:'source'|'destination';approval?:string}

export function WorkspaceResidencyRouting({workspace}:{workspace:string}) {
  const [state,setState]=useState<Rehearsal|null>(null)
  const [published,setPublished]=useState<PublishedRoute|null>(null)
  const [proof,setProof]=useState('')
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)

  const refresh=useCallback(async (signal?:AbortSignal)=>{
    const parameters={p_workspace:workspace}
    const rehearsal=db!.rpc('st_v8_residency_routing_rehearsal',parameters)
    const active=db!.rpc('st_v8_residency_active_route',parameters)
    const [rehearsalResult,activeResult]=await Promise.all([
      signal?rehearsal.abortSignal(signal):rehearsal,
      signal?active.abortSignal(signal):active,
    ])
    if(signal?.aborted)return
    setState(rehearsalResult.error?null:rehearsalResult.data as Rehearsal)
    setPublished(activeResult.error?null:activeResult.data as PublishedRoute)
  },[workspace])

  useEffect(()=>{
    const controller=new AbortController()
    void refresh(controller.signal)
    const timer=window.setInterval(()=>void refresh(controller.signal),10000)
    return ()=>{controller.abort();window.clearInterval(timer)}
  },[refresh])

  useEffect(()=>{
    if(!state?.until)return
    const controller=new AbortController()
    const timer=window.setTimeout(()=>void refresh(controller.signal),Math.max(100,Date.parse(state.until)-Date.now()+100))
    return ()=>{controller.abort();window.clearTimeout(timer)}
  },[state?.until,refresh])

  async function apply(event:FormEvent<HTMLFormElement>,action:Action){
    event.preventDefault()
    if(busy)return
    const form=event.currentTarget
    const values=new FormData(form)
    setBusy(true);setError('')
    try {
      const {data,error}=await db!.rpc('st_v7_sensitive_action_status',{p_kind:'room_role'})
      if(error)throw error
      if(data!=='verified'){
        const code=String(values.get('code')||'')
        if(!code)throw new Error('Enter a current authenticator code to continue.')
        await verifyAccountCredential(code,true)
      }
      const result=await db!.rpc('st_v8_residency_routing_rehearsal',{
        p_workspace:workspace,p_action:action,p_rehearsal:state?.rehearsal||null,p_confirmation:String(values.get('workspace')||''),
      })
      if(result.error)throw result.error
      form.reset()
      await refresh()
    } catch(cause){setError(formatError(cause,'The routing rehearsal could not be changed.'))}
    finally{setBusy(false)}
  }

  async function applyPublished(event:FormEvent<HTMLFormElement>,action:'issue'|'publish'){
    event.preventDefault()
    if(busy||!published?.approval)return
    const form=event.currentTarget
    const values=new FormData(form)
    setBusy(true);setError('');setProof('')
    try {
      const credential=await db!.rpc('st_v7_sensitive_action_status',{p_kind:'room_role'})
      if(credential.error)throw credential.error
      if(credential.data!=='verified'){
        const code=String(values.get('code')||'')
        if(!code)throw new Error('Enter a current authenticator code to continue.')
        await verifyAccountCredential(code,true)
      }
      let suppliedProof=null
      if(action==='publish'){
        try{suppliedProof=JSON.parse(String(values.get('proof')||''))}
        catch{throw new Error('Paste the complete destination activation proof.')}
      }
      const result=await db!.rpc('st_v8_residency_active_route',{
        p_workspace:workspace,p_action:action,p_approval:published.approval,
        p_confirmation:String(values.get('workspace')||''),p_proof:suppliedProof,
      })
      if(result.error)throw result.error
      if(action==='issue')setProof(JSON.stringify(result.data.proof))
      form.reset()
      await refresh()
    } catch(cause){setError(formatError(cause,'Could not publish the active workspace route.'))}
    finally{setBusy(false)}
  }

  async function openDestination(){
    if(busy)return
    setBusy(true);setError('')
    try {
      const {data:{session}}=await db!.auth.getSession()
      if(!session)throw new Error('Sign in again to open the destination.')
      const result=await fetch('/api/workspaces/residency/route-link?'+new URLSearchParams({workspace}),{
        cache:'no-store',headers:{Authorization:'Bearer '+session.access_token},
      })
      if(!result.ok)throw new Error('The destination link is currently unavailable.')
      const link=document.createElement('a')
      link.href=(await result.json()).url
      link.rel='noreferrer'
      link.click()
    } catch(cause){setError(formatError(cause,'Could not open the destination.'));await refresh()}
    finally{setBusy(false)}
  }

  const publishedAction=published?.status==='ready'?(published.side==='destination'?'issue':'publish'):undefined
  const showRehearsal=state&&state.status!=='inactive'&&published?.status!=='active'&&published?.status!=='unavailable'
  const action:Action|undefined=state?.role==='owner'?(state.status==='ready'?'request':'end'):
    state?.role==='reviewer'&&state.status==='pending'?'approve':undefined
  return <>
  {published&&published.status!=='inactive'&&<section className="release-section" aria-label="Active workspace routing">
    <h3>Active workspace routing</h3>
    {published.status==='active'&&<>
      <p role="status">The destination workspace is active.</p>
      <button className="secondary" disabled={busy} onClick={()=>void openDestination()}>Open the active workspace</button>
      <p>Sign in separately at the destination.</p>
    </>}
    {published.status==='unavailable'&&<p role="status">The approved destination is currently unavailable.</p>}
    {publishedAction&&<form className="release-form" onSubmit={event=>void applyPublished(event,publishedAction)}>
      <p>{publishedAction==='issue'?'Generate a short-lived proof to publish this activation from the source workspace.':
        'Publish the activated destination so current members can open it.'}</p>
      <p>Workspace ID <code>{workspace}</code></p>
      <label>Confirm active route workspace ID<input name="workspace" autoComplete="off" required disabled={busy}/></label>
      <label>Authenticator code if prompted<input name="code" autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]{6}" disabled={busy}/></label>
      {publishedAction==='publish'&&<label>Paste destination activation proof<textarea name="proof" maxLength={2400} required disabled={busy}/></label>}
      <button type="submit" className="secondary" disabled={busy}>{publishedAction==='issue'?'Create destination activation proof':'Publish active workspace route'}</button>
    </form>}
    {proof&&publishedAction==='issue'&&<label>Destination activation proof<textarea value={proof} readOnly rows={4} onFocus={event=>event.currentTarget.select()}/></label>}
    {error&&<p role="alert">{error}</p>}
  </section>}
  {showRehearsal&&<section className="release-section" aria-label="Workspace routing rehearsal">
    <h3>Workspace routing rehearsal</h3>
    {state.status==='ready'&&<p>Request a short rehearsal while source writes are paused.</p>}
    {state.status==='pending'&&<p role="status">Waiting for independent review.</p>}
    {state.status==='active'&&<p role="status">The rehearsal is active until <time dateTime={state.until}>{new Date(state.until!).toLocaleTimeString()}</time>.</p>}
    {state.status==='active'&&state.until&&<button className="secondary" disabled={busy} onClick={()=>void openDestination()}>Open the destination workspace</button>}
    {state.status==='active'&&state.until&&<p>Sign in separately on the destination. Use your browser’s Back button to return.</p>}
    {action&&<form className="release-form" onSubmit={event=>void apply(event,action)}>
      <p>Workspace ID <code>{workspace}</code></p>
      <label>Confirm workspace ID<input name="workspace" autoComplete="off" required disabled={busy}/></label>
      <label>Authenticator code if prompted<input name="code" autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]{6}" disabled={busy}/></label>
      <button type="submit" className="secondary" disabled={busy}>{action==='request'?'Request routing rehearsal':action==='approve'?'Approve routing rehearsal':'End routing rehearsal'}</button>
    </form>}
    {error&&(!published||published.status==='inactive')&&<p role="alert">{error}</p>}
  </section>}
  </>
}
