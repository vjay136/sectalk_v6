'use client'

import {useCallback,useEffect,useState,type FormEvent} from 'react'
import {db,formatError} from '../lib/data'

type PauseState={paused:boolean;until:string|null}

export function WorkspaceResidencySourcePause({workspace,request,verified,disabled,authorize}:{workspace:string;request:string;
  verified:boolean;disabled?:boolean;authorize:(action:()=>Promise<void>)=>void|Promise<void>}) {
  const [state,setState]=useState<PauseState|null>(null)
  const [confirmation,setConfirmation]=useState('')
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)
  const load=useCallback(async(signal?:AbortSignal)=>{
    const pending=db!.rpc('st_v8_residency_source_pause',{p_workspace:workspace,p_request:request})
    const result=await (signal?pending.abortSignal(signal):pending)
    if(signal?.aborted)return
    if(result.error)setError(formatError(result.error,'Could not check the source write pause.'))
    else {setState(result.data as PauseState);setError('')}
  },[workspace,request])

  useEffect(()=>{
    const abort=new AbortController()
    void load(abort.signal)
    return ()=>abort.abort()
  },[load])

  useEffect(()=>{
    if(!state?.until)return
    const abort=new AbortController()
    const timer=window.setTimeout(()=>void load(abort.signal),Math.max(100,Date.parse(state.until)-Date.now()+200))
    return ()=>{window.clearTimeout(timer);abort.abort()}
  },[state?.until,load])

  function change(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if(!state||confirmation!==workspace||(!state.paused&&!verified))return
    void authorize(async()=>{
      setBusy(true)
      setError('')
      try {
        const result=await db!.rpc('st_v8_residency_source_pause',{
          p_workspace:workspace,p_request:request,p_action:state.paused?'resume':'pause',p_confirmation:confirmation,
        })
        if(result.error)throw result.error
        setState(result.data as PauseState)
        setConfirmation('')
      } catch(cause) {
        setError(formatError(cause,'The source write pause could not be changed.'))
      } finally {
        setBusy(false)
      }
    })
  }

  if(!verified&&!state?.paused)return null
  return <section className="release-section" aria-label="Source workspace writes">
    <h4>Source workspace writes</h4>
    <p>Pause messages, uploads, tasks, and other guarded writes while you verify the destination. Reads and safety actions remain available.</p>
    {state?.until&&<p role="status">Workspace writes are paused until <time dateTime={state.until}>{new Date(state.until).toLocaleString()}</time>.</p>}
    {state&&!state.paused&&<p role="status">The temporary migration pause is inactive.</p>}
    <form className="release-form" onSubmit={change}>
      <label>Confirm source workspace ID<input autoComplete="off" value={confirmation} onChange={event=>setConfirmation(event.target.value)}
        disabled={disabled||busy||!state} required/></label>
      <button type="submit" className="secondary" disabled={disabled||busy||!state||confirmation!==workspace}>
        {state?.paused?'Resume workspace writes':'Pause workspace writes for 30 minutes'}
      </button>
    </form>
    {error&&<p role="alert">{error}</p>}
  </section>
}
