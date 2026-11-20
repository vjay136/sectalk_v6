'use client'

import {useEffect,useRef,useState} from 'react'
import {db} from '../lib/data'
import {useSensitiveAction} from './sensitive-action'

type TrialPlan='professional'|'business'
type TrialStatus={state:'active'|'used'|'subscribed'|'pending'|'eligible';plan:TrialPlan|null;
  expires_at:string|null;reserved_until:string|null;policy:'optional'|'required'|'unavailable'}
const planNames={professional:'Professional',business:'Business (Team)'}

export function WorkspaceTrial({workspace}:{workspace:string}) {
  const [status,setStatus]=useState<TrialStatus|null>(null)
  const [plan,setPlan]=useState<TrialPlan>('professional')
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [readError,setReadError]=useState('')
  const reads=useRef(0)
  const {authorize,confirmation}=useSensitiveAction()

  useEffect(()=>{
    const controller=new AbortController()
    async function refresh(){
      const read=++reads.current
      try{
        const {data}=await db!.auth.getSession()
        if(!data.session)throw new Error('Sign in to view your workspace trial.')
        const response=await fetch('/api/workspaces/trial?workspace='+workspace,{
          signal:controller.signal,headers:{Authorization:'Bearer '+data.session.access_token},
        })
        if(!response.ok)throw new Error('Could not read your workspace trial status. Try again shortly.')
        const value=await response.json() as TrialStatus
        if(!controller.signal.aborted&&read===reads.current){setStatus(value);setReadError('')}
      }catch(cause){
        if(!controller.signal.aborted&&read===reads.current){
          setReadError(cause instanceof Error?cause.message:'Workspace trial status is unavailable.')
        }
      }
    }
    void refresh()
    const timer=window.setInterval(()=>void refresh(),7000)
    return ()=>{controller.abort();window.clearInterval(timer)}
  },[workspace])

  async function start(){
    if(!status||busy)return
    const chosen=status.state==='pending'?status.plan:plan
    if(!chosen)return
    setBusy(true)
    setError('')
    try{
      const {data}=await db!.auth.getSession()
      if(!data.session)throw new Error('Sign in to start a workspace trial.')
      const response=await fetch('/api/workspaces/trial',{
        method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+data.session.access_token},
        body:JSON.stringify({workspace,plan:chosen}),
      })
      const value=await response.json()
      if(!response.ok)throw new Error(value.error||'The trial request could not be completed.')
      if(value.state==='pending'&&typeof value.url==='string'){window.location.assign(value.url);return}
      reads.current++
      setStatus(previous=>previous&&({...previous,state:value.state,plan:chosen,expires_at:value.expires_at??null}))
    }catch(cause){setError(cause instanceof Error?cause.message:'The trial request could not be completed.')}
    finally{setBusy(false)}
  }

  return <section className="release-section" aria-label="Workspace trial">
    <h2>Workspace trial</h2><p>Try Professional or Business for 14 days. Each workspace can start one trial.</p>
    {confirmation}
    {error&&<p role="alert" className="error">{error}</p>}
    {readError&&<p role="alert" className="error">{readError}</p>}
    {!status&&!readError&&<p role="status">Checking trial availability…</p>}
    {status?.state==='active'&&<p role="status">{status.plan&&planNames[status.plan]} trial is active. Access ends {status.expires_at&&
      <time dateTime={status.expires_at}>{new Date(status.expires_at).toLocaleString()}</time>}.</p>}
    {status?.state==='used'&&<p role="status">This workspace has used its 14-day trial.</p>}
    {status?.state==='subscribed'&&<p role="status">This workspace already has a paid plan.</p>}
    {status?.state==='eligible'&&status.policy==='unavailable'&&<p role="status">Workspace trials are currently unavailable.</p>}
    {status?.state==='eligible'&&status.policy!=='unavailable'&&<div className="release-form">
      <label>Trial plan<select aria-label="Trial plan" value={plan} onChange={event=>setPlan(event.target.value as TrialPlan)}>
        <option value="professional">Professional</option><option value="business">Business (Team)</option>
      </select></label>
      <p>{status.policy==='required'?'Stripe confirms a card. The trial has no automatic charge.':'No card is needed. The trial ends automatically.'}</p>
      <button className="primary" type="button" disabled={busy} onClick={()=>void authorize('billing',start)}>
        {status.policy==='required'?'Confirm a card with Stripe':'Start 14-day trial'}
      </button>
    </div>}
    {status?.state==='pending'&&<div className="release-form">
      <p role="status">Waiting for Stripe to confirm the card for this trial.</p>
      {status.policy==='required'&&<button className="secondary" type="button" disabled={busy} onClick={()=>void authorize('billing',start)}>
        Resume card confirmation</button>}
    </div>}
  </section>
}
