'use client'

import {useEffect,useState} from 'react'
import {db,onReconnect} from '../lib/data'

type PaymentState={mode:'active'|'grace'|'read_only';grace_until?:string}

export function WorkspacePaymentStatus({id,owner}:{id:string;owner:boolean}) {
  const [state,setState]=useState<PaymentState|null>(null)
  useEffect(()=>{
    if(!db)return
    const client=db
    const abort=new AbortController()
    let pending=false
    const refresh=()=>{
      if(pending||abort.signal.aborted)return
      pending=true
      void (async()=>{
        try {
          const result=await client.rpc('st_v7_workspace_payment_state',{p_workspace:id}).abortSignal(abort.signal)
          if(!abort.signal.aborted&&!result.error)setState(result.data as PaymentState)
        } finally {pending=false}
      })()
    }
    refresh()
    const reconnect=onReconnect(refresh)
    const timer=window.setInterval(()=>{if(document.visibilityState==='visible')refresh()},12000)
    return()=>{abort.abort();reconnect();window.clearInterval(timer)}
  },[id])
  if(state?.mode==='read_only')return <aside className="panel release-panel" aria-label="Workspace billing status">
    <strong>Workspace is read-only</strong>
    <p>Billing requires attention. You can still view your data and use the exports you have permission to access.</p>
    {owner&&<a href="/?billing=renewal">Open Billing</a>}
  </aside>
  if(state?.mode==='grace'&&owner&&state.grace_until)return <aside className="panel release-panel" aria-label="Workspace billing status">
    <strong>Workspace payment grace period</strong>
    <p>Workspace writes remain available until <time dateTime={state.grace_until}>{new Date(state.grace_until).toLocaleString()}</time>.</p>
    <a href="/?billing=renewal">Open Billing</a>
  </aside>
  return null
}
