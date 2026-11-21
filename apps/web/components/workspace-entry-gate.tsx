'use client'

import { useCallback, useEffect, useState } from 'react'
import { db } from '../lib/data'
import { StaffMfa } from './staff-mfa'
import { WorkspaceSsoSignIn } from './workspace-sso-sign-in'

type Recovery = { access: 'none' | 'mfa' | 'verified'; required?: boolean }

export function WorkspaceEntryGate({workspace,owner,onRecovered}:{
  workspace:string; owner:boolean; onRecovered:()=>Promise<void>
}) {
  const [recover,setRecover]=useState(false)
  const [policy,setPolicy]=useState<Recovery>()
  const [working,setWorking]=useState(false)
  const [error,setError]=useState('')
  const read=useCallback(async()=>{
    const result=await db!.rpc('st_v8_workspace_entry_policy',{p_workspace:workspace})
    if(result.error)setError('Could not check owner recovery access.')
    else{
      setError('')
      setPolicy(result.data as Recovery)
    }
  },[workspace])
  useEffect(()=>{if(recover)void read()},[read,recover])

  async function restore() {
    setWorking(true);setError('')
    try{
      const result=await db!.rpc('st_v8_workspace_entry_policy',{p_workspace:workspace,p_require:false})
      if(result.error)throw result.error
      const next=result.data as Recovery
      setPolicy(next)
      if(next.access==='verified'&&next.required===false)await onRecovered()
    }catch{
      setError('Could not restore standard workspace sign-in.')
    }finally{setWorking(false)}
  }

  return <section className="panel release-panel" aria-label="Workspace sign-in required">
    <h2>Workspace sign-in required</h2>
    <p>Sign in through your organization to open this workspace.</p>
    <WorkspaceSsoSignIn workspace={workspace}/>
    {owner&&<details className="release-create" onToggle={event=>setRecover(event.currentTarget.open)}>
      <summary>Owner recovery</summary>
      {recover&&!policy&&!error&&<p role="status">Checking owner recovery access…</p>}
      {recover&&policy?.access==='mfa'&&<StaffMfa refresh={read} heading="Verify workspace ownership"
        explanation="Use your authenticator to restore standard workspace sign-in."/>}
      {recover&&policy?.access==='verified'&&<button type="button" className="secondary" disabled={working}
        onClick={()=>void restore()}>Restore standard workspace sign-in</button>}
      {recover&&policy?.access==='none'&&<p>Workspace owner recovery is unavailable.</p>}
      {recover&&error&&<p role="alert">{error}</p>}
    </details>}
  </section>
}
