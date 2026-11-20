'use client'

import {useCallback,useEffect,useState} from 'react'
import type {ManifestEntry} from '../lib/contact-key-verification'
import {db} from '../lib/data'
import {enrollCurrentDevice} from '../lib/device-identity'
import {groupLocalDevice,rewrapGroupHistory,type GroupEnvelope} from '../lib/group-chat-crypto'
import type {GroupHistoryProof} from '../lib/group-history-proof'
import {useSensitiveAction} from './sensitive-action'

type Target={id:string;state:'trusted'|'managed';created_at:string}
type Preparation=GroupHistoryProof&{original:GroupEnvelope[];recipient:ManifestEntry}

export function GroupHistoryTransfer({actor,group,source}:{actor:string;group:string;source:string}){
  const [opened,setOpened]=useState(false)
  const [targets,setTargets]=useState<Target[]|null>(null)
  const [selected,setSelected]=useState('')
  const [error,setError]=useState('')
  const [notice,setNotice]=useState('')
  const [busy,setBusy]=useState(false)
  const {authorize,confirmation}=useSensitiveAction()
  const read=useCallback(async()=>{
    const result=await db!.rpc('st_v7_group_history_targets',{p_group:group})
    if(result.error)throw new Error('Could not load eligible devices.')
    const list=result.data as Target[]
    setTargets(list)
    setSelected(value=>list.some(item=>item.id===value)?value:list[0]?.id??'')
  },[group])

  useEffect(()=>{if(opened)void read().catch(cause=>setError(cause.message))},[opened,read])

  async function transfer(){
    if(!selected||busy)return
    setBusy(true);setError('');setNotice('')
    try{
      const live=await db!.auth.getSession()
      if(live.data.session?.user.id!==actor)throw new Error('Sign in again on the current browser.')
      const local=await groupLocalDevice(actor,source)
      await enrollCurrentDevice({existingOnly:true})
      const prepared=await db!.rpc('st_v7_prepare_group_history',{p_group:group,p_target:selected})
      if(prepared.error)throw new Error(prepared.error.message)
      if(!prepared.data){await read();setNotice('This browser has the available keys for this group.');return}
      const proof=prepared.data as Preparation
      const message=await rewrapGroupHistory(proof,local,proof.recipient,proof.original)
      const active=await db!.auth.getSession()
      if(active.data.session?.user.id!==actor)return
      const result=await fetch('/api/group-history',{
        method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+active.data.session.access_token},
        body:JSON.stringify({nonce:proof.nonce,...message}),
      })
      if(!result.ok)throw new Error('The approved history transfer could not be completed. Retry on your current browser.')
      setNotice('Group history was shared with the selected approved browser.')
      await read()
    }catch(cause){setError(cause instanceof Error?cause.message:'Could not transfer encrypted group history.')}
    finally{setBusy(false)}
  }

  return <details className="release-create" onToggle={event=>setOpened(event.currentTarget.open)}>
    <summary>Transfer encrypted history</summary>
    <p>Share this browser’s available group history with another approved browser on your account.</p>
    {confirmation}
    {error&&<p className="error" role="alert">{error}</p>}
    {notice&&<p role="status">{notice}</p>}
    {!targets&&!error&&<p role="status">Checking approved browsers…</p>}
    {targets?.length===0&&<p>No approved browsers need keys for this group.</p>}
    {targets&&targets.length>0&&<div className="release-form">
      <label>Approved browser<select aria-label="Approved browser" value={selected} onChange={event=>setSelected(event.target.value)} disabled={busy}>
        {targets.map(device=><option key={device.id} value={device.id}>
          {device.state==='managed'?'Managed':'Trusted'} browser · {new Date(device.created_at).toLocaleDateString()} · {device.id.slice(0,8)}
        </option>)}
      </select></label>
      <button className="secondary" type="button" disabled={!selected||busy} onClick={()=>void authorize('history_transfer',transfer)}>
        Transfer group history
      </button>
    </div>}
  </details>
}
