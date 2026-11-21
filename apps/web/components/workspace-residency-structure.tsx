'use client'

import { useEffect,useState,type FormEvent } from 'react'
import { db,formatError } from '../lib/data'

type Structure={id:string;name:string;importedAt:string|null}
type StructureImport={approval:string;manifestSha256:string;channels?:Structure[];rooms?:Structure[]}

export function WorkspaceResidencyStructure({workspace,kind,disabled,authorize,onImported}:{workspace:string;kind:'channel'|'room';disabled:boolean;
  authorize:(perform:()=>Promise<void>)=>Promise<void>;onImported?:()=>void}) {
  const [queue,setQueue]=useState<StructureImport|null>(null)
  const [selected,setSelected]=useState('')
  const [confirmation,setConfirmation]=useState('')
  const [notice,setNotice]=useState('')
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)
  const operation=kind==='channel'?'st_v8_residency_channel_import':'st_v8_residency_room_import'
  const group=kind==='channel'?'channels':'rooms'
  const heading=`Approved workspace ${kind} import`
  const prefix=kind==='channel'?'#':''

  useEffect(()=>{
    const controller=new AbortController()
    void db!.rpc(operation,{p_workspace:workspace}).abortSignal(controller.signal).then(result=>{
      if(!controller.signal.aborted && !result.error)setQueue(result.data as StructureImport|null)
    })
    return()=>controller.abort()
  },[operation,workspace])

  function publish(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if(busy||disabled||!queue||!selected||confirmation!==workspace)return
    void authorize(async()=>{
      setBusy(true);setError('');setNotice('')
      try {
        const result=await db!.rpc(operation,{
          p_workspace:workspace,p_approval:queue.approval,[`p_${kind}`]:selected,p_confirmation:confirmation,
        })
        if(result.error)throw result.error
        const published=result.data as {channel?:string;room?:string;name:string;importedAt:string}
        setQueue(current=>current && {...current,[group]:current[group]?.map(item=>
          item.id===published[kind] ? {...item,importedAt:published.importedAt} : item)})
        setNotice(`${kind==='channel'?'Channel':'Room'} ${prefix}${published.name} imported. Open ${kind==='channel'?'Channels':'Rooms'} to view it.`)
        setSelected('');setConfirmation('')
        onImported?.()
      } catch(cause) {setError(formatError(cause,`Could not import the approved ${kind}.`))}
      finally {setBusy(false)}
    })
  }

  const items=queue?.[group]
  if(!queue||!items?.length)return null
  const pending=items.filter(item=>!item.importedAt)
  return <section aria-label={heading}>
    <h4>{heading}</h4>
    <p>{kind==='room' ? 'Create a private standard room with the approved name and identifier. It starts with Confidential classification and you as its only member.'
      : 'Import the approved channel name and identifier into the destination workspace.'}</p>
    <p>Approved manifest <code>{queue.manifestSha256}</code></p>
    <ul>{items.map(item=><li key={item.id}>{prefix}{item.name} · {item.importedAt ? 'Imported' : 'Available for import'}</li>)}</ul>
    {pending.length>0&&<form className="release-form" onSubmit={publish}>
      <label>Approved standard {kind}<select value={selected} onChange={event=>setSelected(event.target.value)} required disabled={disabled||busy}>
        <option value="">Select a {kind}</option>
        {pending.map(item=><option key={item.id} value={item.id}>{prefix}{item.name}</option>)}
      </select></label>
      <label>Confirm destination workspace for {kind} import<input value={confirmation} autoComplete="off"
        onChange={event=>setConfirmation(event.target.value)} required disabled={disabled||busy}/></label>
      <button className="secondary" disabled={disabled||busy||!selected||confirmation!==workspace}>Import approved {kind}</button>
    </form>}
    {notice&&<p role="status">{notice}</p>}
    {error&&<p role="alert">{error}</p>}
  </section>
}
