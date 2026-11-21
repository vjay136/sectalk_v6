'use client'

import {useEffect,useState,type FormEvent} from 'react'
import {db,formatError} from '../lib/data'

type RoomTasks={id:string;name:string;taskCount:number;importedAt:string|null}
type ApprovedRoomTasks={approval:string;manifestSha256:string;rooms:RoomTasks[]}

export function WorkspaceResidencyRoomTasks({workspace,revision,disabled,authorize,onRestored}:{
  workspace:string;revision:number;disabled:boolean;authorize:(perform:()=>Promise<void>)=>Promise<void>;onRestored?:()=>void
}) {
  const [approved,setApproved]=useState<ApprovedRoomTasks|null>(null)
  const [room,setRoom]=useState('')
  const [confirmation,setConfirmation]=useState('')
  const [busy,setBusy]=useState(false)
  const [notice,setNotice]=useState('')
  const [error,setError]=useState('')

  useEffect(()=>{
    const request=new AbortController()
    void db!.rpc('st_v8_residency_room_task_import',{p_workspace:workspace}).abortSignal(request.signal).then(result=>{
      if(!request.signal.aborted) setApproved(result.error?null:result.data as ApprovedRoomTasks|null)
    })
    return()=>request.abort()
  },[revision,workspace])

  const pending=approved?.rooms.filter(item=>!item.importedAt)??[]
  const selected=pending.find(item=>item.id===room)

  function restore(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if(busy||disabled||!approved||!selected||confirmation!==workspace)return
    void authorize(async()=>{
      setBusy(true);setError('');setNotice('')
      try{
        const result=await db!.rpc('st_v8_residency_room_task_import',{
          p_workspace:workspace,p_approval:approved.approval,p_room:selected.id,p_confirmation:confirmation,
        })
        if(result.error)throw result.error
        const restored=result.data as {room:string;name:string;taskCount:number;importedAt:string}
        setApproved(current=>current && {...current,rooms:current.rooms.map(item=>
          item.id===restored.room?{...item,importedAt:restored.importedAt}:item)})
        setRoom('');setConfirmation('')
        setNotice(`${restored.taskCount} approved room ${restored.taskCount===1?'task':'tasks'} restored to ${restored.name}.`)
        onRestored?.()
      }catch(cause){setError(formatError(cause,'Could not restore the approved room tasks.'))}
      finally{setBusy(false)}
    })
  }

  if(!approved?.rooms.length)return null
  return <section aria-label="Approved room task restore">
    <h4>Approved room task restore</h4>
    <p>Restore approved tasks to an imported private room. SecTalk records your account as the importer. Reassign tasks in the room if needed.</p>
    <p>Approved manifest <code>{approved.manifestSha256}</code></p>
    <ul>{approved.rooms.map(item=><li key={item.id}>
      {item.name} · {item.taskCount} {item.taskCount===1?'task':'tasks'} {item.importedAt?'restored':'available'}
    </li>)}</ul>
    {!!pending.length&&<form className="release-form" onSubmit={restore}>
      <label>Imported room<select value={room} onChange={event=>setRoom(event.target.value)} required disabled={disabled||busy}>
        <option value="">Select a room</option>
        {pending.map(item=><option key={item.id} value={item.id}>{item.name}</option>)}
      </select></label>
      <label>Confirm destination workspace for task restore<input value={confirmation} autoComplete="off"
        onChange={event=>setConfirmation(event.target.value)} required disabled={disabled||busy}/></label>
      <button className="secondary" disabled={disabled||busy||!selected||confirmation!==workspace}>Restore approved room tasks</button>
    </form>}
    {notice&&<p role="status">{notice} Open Tasks in the room to view them.</p>}
    {error&&<p role="alert">{error}</p>}
  </section>
}
