'use client'

import {useCallback,useEffect,useState,type FormEvent} from 'react'
import {verifyAccountCredential} from '../lib/account-credential'
import {db,formatError} from '../lib/data'

type Replay={state:'inactive'|'ready'|'staged'|'applied';side?:'source'|'destination';role?:'owner'|'reviewer';
  tasks?:{id:string;completed:boolean;kind?:'added';title?:string;details?:string;dueAt?:string|null}[];
  records?:{id:string;kind:'channel'|'channel_message'|'room_message'|'room_task';name?:string;body?:string;existingChannelName?:string;
    roomName?:string;parent?:string;priority?:string;labels?:string[];dueAt?:string|null}[];
  packet?:{payload:string;signature:string}}

const replayScopes={
  board:{rpc:'st_v8_residency_rollback_board_replay',title:'Board task rollback replay',artifact:'Board',
    records:'Board task changes',apply:'Apply reviewed task changes'},
  channels:{rpc:'st_v8_residency_rollback_channels',title:'Standard channel rollback replay',artifact:'channel',
    records:'channels and messages',apply:'Apply reviewed channels and messages'},
  rooms:{rpc:'st_v8_residency_rollback_rooms',title:'Standard room rollback replay',artifact:'room message',
    records:'room messages',apply:'Apply reviewed room messages'},
  roomTasks:{rpc:'st_v8_residency_rollback_room_tasks',title:'Room task rollback replay',artifact:'room task',
    records:'room tasks',apply:'Apply reviewed room tasks'},
} as const

export function WorkspaceResidencyBoardReplay({workspace,scope='board'}:{workspace:string;scope?:keyof typeof replayScopes}) {
  const {rpc:rpcName,title,artifact,records,apply}=replayScopes[scope]
  const [replay,setReplay]=useState<Replay>()
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const refresh=useCallback(async (signal?:AbortSignal)=>{
    const query=db!.rpc(rpcName,{p_workspace:workspace})
    const result=await (signal?query.abortSignal(signal):query)
    if(!signal?.aborted&&!result.error)setReplay(result.data as Replay)
  },[workspace,rpcName])

  useEffect(()=>{
    const abort=new AbortController()
    void refresh(abort.signal)
    return ()=>abort.abort()
  },[refresh])

  async function submit(event:FormEvent<HTMLFormElement>,action:'issue'|'stage'|'apply'){
    event.preventDefault()
    if(busy)return
    const form=event.currentTarget
    const fields=new FormData(form)
    const confirmation=String(fields.get('workspace')||'')
    setBusy(true);setError('')
    try {
      if(confirmation!==workspace)throw new Error('Enter the exact workspace ID shown above.')
      let packet
      if(action==='stage'){
        const file=fields.get('batch')
        if(!(file instanceof File)||!file.size||file.size>8388608)throw new Error(`Choose the signed ${artifact} recovery file, up to 8 MB.`)
        try{packet=JSON.parse(await file.text())}catch{throw new Error(`Choose a valid ${artifact} recovery JSON file.`)}
      }
      const assurance=await db!.rpc('st_v7_sensitive_action_status',{p_kind:'room_role'})
      if(assurance.error)throw assurance.error
      if(assurance.data!=='verified'){
        const code=String(fields.get('code')||'')
        if(!code)throw new Error('Enter a current authenticator code.')
        await verifyAccountCredential(code,true)
      }
      const result=await db!.rpc(rpcName,{
        p_workspace:workspace,p_action:action,p_confirmation:confirmation,p_packet:packet,
      })
      if(result.error)throw result.error
      const next=result.data as Replay
      if(action==='issue'&&next.packet){
        const url=URL.createObjectURL(new Blob([JSON.stringify(next.packet)],{type:'application/json'}))
        const link=document.createElement('a')
        link.href=url
        link.download='sectalk-'+artifact.toLowerCase().replaceAll(' ','-')+'-recovery-'+workspace+'.json'
        link.click()
        window.setTimeout(()=>URL.revokeObjectURL(url),1000)
      }else setReplay(next)
      form.reset()
    } catch(cause){setError(formatError(cause,`Could not complete the ${artifact} recovery action.`))}
    finally{setBusy(false)}
  }

  if(!replay?.side)return null
  const action=replay.role==='owner'&&replay.state==='ready'?(replay.side==='destination'?'issue':'stage'):
    replay.role==='reviewer'&&replay.state==='staged'?'apply':undefined
  return <section className="release-section" aria-label={title}>
    <h3>{title}</h3>
    {replay.state==='inactive'&&<p role="status">The signed recovery admission and verified manifest are required.</p>}
    {replay.state==='staged'&&<p role="status">The original independent source reviewer can apply the staged {records}.</p>}
    {replay.state==='applied'&&<p role="status">Reviewed {records} were replayed. Workspace writes remain held.</p>}
    {!!replay.tasks?.length&&<details><summary>Review the staged task changes</summary>
      <ul>{replay.tasks.map(task=><li key={task.id}>
        <code>{task.id}</code> · {task.completed?'Complete':'Incomplete'}
        {task.kind==='added'&&<>
          <p>New task · {task.title}</p>
          {task.details&&<p>{task.details}</p>}
          {task.dueAt&&<p>Due <time dateTime={task.dueAt}>{new Date(task.dueAt).toLocaleString()}</time></p>}
        </>}
      </li>)}</ul>
    </details>}
    {replay.state==='staged'&&!!replay.records?.length&&<details><summary>Review the staged {records}</summary>
      <ul>{replay.records.map(record=><li key={record.kind+record.id}>
        <code>{record.id}</code> · {record.kind==='channel'?'Channel':record.kind==='room_task'?'Task':record.parent?'Thread reply':'Message'}
        {record.existingChannelName&&<span> · Previously migrated channel <strong>{record.existingChannelName}</strong></span>}
        {record.roomName&&<span> · Previously migrated room <strong>{record.roomName}</strong></span>}
        {record.parent&&<span> · Reply to <code>{record.parent}</code></span>}
        <p>{record.name??record.body}</p>
        {record.kind==='room_task'&&<>
          <p>To do · {record.priority} priority</p>
          {!!record.labels?.length&&<p>Labels {record.labels.join(', ')}</p>}
          {record.dueAt&&<p>Due <time dateTime={record.dueAt}>{new Date(record.dueAt).toLocaleString()}</time></p>}
        </>}
      </li>)}</ul>
    </details>}
    {action&&<form className="release-form" onSubmit={event=>void submit(event,action)}>
      <p>Workspace ID <code>{workspace}</code></p>
      <label>{`Confirm ${artifact} recovery workspace ID`}<input name="workspace" required autoComplete="off" disabled={busy}/></label>
      {action==='stage'&&<label>{`Signed ${artifact} recovery file`}<input name="batch" type="file" accept=".json,application/json" required disabled={busy}/></label>}
      <label>Authenticator code if prompted<input name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" disabled={busy}/></label>
      <button className="secondary" type="submit" disabled={busy}>
        {action==='issue'?`Download ${artifact} recovery file`:action==='stage'?`Stage ${artifact} recovery file`:apply}
      </button>
    </form>}
    <button className="secondary" disabled={busy} onClick={()=>void refresh()}>{`Refresh ${artifact} replay`}</button>
    {error&&<p role="alert">{error}</p>}
  </section>
}
