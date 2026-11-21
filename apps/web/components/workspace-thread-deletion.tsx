'use client'

import {useCallback,useEffect,useRef,useState,type FormEvent} from 'react'
import {db,formatError} from '../lib/data'

type Thread={id:string;room:string;name:string;copied:boolean;messageCount:number}
type Plan={plan:string;room:string;root:string;sha256:string;messageCount:number;approvedAt:string|null;deletedAt:string|null;
  manifest:{id:string;parent:string|null;sha256:string;sourceSha256:string}[]}
type Status={held:boolean;threads:Thread[];plans:Plan[]}
type Action='copy'|'capture'|'approve'|'delete'

export function WorkspaceThreadDeletion({workspace,role}:{workspace:string;role:'owner'|'reviewer'}) {
  const [open,setOpen]=useState(false)
  const [status,setStatus]=useState<Status>()
  const [selected,setSelected]=useState('')
  const [busy,setBusy]=useState(false)
  const [notice,setNotice]=useState('')
  const [error,setError]=useState('')
  const [loadError,setLoadError]=useState('')
  const latest=useRef(0)

  const load=useCallback(async()=>{
    const request=++latest.current
    const result=await db!.rpc('st_v8_offboarding_room_thread_status',{p_workspace:workspace})
    if(request!==latest.current) return
    if(result.error) {
      setStatus(undefined)
      setLoadError(formatError(result.error,'The room thread status could not be loaded.'))
    } else {
      setStatus(result.data)
      setLoadError('')
    }
  },[workspace])
  useEffect(()=>{
    if(!open) return
    void load()
    const timer=window.setInterval(()=>{if(document.visibilityState==='visible') void load()},12000)
    return ()=>{++latest.current;window.clearInterval(timer)}
  },[load,open])

  async function submit(event:FormEvent<HTMLFormElement>,action:Action,room:string,root:string,plan?:Plan) {
    event.preventDefault()
    if(busy) return
    const form=event.currentTarget
    const values=new FormData(form)
    if(action==='delete'&&String(values.get('root')).trim()!==root) {
      setError('Enter the exact root message ID to confirm thread deletion.')
      return
    }
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const args={p_workspace:workspace,p_room:room,p_root:root,p_confirmation:String(values.get('workspace')).trim()}
      const result=action==='copy'?await db!.rpc('st_v8_offboarding_room_thread_copy',args)
        :await db!.rpc('st_v8_offboarding_room_thread_delete',{...args,p_action:action,
          ...(plan?{p_plan:plan.plan,p_sha256:plan.sha256}:{})})
      if(result.error) throw result.error
      if(action==='copy') {
        const url=URL.createObjectURL(new Blob([JSON.stringify(result.data)],{type:'application/json'}))
        const link=document.createElement('a')
        link.href=url
        link.download='sectalk-approved-room-thread-'+root+'.json'
        link.click()
        window.setTimeout(()=>URL.revokeObjectURL(url),1000)
      }
      setNotice({copy:'Approved room thread copy downloaded.',capture:'Room thread prepared for independent review.',
        approve:'Exact room thread deletion plan approved.',delete:'The complete thread and its search entries were permanently deleted.'}[action])
      form.reset()
    } catch(cause) {
      setError(formatError(cause,'The room thread offboarding action could not be completed.'))
    } finally {
      await load()
      setBusy(false)
    }
  }

  const thread=status?.threads.find(item=>item.id===selected)
  return <details className="release-create" onToggle={event=>setOpen(event.currentTarget.open)}>
    <summary>Permanent room thread deletion</summary>
    <section aria-label="Permanent room thread deletion">
      <p>Review an approved root and all of its replies together. Eligible threads have 2 to 16 messages in a standard public room.</p>
      {status?.held&&<p>Active preservation holds block thread deletion.</p>}
      {(error||loadError)&&<p role="alert" className="error">{error||loadError}</p>}
      {notice&&<p role="status">{notice}</p>}
      {status&&role==='owner'&&status.threads.length===0&&<p>No eligible approved room threads found.</p>}
      {status&&role==='owner'&&status.threads.length>0&&<>
        <label>Approved room thread<select aria-label="Approved room thread" value={thread?.id??''}
          onChange={event=>setSelected(event.currentTarget.value)} disabled={busy}>
          <option value="">Choose a room thread</option>
          {status.threads.map(item=><option key={item.id} value={item.id}>
            {item.name} · {item.messageCount} messages · {item.id}
          </option>)}
        </select></label>
        {thread&&<form key={thread.id} className="release-form" onSubmit={event=>{
          const trigger=(event.nativeEvent as SubmitEvent).submitter?.getAttribute('value')
          void submit(event,trigger==='capture'?'capture':'copy',thread.room,thread.id)
        }}>
          <label>Confirm thread offboarding workspace ID<input name="workspace" required maxLength={36} autoComplete="off"/></label>
          <div className="actions">
            <button type="submit" className="secondary" disabled={busy}>Download approved thread copy</button>
            {thread.copied&&<button type="submit" className="secondary" value="capture" disabled={busy||status.held}>
              Prepare exact thread deletion plan
            </button>}
          </div>
        </form>}
      </>}
      {status?.plans.map(plan=><article key={plan.plan} className="release-board-item">
        <h5>Thread with {plan.messageCount} messages</h5>
        <p>Room ID <code>{plan.room}</code></p>
        <p>Root message ID <code>{plan.root}</code></p>
        <p>Deletion plan SHA-256 <code>{plan.sha256}</code></p>
        <details>
          <summary>Show exact message manifest</summary>
          <ul>{plan.manifest.map(item=><li key={item.id}>
            {item.parent?'Reply':'Root'} <code>{item.id}</code> · Archive SHA-256 <code>{item.sha256}</code>
          </li>)}</ul>
        </details>
        <p>{plan.deletedAt?'Thread deleted from the live workspace':plan.approvedAt?'Thread independently approved':'Awaiting independent thread review'}</p>
        {!status.held&&!plan.deletedAt&&role==='reviewer'&&!plan.approvedAt&&<form className="release-form"
          onSubmit={event=>void submit(event,'approve',plan.room,plan.root,plan)}>
          <label>Confirm thread review workspace ID<input name="workspace" required maxLength={36} autoComplete="off"/></label>
          <button type="submit" className="secondary" disabled={busy}>Approve exact room thread deletion</button>
        </form>}
        {!status.held&&!plan.deletedAt&&role==='owner'&&plan.approvedAt&&<details className="release-create">
          <summary>Permanently delete this room thread</summary>
          <form className="release-form" onSubmit={event=>void submit(event,'delete',plan.room,plan.root,plan)}>
            <p>This removes the complete thread from the live room and search. This action cannot be undone in SecTalk.</p>
            <label>Confirm thread deletion workspace ID<input name="workspace" required maxLength={36} autoComplete="off"/></label>
            <label>Confirm exact root message ID<input name="root" required maxLength={36} autoComplete="off"/></label>
            <label className="task-check"><input type="checkbox" required/> I retained the approved thread copy according to my workspace’s policy.</label>
            <button type="submit" className="primary" disabled={busy}>Permanently delete approved thread</button>
          </form>
        </details>}
      </article>)}
      <button type="button" className="secondary" disabled={busy} onClick={()=>void load()}>Refresh thread deletion status</button>
    </section>
  </details>
}
