'use client'

import {useCallback,useEffect,useRef,useState,type FormEvent} from 'react'
import {db,formatError} from '../lib/data'

const labels={workspace_task:'Workspace task',channel_message:'Channel post',room_message:'Room message',room_task:'Room task'} as const
type Source={kind:keyof typeof labels;scope:string;id:string}
type Candidate=Source&{title:string}
type Batch={id:string;manifest:(Source&{plan:string;sha256:string})[];sha256:string;approvedAt:string|null;deletedAt:string|null}
type Status={held:boolean;candidates:Candidate[];batches:Batch[]}
type Action='capture'|'approve'|'delete'
const sourceKey=(source:Source)=>[source.kind,source.scope,source.id].join(':')

export function WorkspaceSourceBatch({workspace,role}:{workspace:string;role:'owner'|'reviewer'}) {
  const [open,setOpen]=useState(false)
  const [status,setStatus]=useState<Status>()
  const [selected,setSelected]=useState<Candidate[]>([])
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [notice,setNotice]=useState('')
  const latest=useRef(0)

  const load=useCallback(async()=>{
    const request=++latest.current
    const result=await db!.rpc('st_v8_offboarding_source_batch_status',{p_workspace:workspace})
    if(request===latest.current) setStatus(result.error?undefined:result.data)
  },[workspace])

  useEffect(()=>{
    if(!open) return
    void load()
    const timer=window.setInterval(()=>{if(document.visibilityState==='visible') void load()},12000)
    return ()=>{++latest.current;window.clearInterval(timer)}
  },[load,open])

  async function submit(event:FormEvent<HTMLFormElement>,action:Action,batch?:Batch) {
    event.preventDefault()
    if(busy) return
    const form=event.currentTarget
    const values=new FormData(form)
    if(action==='delete'&&String(values.get('batch')).trim()!==batch?.id) {
      setError('Enter the exact batch ID to confirm permanent deletion.')
      return
    }
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const result=await db!.rpc('st_v8_offboarding_source_batch',{
        p_workspace:workspace,p_action:action,p_confirmation:String(values.get('workspace')).trim(),
        ...(batch?{p_batch:batch.id,p_sha256:batch.sha256}:{p_sources:selected.map(({kind,scope,id})=>({kind,scope,id}))})
      })
      if(result.error) throw result.error
      form.reset()
      if(action==='capture') setSelected([])
      setNotice({capture:'Batch prepared for independent review.',approve:'Exact batch approved.',
        delete:'All sources in this batch were permanently deleted from the live workspace and search.'}[action])
    } catch(cause) {
      setError(formatError(cause,'The batch action could not be completed.'))
    } finally {
      await load()
      setBusy(false)
    }
  }

  const candidates=status?.candidates.filter(source=>!selected.some(item=>sourceKey(source)===sourceKey(item)))??[]
  return <details className="release-create" onToggle={event=>setOpen(event.currentTarget.open)}>
    <summary>Batch source deletion</summary>
    <section aria-label="Batch source deletion">
      <p>An independent reviewer approves the exact list. If one source fails its checks, the whole batch stays in place.</p>
      {role==='owner'&&<p>Download each approved copy in its source panel, then select two to four copied sources.</p>}
      {status?.held&&<p>Active preservation holds block batch deletion.</p>}
      {error&&<p className="error" role="alert">{error}</p>}
      {notice&&<p role="status">{notice}</p>}
      {role==='owner'&&status&&!status.held&&<form className="release-form" onSubmit={event=>void submit(event,'capture')}>
        <label>Add copied source<select value="" disabled={busy||!candidates.length||selected.length===4} onChange={event=>{
          const item=candidates.find(candidate=>sourceKey(candidate)===event.currentTarget.value)
          if(item) setSelected(current=>[...current,item])
        }}>
          <option value="">{candidates.length?'Choose a source':'No more copied sources available'}</option>
          {candidates.map(source=><option key={sourceKey(source)} value={sourceKey(source)}>
            {labels[source.kind]} · {source.title} · {source.id}
          </option>)}
        </select></label>
        {selected.length>0&&<ul>{selected.map(source=><li key={sourceKey(source)}>
          {labels[source.kind]} · {source.title} · <code>{source.id}</code>
          <button type="button" className="secondary" disabled={busy} aria-label={'Remove source '+source.id}
            onClick={()=>setSelected(current=>current.filter(item=>sourceKey(item)!==sourceKey(source)))}>Remove</button>
        </li>)}</ul>}
        {selected.length>=2&&<>
          <label>Confirm batch workspace ID<input name="workspace" required autoComplete="off" maxLength={36}/></label>
          <button className="secondary" disabled={busy}>Prepare exact deletion batch</button>
        </>}
      </form>}
      {status?.batches.map(batch=><article key={batch.id} className="release-board-item">
        <h5>Batch of {batch.manifest.length} sources</h5>
        <p>Batch ID <code>{batch.id}</code></p>
        <p>Batch SHA-256 <code>{batch.sha256}</code></p>
        <ul>{batch.manifest.map(source=><li key={sourceKey(source)}>
          {labels[source.kind]} <code>{source.id}</code> · Scope <code>{source.scope}</code>
        </li>)}</ul>
        <p>{batch.deletedAt?'Batch deleted from the live workspace':batch.approvedAt?'Batch independently approved':'Awaiting independent batch review'}</p>
        {!batch.deletedAt&&!status.held&&role==='reviewer'&&!batch.approvedAt&&
          <form className="release-form" onSubmit={event=>void submit(event,'approve',batch)}>
            <label>Confirm batch review workspace ID<input name="workspace" required autoComplete="off" maxLength={36}/></label>
            <button className="secondary" disabled={busy}>Approve exact deletion batch</button>
          </form>}
        {!batch.deletedAt&&!status.held&&role==='owner'&&batch.approvedAt&&<details className="release-create">
          <summary>Permanently delete this batch</summary>
          <form className="release-form" onSubmit={event=>void submit(event,'delete',batch)}>
            <p>This action cannot be undone in SecTalk.</p>
            <label>Confirm batch deletion workspace ID<input name="workspace" required autoComplete="off" maxLength={36}/></label>
            <label>Confirm exact batch ID<input name="batch" required autoComplete="off" maxLength={36}/></label>
            <label className="task-check"><input type="checkbox" required/> I retained the approved copies according to my workspace’s policy.</label>
            <button className="primary" disabled={busy}>Permanently delete approved batch</button>
          </form>
        </details>}
      </article>)}
      <button type="button" className="secondary" disabled={busy} onClick={()=>void load()}>Refresh deletion batches</button>
    </section>
  </details>
}
