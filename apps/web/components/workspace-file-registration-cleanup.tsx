'use client'

import {useCallback,useEffect,useRef,useState,type FormEvent} from 'react'
import {db,formatError} from '../lib/data'

type Candidate={copy:string;room?:string;file:string;sourceSha256:string;reviewedAt:string|null}
type Status={held:boolean;candidates:Candidate[];retired:{room?:string;file:string;observedAt:string;removedAt:string}[]}

export function WorkspaceFileRegistrationCleanup({workspace,role,scope}:{
  workspace:string;role:'owner'|'reviewer';scope:'room'|'workspace'
}) {
  const label=scope+' file'
  const title=(scope==='room'?'Room':'Workspace')+' file registration cleanup'
  const [open,setOpen]=useState(false)
  const [status,setStatus]=useState<Status>()
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [notice,setNotice]=useState('')
  const latest=useRef(0)

  const load=useCallback(async()=>{
    const request=++latest.current
    const result=await db!.rpc(scope==='room'?'st_v8_room_file_cleanup_status':'st_v8_workspace_file_cleanup_status',{p_workspace:workspace})
    if(request===latest.current) {
      setStatus(result.error?undefined:result.data)
      if(result.error) setError(formatError(result.error,title+' could not be loaded.'))
    }
  },[workspace,scope,title])
  useEffect(()=>{
    if(!open) return
    void load()
    const timer=window.setInterval(()=>{if(document.visibilityState==='visible') void load()},20000)
    return ()=>{++latest.current;window.clearInterval(timer)}
  },[load,open])

  async function submit(event:FormEvent<HTMLFormElement>,file:Candidate) {
    event.preventDefault()
    if(busy) return
    const form=event.currentTarget
    const values=new FormData(form)
    const confirmation=String(values.get('workspace')).trim()
    const review=role==='reviewer'
    if(!review&&String(values.get('file')).trim()!==file.file) {
      setError('Enter the exact '+label+' ID to confirm registration removal.')
      return
    }
    const retained=values.get('retained')
    if(review&&(!(retained instanceof File)||!retained.size)) {
      setError('Choose the retained approved file from your recovery copy.')
      return
    }
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const {data}=await db!.auth.getSession()
      if(!data.session) throw new Error('Sign in again to continue.')
      const query=new URLSearchParams({workspace,copy:file.copy,file:file.file,action:review?'review':'remove',confirmation})
      const result=await fetch('/api/workspaces/offboarding/'+scope+'-file-cleanup?'+query,{
        method:'POST',headers:{Authorization:'Bearer '+data.session.access_token},
        ...(review&&retained instanceof File?{body:retained}:{})
      })
      if(!result.ok) throw new Error((await result.json()).error||'The '+label+' registration could not be updated.')
      setNotice(review?'Independent recovery copy verified.':'The '+label+' registration was removed.')
      form.reset()
      await load()
    } catch(cause) {setError(formatError(cause,title+' is unavailable.'))}
    finally {setBusy(false)}
  }

  return <details className="release-create" onToggle={event=>setOpen(event.currentTarget.open)}>
    <summary>{title}</summary>
    <section aria-label={title}>
      <p>Review the retained copy of an approved {label} whose original Storage path is absent. SecTalk checks the retained bytes without storing a new file.</p>
      <p>Registration removal records current Storage absence. Provider byte erasure and backup erasure remain unverified.</p>
      {status?.held&&<p>Active preservation holds block {label} cleanup.</p>}
      {error&&<p role="alert" className="error">{error}</p>}
      {notice&&<p role="status">{notice}</p>}
      {status&&!status.candidates.length&&<p>No approved copied {label}s have an absent Storage path.</p>}
      {status?.candidates.map(file=><article key={file.copy} className="release-board-item">
        <h5>{scope==='room'?'Room':'Workspace'} file</h5>
        {file.room&&<p>Room ID <code>{file.room}</code></p>}
        <p>{scope==='room'?'Room':'Workspace'} file ID <code>{file.file}</code></p>
        <p>Reviewed source SHA-256 <code>{file.sourceSha256}</code></p>
        <p>{file.reviewedAt?'Recovery copy independently verified':'Awaiting independent recovery verification'}</p>
        {!status.held&&role==='reviewer'&&!file.reviewedAt&&<form className="release-form" onSubmit={event=>void submit(event,file)}>
          <label>Confirm recovery workspace ID<input name="workspace" required maxLength={36} autoComplete="off"/></label>
          <label>Retained approved file<input type="file" name="retained" required/></label>
          <button type="submit" className="secondary" disabled={busy}>Verify recovered {label}</button>
        </form>}
        {!status.held&&role==='owner'&&file.reviewedAt&&<details className="release-create">
          <summary>Remove this {label} registration</summary>
          <form className="release-form" onSubmit={event=>void submit(event,file)}>
            <p>SecTalk checks the current Storage path before permanently removing this registration.</p>
            <label>Confirm cleanup workspace ID<input name="workspace" required maxLength={36} autoComplete="off"/></label>
            <label>Confirm exact {label} ID<input name="file" required maxLength={36} autoComplete="off"/></label>
            <button type="submit" className="primary" disabled={busy}>Remove approved {label} registration</button>
          </form>
        </details>}
      </article>)}
      {status?.retired.map(file=><article key={(file.room??workspace)+file.file} className="release-board-item">
        <h5>{scope==='room'?'Room':'Workspace'} file registration removed</h5>
        {file.room&&<p>Room ID <code>{file.room}</code></p>}
        <p>{scope==='room'?'Room':'Workspace'} file ID <code>{file.file}</code></p>
        <p>Storage checked <time dateTime={file.observedAt}>{new Date(file.observedAt).toLocaleString()}</time></p>
      </article>)}
      <button type="button" className="secondary" disabled={busy} onClick={()=>void load()}>Refresh {label} cleanup status</button>
    </section>
  </details>
}
