'use client'

import {useCallback,useEffect,useState,type FormEvent} from 'react'
import {verifyAccountCredential} from '../lib/account-credential'
import {saveDownload} from '../lib/chat-files'
import {db,formatError} from '../lib/data'
import {workspaceFileRequest} from '../lib/workspace-files-client'

type Change={kind:string;id:string;state:'added'|'removed'|'changed';before:string|null;after:string|null}
type Review={
  state:'inactive'|'ready'|'pending'|'reviewed'|'changed'|'baseline_missing'|'capacity_exceeded'
  role?:'owner'|'reviewer'
  id?:string
  digest?:string
  reviewedAt?:string
  changes?:Change[]
}

async function verifyReviewCredential(fields:FormData) {
  const assurance=await db!.rpc('st_v7_sensitive_action_status',{p_kind:'room_role'})
  if(assurance.error)throw assurance.error
  if(assurance.data==='verified')return
  const code=String(fields.get('code')||'')
  if(!code)throw new Error('Enter a current authenticator code.')
  await verifyAccountCredential(code,true)
}

export function WorkspaceResidencyRollbackReview({workspace}:{workspace:string}) {
  const [review,setReview]=useState<Review>()
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)
  const [visible,setVisible]=useState(50)

  const refresh=useCallback(async (signal?:AbortSignal)=>{
    const query=db!.rpc('st_v8_residency_rollback_reconcile',{p_workspace:workspace})
    const result=await (signal?query.abortSignal(signal):query)
    if(!signal?.aborted&&!result.error)setReview(result.data as Review)
  },[workspace])

  useEffect(()=>{
    const abort=new AbortController()
    void refresh(abort.signal)
    return ()=>abort.abort()
  },[refresh])

  async function submit(event:FormEvent<HTMLFormElement>,action:'capture'|'confirm'){
    event.preventDefault()
    if(busy)return
    const form=event.currentTarget
    const fields=new FormData(form)
    const confirmation=String(fields.get('workspace')||'')
    setBusy(true);setError('')
    try {
      if(confirmation!==workspace)throw new Error('Enter the exact workspace ID shown above.')
      await verifyReviewCredential(fields)
      const result=await db!.rpc('st_v8_residency_rollback_reconcile',{
        p_workspace:workspace,p_action:action,p_confirmation:confirmation,p_review:review?.id,p_digest:review?.digest,
      })
      if(result.error)throw result.error
      form.reset()
      setVisible(50);setReview(result.data as Review)
    } catch(cause){setError(formatError(cause,'Could not update the destination change review.'));await refresh()}
    finally{setBusy(false)}
  }

  async function downloadCopy(event:FormEvent<HTMLFormElement>,file:string,roomFile:boolean) {
    event.preventDefault()
    if(busy||!review?.id)return
    const form=event.currentTarget
    setBusy(true);setError('')
    try{
      await verifyReviewCredential(new FormData(form))
      const response=await workspaceFileRequest(workspace,'GET',{id:file,rollbackReview:review.id,rollbackRoom:roomFile})
      const proofHeader=response.headers.get('X-SecTalk-Rollback-File-Proof')
      if(!proofHeader)throw new Error('The signed file copy was unavailable.')
      const proof=JSON.parse(new TextDecoder().decode(
        Uint8Array.from(atob(proofHeader.replaceAll('-','+').replaceAll('_','/')),value=>value.charCodeAt(0))))
      const bytes=new Uint8Array(await response.arrayBuffer())
      const chunks=[]
      for(let offset=0;offset<bytes.length;offset+=16384){
        chunks.push(String.fromCharCode(...bytes.subarray(offset,offset+16384)))
      }
      const copy={format:'sectalk-residency-file-copy-v1',proof,contentBase64:btoa(chunks.join(''))}
      saveDownload(new Blob([JSON.stringify(copy)],{type:'application/json'}),'sectalk-file-recovery-'+file+'.json')
      form.reset()
    }catch(cause){setError(formatError(cause,'Could not download the reviewed file copy.'))}
    finally{setBusy(false)}
  }

  if(!review||review.state==='inactive')return null
  const action=review.role==='owner'&&(review.state==='ready'||review.state==='changed')?'capture':
    review.role==='reviewer'&&review.state==='pending'?'confirm':undefined
  const changes=review.changes||[]
  return <section className="release-section" aria-label="Destination rollback change review">
    <h3>Destination rollback change review</h3>
    {review.state==='baseline_missing'&&<p role="status">This activation has no captured baseline. It requires separate recovery evidence.</p>}
    {review.state==='capacity_exceeded'&&<p role="status">At least one record type exceeds the review limit. It requires a separate inventory.</p>}
    {review.state==='ready'&&<p role="status">The destination owner can capture changes against the activation baseline.</p>}
    {review.state==='pending'&&<p role="status">Awaiting independent review.</p>}
    {review.state==='changed'&&<p role="status">The evidence or reviewer access changed. Capture a new review.</p>}
    {review.state==='reviewed'&&<p role="status">The independent review is current. Workspace writes remain held.</p>}
    {review.id&&<>
      <p>{changes.length} {changes.length===1?'record':'records'} changed in the covered data.</p>
      <p>Review digest <code>{review.digest}</code></p>
      {changes.length>0&&<details>
        <summary>View record revisions</summary>
        <ul>{changes.slice(0,visible).map(record=><li key={record.kind+record.id}>
          {record.kind.replaceAll('_',' ')} · {record.state} · <code>{record.id}</code>
          {record.before&&<div>Previous revision <code>{record.before}</code></div>}
          {record.after&&<div>Current revision <code>{record.after}</code></div>}
          {review.role==='owner'&&review.state==='reviewed'&&['workspace_file','room_file'].includes(record.kind)&&record.state==='added'&&
            <form className="release-form" onSubmit={event=>void downloadCopy(event,record.id,record.kind==='room_file')}>
              <label>Authenticator code if prompted<input name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" disabled={busy}/></label>
              <button className="secondary" type="submit" disabled={busy}>
                {record.kind==='room_file'?'Download reviewed room file copy':'Download reviewed file copy'}
              </button>
            </form>}
        </li>)}</ul>
        {visible<changes.length&&<button className="secondary" onClick={()=>setVisible(previous=>previous+50)}>Show more records</button>}
      </details>}
    </>}
    {action&&<form className="release-form" onSubmit={event=>void submit(event,action)}>
      <p>Workspace ID <code>{workspace}</code></p>
      <label>Confirm change review workspace ID<input name="workspace" required autoComplete="off" disabled={busy}/></label>
      <label>Authenticator code if prompted<input name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" disabled={busy}/></label>
      <button className="secondary" type="submit" disabled={busy}>{action==='capture'?'Capture destination changes':'Confirm independent change review'}</button>
    </form>}
    <button className="secondary" disabled={busy} onClick={()=>void refresh()}>Refresh change review</button>
    {error&&<p role="alert">{error}</p>}
  </section>
}
