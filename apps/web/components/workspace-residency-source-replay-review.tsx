'use client'

import {useCallback,useEffect,useState,type FormEvent} from 'react'
import {verifyAccountCredential} from '../lib/account-credential'
import {db,formatError} from '../lib/data'
import {workspaceFileRequest} from '../lib/workspace-files-client'

type ReplayResult='matched'|'source_changed'|'not_replayed'
type ReplayRecord={kind:string;id:string;change:string;revision:string|null;result:ReplayResult}
type StagedFile={file:string;room?:string|null;filename:string|null;sha256:string;bytes:number;digest:string;state:'staged'|'approved'|'changed'|'restored'}
type FileReview={role?:'owner'|'reviewer';files?:StagedFile[]}
type SourceReview={
  state:'inactive'|'awaiting_manifest'|'held'
  reviewDigest?:string
  records?:ReplayRecord[]
  role?:'owner'|'reviewer'
  coverage?:'incomplete'|'preservation_hold'|'ready'|'pending'|'reviewed'
  evidenceId?:string
  evidenceDigest?:string
}

const resultLabels:Record<ReplayResult,string>={
  matched:'Verified at source',
  source_changed:'Source differs from replay evidence',
  not_replayed:'No applied replay',
}

export function WorkspaceResidencySourceReplayReview({workspace}:{workspace:string}) {
  const [review,setReview]=useState<SourceReview>()
  const [fileReview,setFileReview]=useState<FileReview>()
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [visible,setVisible]=useState(50)

  const refresh=useCallback(async (signal?:AbortSignal)=>{
    setBusy(true);setError('')
    try{
      const query=db!.rpc('st_v8_residency_source_evidence',{p_workspace:workspace})
      const result=await (signal?query.abortSignal(signal):query)
      if(signal?.aborted)return
      if(result.error)throw result.error
      const next=result.data as SourceReview
      setReview(next)
      if(next.state==='held') {
        const files=db!.rpc('st_v8_residency_source_file_review',{p_workspace:workspace})
        const staged=await (signal?files.abortSignal(signal):files)
        if(signal?.aborted)return
        if(staged.error)throw staged.error
        setFileReview(staged.data as FileReview)
      } else setFileReview(undefined)
    }catch(cause){
      if(!signal?.aborted){
        setError(formatError(cause,'Could not check the source records.'))
      }
    }finally{
      if(!signal?.aborted)setBusy(false)
    }
  },[workspace])

  useEffect(()=>{
    const controller=new AbortController()
    void refresh(controller.signal)
    return ()=>controller.abort()
  },[refresh])

  async function verifyCredential(fields:FormData,confirmation:string){
    if(confirmation!==workspace)throw new Error('Enter the exact workspace ID shown above.')
    const assurance=await db!.rpc('st_v7_sensitive_action_status',{p_kind:'room_role'})
    if(assurance.error)throw assurance.error
    if(assurance.data!=='verified'){
      const code=String(fields.get('code')||'')
      if(!code)throw new Error('Enter a current authenticator code.')
      await verifyAccountCredential(code,true)
    }
  }

  async function processFile(event:FormEvent<HTMLFormElement>,file:StagedFile,action:'approve'|'restore'){
    event.preventDefault()
    if(busy||!fileReview)return
    const form=event.currentTarget
    const fields=new FormData(form)
    const confirmation=String(fields.get('workspace')||'')
    setBusy(true);setError('')
    try {
      await verifyCredential(fields,confirmation)
      let updated:StagedFile
      if(action==='approve') {
        const result=await db!.rpc('st_v8_residency_source_file_review',{
          p_workspace:workspace,p_file:file.file,p_digest:file.digest,p_confirmation:confirmation,
        })
        if(result.error)throw result.error
        const approved=(result.data as FileReview).files?.[0]
        if(!approved||approved.file!==file.file||approved.state!=='approved')throw new Error('The file approval could not be verified.')
        updated=approved
      }else{
        const response=await workspaceFileRequest(workspace,'POST',{id:file.file,rollbackRestore:file.digest})
        const result=await response.json()
        if(result.file!==file.file||result.state!=='restored')throw new Error('The restored file could not be verified.')
        updated={...file,state:'restored'}
      }
      setFileReview({...fileReview,files:fileReview.files?.map(copy=>copy.file===file.file?updated:copy)})
      form.reset()
    }catch(cause){setError(formatError(cause,action==='approve'?'Could not approve the staged file.':'Could not restore the approved file.'))}
    finally{setBusy(false)}
  }

  async function recordEvidence(event:FormEvent<HTMLFormElement>,action:'capture'|'confirm'){
    event.preventDefault()
    if(busy||!review?.evidenceDigest)return
    const form=event.currentTarget
    const fields=new FormData(form)
    const confirmation=String(fields.get('workspace')||'')
    setBusy(true);setError('')
    try {
      await verifyCredential(fields,confirmation)
      const result=await db!.rpc('st_v8_residency_source_evidence',{
        p_workspace:workspace,p_action:action,p_confirmation:confirmation,
        p_review:review.evidenceId,p_digest:review.evidenceDigest,
      })
      if(result.error)throw result.error
      form.reset()
      setReview(result.data as SourceReview)
    }catch(cause){setError(formatError(cause,'Could not record the source evidence.'))}
    finally{setBusy(false)}
  }

  if(!review||review.state==='inactive')return null
  const records=review.records||[]
  const verified=records.filter(record=>record.result==='matched').length
  const action=review.role==='owner'&&review.coverage==='ready'?'capture':
    review.role==='reviewer'&&review.coverage==='pending'?'confirm':undefined
  return <section className="release-section" aria-label="Source rollback verification">
    <h3>Source rollback verification</h3>
    {error?<p role="alert">{error}</p>:review.state==='awaiting_manifest'?<p role="status">Import the independently reviewed destination manifest to compare source records.</p>:<>
      <p role="status">{verified} of {records.length} reviewed changes verified at the source. Workspace writes are held.</p>
      <p>Destination review digest <code>{review.reviewDigest}</code></p>
      {review.coverage==='preservation_hold'&&<p>Evidence sign-off is paused by an active preservation hold.</p>}
      {review.coverage==='pending'&&<p role="status">Awaiting independent sign-off on the recorded source evidence.</p>}
      {review.coverage==='reviewed'&&<p role="status">The independent reviewer signed off on all changes in this manifest.</p>}
      {review.evidenceDigest&&<p>Source evidence digest <code>{review.evidenceDigest}</code></p>}
      {!!records.length&&<details>
        <summary>View source verification by record</summary>
        <ul>{records.slice(0,visible).map(record=><li key={record.kind+':'+record.id}>
          {record.kind.replaceAll('_',' ')} · {record.change} · {resultLabels[record.result]} · <code>{record.id}</code>
        </li>)}</ul>
        {visible<records.length&&<button className="secondary" onClick={()=>setVisible(previous=>previous+50)}>Show more records</button>}
      </details>}
      {!!fileReview?.files?.length&&<section aria-label="Staged rollback files">
        <h4>Staged rollback files</h4>
        <ul>{fileReview.files.map(file=>{
          const fileAction=review.coverage==='preservation_hold'||!file.filename?undefined:
            file.state==='staged'&&fileReview.role==='reviewer'?'approve':file.state==='approved'&&fileReview.role==='owner'?'restore':undefined
          return <li key={file.file}>
          {file.filename&&<p>{file.filename}</p>}
          {file.room&&<p>Room <code>{file.room}</code></p>}
          <p>File <code>{file.file}</code> · {file.bytes.toLocaleString()} bytes</p>
          <p>SHA-256 <code>{file.sha256}</code></p>
          <p role="status">{!file.filename?'Stage a fresh signed copy for restoration':file.state==='restored'?
            file.room?'Restored to room Files':'Restored to workspace Files':
            file.state==='approved'?'Approved for restoration':file.state==='changed'?'Recovery copy changed or is missing':'Awaiting independent approval'}</p>
          {fileAction&&<form className="release-form" onSubmit={event=>void processFile(event,file,fileAction)}>
              <p>Workspace ID <code>{workspace}</code></p>
              <label>Confirm staged file workspace ID<input name="workspace" required autoComplete="off" disabled={busy}/></label>
              <label>Authenticator code if prompted<input name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" disabled={busy}/></label>
              <button className="secondary" disabled={busy}>{fileAction==='approve'?'Approve staged file':'Restore approved file'}</button>
            </form>}
        </li>})}</ul>
      </section>}
    </>}
    {!error&&action&&<form className="release-form" onSubmit={event=>void recordEvidence(event,action)}>
      <p>Workspace ID <code>{workspace}</code></p>
      <label>Confirm source evidence workspace ID<input name="workspace" required autoComplete="off" disabled={busy}/></label>
      <label>Authenticator code if prompted<input name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" disabled={busy}/></label>
      <button className="secondary" type="submit" disabled={busy}>{action==='capture'?'Record source evidence':'Sign off on source evidence'}</button>
    </form>}
    <button className="secondary" disabled={busy} onClick={()=>void refresh()}>Refresh source verification</button>
  </section>
}
