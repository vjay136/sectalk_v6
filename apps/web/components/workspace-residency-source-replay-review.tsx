'use client'

import {useCallback,useEffect,useState,type FormEvent} from 'react'
import {verifyAccountCredential} from '../lib/account-credential'
import {db,formatError} from '../lib/data'

type ReplayResult='matched'|'source_changed'|'not_replayed'
type ReplayRecord={kind:string;id:string;change:string;revision:string|null;result:ReplayResult}
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
      setReview(result.data as SourceReview)
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

  async function recordEvidence(event:FormEvent<HTMLFormElement>,action:'capture'|'confirm'){
    event.preventDefault()
    if(busy||!review?.evidenceDigest)return
    const form=event.currentTarget
    const fields=new FormData(form)
    const confirmation=String(fields.get('workspace')||'')
    setBusy(true);setError('')
    try {
      if(confirmation!==workspace)throw new Error('Enter the exact workspace ID shown above.')
      const assurance=await db!.rpc('st_v7_sensitive_action_status',{p_kind:'room_role'})
      if(assurance.error)throw assurance.error
      if(assurance.data!=='verified'){
        const code=String(fields.get('code')||'')
        if(!code)throw new Error('Enter a current authenticator code.')
        await verifyAccountCredential(code,true)
      }
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
