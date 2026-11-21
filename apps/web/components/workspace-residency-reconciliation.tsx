'use client'

import {useState} from 'react'
import {db,formatError} from '../lib/data'

type RecordKind='workspace_task'|'workspace_event'|'room_task'|'channel_message'|'room_message'|'workspace_file'|'room_file'
type RecordStatus='matched'|'missing'|'changed'|'check_bytes'|'unsupported'
type DestinationRecord={id:string;scope:string;kind:RecordKind;status:RecordStatus}
type Reconciliation={checkedAt:string;approvalCurrent:boolean;manifestSha256:string;records:DestinationRecord[]}

const kinds:Record<RecordKind,string>={workspace_task:'Workspace task',workspace_event:'Workspace calendar event',room_task:'Room task',channel_message:'Channel message',
  room_message:'Room message',workspace_file:'Workspace file',room_file:'Room file'}
const statuses:Record<RecordStatus,string>={matched:'Match the approved record',missing:'Await restoration',changed:'Changed since approval',
  check_bytes:'Need a protected download check',unsupported:'Need a supported restore path'}

export function WorkspaceResidencyReconciliation({workspace,approval,disabled,authorize}:{workspace:string;approval:string;disabled?:boolean;
  authorize:(action:()=>Promise<void>)=>void|Promise<void>}) {
  const [result,setResult]=useState<Reconciliation|null>(null)
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)
  const [proof,setProof]=useState('')

  function compare(file?:DestinationRecord) {
    void authorize(async()=>{
      setBusy(true)
      setProof('')
      if(!file)setResult(null)
      setError('')
      try {
        if(file){
          const {data:{session}}=await db!.auth.getSession()
          if(!session)throw new Error('Sign in again to verify this file.')
          const room=file.kind==='room_file'
          const query=new URLSearchParams({file:file.id,'residency-verify':approval,
            ...(room?{room:file.scope}:{workspace})})
          const response=await fetch((room?'/api/room-files?':'/api/workspace-files?')+query,{
            headers:{Authorization:'Bearer '+session.access_token},cache:'no-store',
          })
          if(!response.ok)throw new Error('The protected file could not be verified against the approved bytes.')
        }
        const {data,error}=await db!.rpc('st_v8_residency_compare_destination',{p_workspace:workspace,p_approval:approval})
        if(error)throw error
        setResult(data as Reconciliation)
      } catch(cause) {
        setError(formatError(cause,'Could not compare destination records.'))
      } finally {
        setBusy(false)
      }
    })
  }

  function issueReceipt() {
    void authorize(async()=>{
      setBusy(true);setError('');setProof('')
      try {
        const {data,error}=await db!.rpc('st_v8_residency_issue_comparison_receipt',{p_workspace:workspace,p_approval:approval})
        if(error)throw error
        setProof(JSON.stringify(data))
      } catch(cause){setError(formatError(cause,'Could not create the destination receipt.'))}
      finally{setBusy(false)}
    })
  }

  const issues=result?.records.filter(record=>record.status!=='matched')??[]
  return <section className="release-section" aria-label="Compare destination records">
    <h4>Compare destination records</h4>
    <p>Compare this destination with the approved manifest before routing traffic. File verification reads the protected bytes and checks the current storage revision.</p>
    <button type="button" className="secondary" disabled={disabled||busy} onClick={()=>compare()}>Compare approved records</button>
    {busy&&<p role="status">Comparing destination records…</p>}
    {error&&<p role="alert">{error}</p>}
    {result&&<>
      <p role="status">Checked {result.records.length} approved records at {new Date(result.checkedAt).toLocaleString()}.</p>
      {!result.approvalCurrent&&<p role="alert">The approval has expired. Obtain current approval before moving traffic.</p>}
      <p>Manifest <code>{result.manifestSha256}</code></p>
      {result.approvalCurrent&&<button type="button" className="secondary" disabled={disabled||busy} onClick={issueReceipt}>
        Create destination comparison receipt
      </button>}
      {proof&&<label className="release-form">Destination comparison receipt
        <textarea value={proof} readOnly rows={4} onFocus={event=>event.currentTarget.select()}/>
        <span>Share the receipt with the source reviewer within five minutes.</span>
      </label>}
      <ul aria-label="Destination comparison totals">
        {Object.entries(statuses).map(([status,label])=><li key={status}>
          {label} <strong>{result.records.filter(record=>record.status===status).length}</strong>
        </li>)}
      </ul>
      {issues.length>0&&<details>
        <summary>Review {issues.length} records that need attention</summary>
        <ul className="audit">{issues.map(record=><li key={`${record.kind}:${record.scope}:${record.id}`}>
          {kinds[record.kind]} <code>{record.id}</code> · {statuses[record.status]}
          {record.status==='check_bytes'&&result.approvalCurrent&&<button type="button" className="secondary"
            disabled={disabled||busy} aria-label={'Verify file '+record.id} onClick={()=>compare(record)}>Verify file bytes</button>}
        </li>)}</ul>
      </details>}
    </>}
  </section>
}
