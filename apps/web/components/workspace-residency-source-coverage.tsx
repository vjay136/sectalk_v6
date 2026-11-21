'use client'

import {useState} from 'react'
import {db,formatError} from '../lib/data'

const labels={workspace_task:'Workspace tasks',room_task:'Room tasks',channel_message:'Channel messages',room_message:'Room messages',
  workspace_file:'Workspace files',room_file:'Room files'}
type Family={kind:keyof typeof labels;observed:number;approved:number;current:number;unapproved:number;drifted:number;capped:boolean}
type Coverage={measuredAt:string;approvedRecords:number;families:Family[]}

export function WorkspaceResidencySourceCoverage({workspace,approval}:{workspace:string;approval:string}) {
  const [coverage,setCoverage]=useState<Coverage>()
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')

  async function check(){
    if(busy)return
    setBusy(true);setCoverage(undefined);setError('')
    try {
      const {data,error}=await db!.rpc('st_v8_residency_source_coverage',{p_workspace:workspace,p_approval:approval})
      if(error)throw error
      setCoverage(data as Coverage)
    } catch(cause){setError(formatError(cause,'Verify your current sign-in and retry the source coverage check.'))}
    finally{setBusy(false)}
  }

  return <details className="release-section">
    <summary>Source migration coverage</summary>
    <p>Compare the six supported record types with the approved source manifest.</p>
    <button className="secondary" type="button" disabled={busy} onClick={()=>void check()}>Check source coverage</button>
    {error&&<p role="alert">{error}</p>}
    {coverage&&<>
      <p role="status">Checked {coverage.approvedRecords} approved records at {new Date(coverage.measuredAt).toLocaleString()}.</p>
      {coverage.families.some(family=>family.capped)&&<p role="alert">A record type exceeded the inventory cap. Its observed and unapproved counts are lower bounds.</p>}
      <ul aria-label="Source coverage totals">{coverage.families.map(row=><li key={row.kind}>
        <strong>{labels[row.kind]}</strong> · {row.capped?'At least ':''}{row.observed} observed · {row.current} current approvals · {row.unapproved} unapproved · {row.drifted} changed or unavailable
      </li>)}</ul>
    </>}
  </details>
}
