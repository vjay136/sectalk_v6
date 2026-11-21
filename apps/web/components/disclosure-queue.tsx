'use client'

import {useCallback,useEffect,useState} from 'react'
import {db} from '../lib/data'
import {StaffMfa} from './staff-mfa'

type Access='none'|'mfa'|'verified'
type State='received'|'reviewing'|'resolved'|'dismissed'
type Entry={id:string;state:State;created_at:string;updated_at:string}
type Report=Entry&{title:string;feature:string;details:string;contact:string;receipt:string}
const labels:Record<State,string>={received:'Received',reviewing:'In review',resolved:'Resolved',dismissed:'Dismissed'}

export function useDisclosureAccess() {
  const [access,setAccess]=useState<Access>('none')
  const refresh=useCallback(async()=>{
    const {data,error}=await db!.rpc('st_v8_disclosure_access')
    setAccess(!error&&(data==='verified'||data==='mfa')?data:'none')
  },[])
  useEffect(()=>{
    void refresh()
    const timer=window.setInterval(()=>void refresh(),15000)
    return ()=>window.clearInterval(timer)
  },[refresh])
  return {access,refresh}
}

type Props=ReturnType<typeof useDisclosureAccess>
export function DisclosureQueue({access,refresh}:Props) {
  if (access==='mfa') return <StaffMfa refresh={refresh} explanation="Verify your authenticator to open the private vulnerability disclosure queue."/>
  return access==='verified'?<VerifiedQueue refresh={refresh}/>:null
}

function VerifiedQueue({refresh}:{refresh:()=>Promise<void>}) {
  const [state,setState]=useState<State>('received')
  const [reports,setReports]=useState<Entry[]>([])
  const [report,setReport]=useState<Report|null>(null)
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)
  const [message,setMessage]=useState('')
  const request=useCallback(async<T,>(data:object,signal?:AbortSignal)=>{
    const token=(await db!.auth.getSession()).data.session?.access_token
    const response=await fetch('/api/security/disclosure/queue',{method:'POST',signal,
      headers:{'Content-Type':'application/json',Authorization:'Bearer '+token},body:JSON.stringify(data)})
    const body=await response.json()
    if (response.status===403) await refresh()
    if (!response.ok) throw new Error(body.error||'The disclosure queue is unavailable.')
    return body as T
  },[refresh])
  useEffect(()=>{
    const controller=new AbortController()
    setReports([])
    setReport(null)
    setError('')
    void request<{reports:Entry[]}>({action:'list',state},controller.signal)
      .then(data=>{if(!controller.signal.aborted)setReports(data.reports)})
      .catch(error=>{if(!controller.signal.aborted)setError(error.message)})
    return ()=>controller.abort()
  },[state,request])
  async function run(operation:()=>Promise<void>) {
    setBusy(true)
    setError('')
    setMessage('')
    try {await operation()}
    catch(error) {setError(error instanceof Error?error.message:'The request failed.')}
    finally {setBusy(false)}
  }
  return <section className="panel release-panel" aria-label="Vulnerability disclosure queue">
    <h2>Vulnerability disclosures</h2>
    <label>Report state<select value={state} disabled={busy} onChange={event=>setState(event.target.value as State)}>
      {Object.entries(labels).map(([value,label])=><option key={value} value={value}>{label}</option>)}
    </select></label>
    <button type="button" disabled={busy} onClick={()=>void run(async()=>{
      setReport(null)
      setReports((await request<{reports:Entry[]}>({action:'list',state})).reports)
    })}>Refresh disclosures</button>
    {!reports.length&&!error&&<p>No reports in this state.</p>}
    <ul>{reports.map(entry=><li key={entry.id}>
      <button type="button" disabled={busy} onClick={()=>void run(async()=>{
        setReport(null)
        setReport((await request<{report:Report}>({action:'open',id:entry.id})).report)
      })}>Open disclosure {entry.id.slice(0,8)}</button>
      <time dateTime={entry.created_at}>{new Date(entry.created_at).toLocaleString()}</time>
    </li>)}</ul>
    {report&&<article aria-label="Private disclosure">
      <h3>{report.title}</h3>
      <p>{report.feature}</p>
      <p style={{whiteSpace:'pre-wrap',overflowWrap:'anywhere'}}>{report.details}</p>
      {report.contact&&<p>Reply email {report.contact}</p>}
      <p>Receipt <code>{report.receipt}</code></p>
      <p>{labels[report.state]}</p>
      {(report.state==='received'?['reviewing'] as const:report.state==='reviewing'?['resolved','dismissed'] as const:[]).map(next=><button
        key={next} type="button" disabled={busy} onClick={()=>void run(async()=>{
          await request({action:'move',id:report.id,state:next})
          setReport(null)
          setReports(list=>list.filter(entry=>entry.id!==report.id))
          setMessage('Report moved to '+labels[next].toLowerCase()+'.')
        })}>{next==='reviewing'?'Begin review':next==='resolved'?'Resolve report':'Dismiss report'}</button>)}
    </article>}
    {message&&<p role="status">{message}</p>}
    {error&&<p role="alert">{error}</p>}
  </section>
}
