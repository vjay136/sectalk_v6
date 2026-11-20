'use client'

import { useState, type FormEvent } from 'react'
import { db } from '../lib/data'

export type AuditWorkspace={id:string;name:string}
type AuditResult={source:'workspace'|'room';id:number;event:string;actor:string;target:string|null;room_name:string|null;at:string}
type Integrity={state:'empty'|'matched'|'unavailable';last_local_checkpoint:string|null;can_export:boolean}
type Filters={workspace:string;query:string;source:string|null;from:string|null;before:string|null}

function auditDate(value:FormDataEntryValue|null,exclusiveEnd=false){
  if(!value)return null
  const date=new Date(String(value)+'T00:00:00')
  if(exclusiveEnd)date.setDate(date.getDate()+1)
  return date.toISOString()
}

export function AuditSearch({workspaces}:{workspaces:AuditWorkspace[]}){
  const [rows,setRows]=useState<AuditResult[]|null>(null)
  const [integrity,setIntegrity]=useState<Integrity|null>(null)
  const [filters,setFilters]=useState<Filters|null>(null)
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')

  function clearResults(){
    setRows(null);setIntegrity(null);setFilters(null);setError('')
  }

  async function submit(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    if(busy)return
    const form=new FormData(event.currentTarget)
    setBusy(true);clearResults()
    try {
      const from=auditDate(form.get('from'))
      const before=auditDate(form.get('through'),true)
      if(from&&before&&before<=from){setError('Choose an end date on or after the start date.');return}
      const scope={workspace:String(form.get('workspace')),query:String(form.get('query')).trim(),
        source:String(form.get('source')||'')||null,from,before}
      const {data,error}=await db!.rpc('st_v6_audit_search',{
        p_workspace:scope.workspace,p_query:scope.query,p_source:scope.source,p_from:from,p_before:before,
      })
      if(error)throw error
      const matches=data as AuditResult[]
      setRows(matches)
      const status=await db!.rpc('st_v6_audit_integrity_status',{
        p_workspace:scope.workspace,p_rows:matches.map(({id,source})=>({id,source})),
      })
      if(status.error){setError('Could not verify the selected audit entries.');return}
      setIntegrity(status.data as Integrity)
      setFilters(scope)
    } catch {setError('Could not search audit logs for this workspace.')}
    finally {setBusy(false)}
  }

  async function download(){
    if(busy||!filters||!integrity?.can_export||integrity.state==='unavailable')return
    setBusy(true);setError('')
    try {
      const {data:{session}}=await db!.auth.getSession()
      if(!session)throw new Error('Sign in to export audit entries.')
      const report=await fetch('/api/audit/export',{
        method:'POST',headers:{Authorization:'Bearer '+session.access_token,'Content-Type':'application/json'},
        body:JSON.stringify(filters),
      })
      if(!report.ok){
        const response=await report.json()
        setError(response.error||'Could not generate the signed export.')
        return
      }
      const url=URL.createObjectURL(await report.blob())
      const link=document.createElement('a')
      link.href=url
      link.download='sectalk-audit.json'
      link.click()
      window.setTimeout(()=>URL.revokeObjectURL(url),1000)
    }catch {setError('Could not generate the signed export.')}
    finally {setBusy(false)}
  }

  return <section className="release-section" aria-label="Audit log search">
    <form className="panel release-panel release-form" onSubmit={submit} onChange={clearResults}>
      <label>Audit workspace<select name="workspace" required disabled={busy}>
        {workspaces.map(space=><option key={space.id} value={space.id}>{space.name}</option>)}
      </select></label>
      <label>Audit event, room, or ID<input name="query" maxLength={120} disabled={busy}/></label>
      <div className="release-flex">
        <label>Log source<select name="source" disabled={busy}><option value="">All logs</option><option value="workspace">Workspace</option><option value="room">Room</option></select></label>
        <label>From date<input name="from" type="date" disabled={busy}/></label>
        <label>Through date<input name="through" type="date" disabled={busy}/></label>
      </div>
      <button className="primary" disabled={busy}>{busy?'Searching…':'Search audit logs'}</button>
    </form>
    {error&&<p role="alert" className="error">{error}</p>}
    {integrity&&<div className="panel release-panel">
      <h2>Journal integrity</h2>
      <p role="status">{integrity.state==='matched'?'Displayed entries match the local audit journal.':
        integrity.state==='empty'?'There are no entries to verify.':'The selected entries could not be verified.'}</p>
      {integrity.last_local_checkpoint&&<p>Last local journal checkpoint <time dateTime={integrity.last_local_checkpoint}>
        {new Date(integrity.last_local_checkpoint).toLocaleString()}</time>.</p>}
      {integrity.can_export&&integrity.state!=='unavailable'?
        <button className="secondary" type="button" onClick={()=>void download()} disabled={busy}>Download signed audit</button>:
        !integrity.can_export&&<p>Verify your authenticator in Profile → Security to export.</p>}
    </div>}
    {rows?.length===0&&<p role="status">No matching audit entries.</p>}
    {rows?.length===100&&<p role="status">Showing the latest 100 matches. Refine the filters to find older entries.</p>}
    {rows?.map(row=><article className="panel release-panel" key={row.source+row.id}>
      <div className="release-row"><h2>{row.event.replaceAll('.',' ')}</h2><span className="pill">{row.room_name||'Workspace'}</span>
        <time dateTime={row.at}>{new Date(row.at).toLocaleString()}</time></div>
      <div className="release-row"><span>Actor</span><code>{row.actor}</code>{row.target&&<><span>Target</span><code>{row.target}</code></>}</div>
    </article>)}
  </section>
}
