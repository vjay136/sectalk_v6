'use client'

import { useState, type FormEvent } from 'react'
import { db } from '../lib/data'

export type AuditWorkspace={id:string;name:string}
type AuditResult={source:'workspace'|'room';id:number;event:string;actor:string;target:string|null;room_name:string|null;at:string}

function auditDate(value:FormDataEntryValue|null,exclusiveEnd=false){
  if(!value)return null
  const date=new Date(String(value)+'T00:00:00')
  if(exclusiveEnd)date.setDate(date.getDate()+1)
  return date.toISOString()
}

export function AuditSearch({workspaces}:{workspaces:AuditWorkspace[]}){
  const [rows,setRows]=useState<AuditResult[]|null>(null)
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')

  async function submit(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    if(busy)return
    const form=new FormData(event.currentTarget)
    setBusy(true);setError('');setRows(null)
    try {
      const from=auditDate(form.get('from'))
      const before=auditDate(form.get('through'),true)
      if(from&&before&&before<=from){setError('Choose an end date on or after the start date.');return}
      const {data,error}=await db!.rpc('st_v6_audit_search',{
        p_workspace:form.get('workspace'),p_query:form.get('query'),p_source:form.get('source')||null,p_from:from,p_before:before,
      })
      if(error)throw error
      setRows(data as AuditResult[])
    } catch {setError('Could not search audit logs for this workspace.')}
    finally {setBusy(false)}
  }

  return <section className="release-section" aria-label="Audit log search">
    <form className="panel release-panel release-form" onSubmit={submit}>
      <label>Audit workspace<select name="workspace" required disabled={busy} onChange={()=>{setRows(null);setError('')}}>
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
    {rows?.length===0&&<p role="status">No matching audit entries.</p>}
    {rows?.length===100&&<p role="status">Showing the latest 100 matches. Refine the filters to find older entries.</p>}
    {rows?.map(row=><article className="panel release-panel" key={row.source+row.id}>
      <div className="release-row"><h2>{row.event.replaceAll('.',' ')}</h2><span className="pill">{row.room_name||'Workspace'}</span>
        <time dateTime={row.at}>{new Date(row.at).toLocaleString()}</time></div>
      <div className="release-row"><span>Actor</span><code>{row.actor}</code>{row.target&&<><span>Target</span><code>{row.target}</code></>}</div>
    </article>)}
  </section>
}
