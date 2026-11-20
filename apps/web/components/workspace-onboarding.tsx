'use client'

import { useEffect, useRef, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'

type Template={id:string;label:string;restricted:boolean}
type Step='type'|'name'|'review'

export function WorkspaceOnboarding({openByDefault,onCreated}:{
  openByDefault:boolean;onCreated:(id:string)=>Promise<void>
}){
  const [open,setOpen]=useState(openByDefault)
  const [templates,setTemplates]=useState<Template[]|null>(null)
  const [step,setStep]=useState<Step>('type')
  const [type,setType]=useState('')
  const [name,setName]=useState('')
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)
  const [tries,setTries]=useState(0)
  const request=useRef<{id:string;key:string}|null>(null)
  const selected=templates?.find(template=>template.id===type)

  useEffect(()=>{
    if(!open)return
    let mounted=true
    async function read(){
      const {data,error}=await db!.from('st_v6_workspace_templates').select('id,label,restricted').order('sort_order').returns<Template[]>()
      if(!mounted)return
      if(error){setError('Could not load workspace types.');return}
      setTemplates(data);setError('')
    }
    void read()
    return()=>{mounted=false}
  },[open,tries])

  async function next(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    if(busy||!selected)return
    setError('')
    if(step==='type'){setStep('name');return}
    const displayName=name.trim()
    if(!displayName){setError('Enter a workspace name.');return}
    if(step==='name'){setStep('review');return}
    const key=JSON.stringify([type,displayName])
    if(request.current?.key!==key)request.current={id:crypto.randomUUID(),key}
    setBusy(true)
    try{
      const {data,error}=await db!.rpc('st_v6_create_typed_workspace',{p_id:request.current.id,p_name:displayName,p_type:type})
      if(error)throw error
      await onCreated(data)
      request.current=null
      setStep('type');setName('');setType('');setOpen(false)
    }catch(error){setError(formatError(error,'Could not create the workspace.'))}
    finally{setBusy(false)}
  }

  return <details className="release-create" open={open} onToggle={event=>setOpen(event.currentTarget.open)}>
    <summary>Create a workspace</summary>
    <form className="release-form" aria-label="Workspace setup" onSubmit={next}>
      {step==='type'&&<>
        <h3>Choose a workspace type</h3>
        {!templates&&!error&&<p role="status">Loading workspace types…</p>}
        {!templates&&error&&<button type="button" className="secondary" onClick={()=>{setError('');setTries(previous=>previous+1)}}>Retry workspace types</button>}
        {templates&&<label>Workspace type<select required value={type} onChange={event=>setType(event.target.value)}>
          <option value="">Choose a type</option>
          {templates.map(template=><option key={template.id} value={template.id}>{template.label}</option>)}
        </select></label>}
      </>}
      {step==='name'&&<>
        <h3>Name your workspace</h3>
        <label>Workspace name<input required maxLength={64} value={name} onChange={event=>setName(event.target.value)}/></label>
      </>}
      {step==='review'&&selected&&<>
        <h3>Review workspace setup</h3>
        <p><strong>{name.trim()}</strong> · {selected.label}</p>
        <p>Default policy {selected.restricted?'requires private or admin-only rooms and individual meeting admission.':
          'allows all available room types and lets meeting hosts admit eligible attendees together.'}</p>
      </>}
      {error&&<p className="error" role="alert">{error}</p>}
      <div className="action-row">
        {step!=='type'&&<button className="secondary" type="button" disabled={busy} onClick={()=>{
          setError('');setStep(step==='review'?'name':'type')
        }}>Back</button>}
        <button className="primary" disabled={busy||!selected}>{step==='review'?(busy?'Creating…':'Create workspace'):'Continue'}</button>
      </div>
    </form>
  </details>
}
