'use client'

import { useEffect, useRef, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'

type Template={id:string;label:string;restricted:boolean}
type ComplianceProfile={id:string;label:string;room_kinds:string[];invite_hours:number;individual_admission:boolean}
type Step='type'|'name'|'review'

export function WorkspaceOnboarding({openByDefault,onCreated}:{
  openByDefault:boolean;onCreated:(id:string)=>Promise<void>
}){
  const [open,setOpen]=useState(openByDefault)
  const [templates,setTemplates]=useState<Template[]|null>(null)
  const [profiles,setProfiles]=useState<ComplianceProfile[]>([])
  const [step,setStep]=useState<Step>('type')
  const [type,setType]=useState('')
  const [profile,setProfile]=useState('')
  const [name,setName]=useState('')
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)
  const [tries,setTries]=useState(0)
  const request=useRef<{id:string;key:string}|null>(null)
  const selected=templates?.find(template=>template.id===type)
  const selectedProfile=profiles.find(option=>option.id===profile)

  useEffect(()=>{
    if(!open)return
    let mounted=true
    async function read(){
      const [templates,profiles]=await Promise.all([
        db!.from('st_v6_workspace_templates').select('id,label,restricted').order('sort_order').returns<Template[]>(),
        db!.from('st_v6_compliance_profiles').select('id,label,room_kinds,invite_hours,individual_admission').order('sort_order').returns<ComplianceProfile[]>(),
      ])
      if(!mounted)return
      if(templates.error||profiles.error){setError('Could not load workspace types and profiles.');return}
      setTemplates(templates.data);setProfiles(profiles.data);setError('')
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
    const key=JSON.stringify([type,displayName,profile])
    if(request.current?.key!==key)request.current={id:crypto.randomUUID(),key}
    setBusy(true)
    try{
      const params={p_id:request.current.id,p_name:displayName,p_type:type}
      const {data,error}=profile?
        await db!.rpc('st_v6_create_profiled_workspace',{...params,p_profile:profile}):
        await db!.rpc('st_v6_create_typed_workspace',params)
      if(error)throw error
      await onCreated(data)
      request.current=null
      setStep('type');setName('');setType('');setProfile('');setOpen(false)
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
        <label>Compliance profile<select value={profile} onChange={event=>setProfile(event.target.value)}>
          <option value="">Use workspace type defaults</option>
          {profiles.map(option=><option value={option.id} key={option.id}>{option.label}</option>)}
        </select></label>
      </>}
      {step==='review'&&selected&&<>
        <h3>Review workspace setup</h3>
        <p><strong>{name.trim()}</strong> · {selected.label}</p>
        {selectedProfile?<ul>
          <li><strong>{selectedProfile.label}</strong> setup profile</li>
          <li>Room types: {selected.restricted||!selectedProfile.room_kinds.includes('announcement')?
            'Private and admin-only':'Private, admin-only and announcement'}</li>
          <li>Meeting admission: {selected.restricted||selectedProfile.individual_admission?'individual':'individual or bulk'}</li>
          <li>Email links require an approved domain and expire in at most {selectedProfile.invite_hours} hours.</li>
          {selectedProfile.id==='healthcare'&&<>
            <li>Rooms start confidential and disallow forwarding and guests.</li>
            <li>Managed posts screen for recognized sensitive patterns. Health-record identifiers are blocked by default.</li>
            <li>Emergency evidence access requires explicit report sharing, separate owner approval and a time-limited, single-use grant.</li>
          </>}
        </ul>:<p>Default policy {selected.restricted?'requires private or admin-only rooms and individual meeting admission.':
          'allows all available room types and lets meeting hosts admit eligible attendees together.'}</p>}
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
