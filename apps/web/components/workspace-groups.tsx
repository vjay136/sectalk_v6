'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { db, formatError, onReconnect, type Profile } from '../lib/data'
import { SectionTabs } from './section-tabs'

type Kind='group'|'team'|'department'
type Group={id:string;name:string;description:string;archived_at:string|null}
const title:Record<Kind,string>={group:'Group',team:'Team',department:'Department'}
const pageSize=30

export function WorkspaceGroups({workspace,manager,people,profiles}:{
  workspace:string;manager:boolean;people:{user_id:string}[];profiles:Record<string,Profile>
}){
  const [kind,setKind]=useState<Kind>('team')
  const [archived,setArchived]=useState(false)
  const [page,setPage]=useState(0)
  const [items,setItems]=useState<Group[]|null>(null)
  const [active,setActive]=useState('')
  const [delegate,setDelegate]=useState<{group:string;permissions:string[]}>()
  const [roster,setRoster]=useState<string[]|null>(null)
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [loadError,setLoadError]=useState('')
  const pending=useRef<{key:string;id:string}|null>(null)
  const loadVersion=useRef(0)
  const selected=items?.find(item=>item.id===active)

  const load=useCallback(async()=>{
    const groups=db!.from('st_v6_workspace_groups').select('id,name,description,archived_at')
      .eq('workspace_id',workspace).eq('kind',kind).order('name').order('id')
      .range(page*pageSize,page*pageSize+pageSize)
    const [directory,members,delegation]=await Promise.all([
      (archived?groups.not('archived_at','is',null):groups.is('archived_at',null)).returns<Group[]>(),
      active?db!.from('st_v6_workspace_group_members').select('user_id').eq('workspace_id',workspace).eq('group_id',active):null,
      !manager&&active?db!.rpc('st_v7_custom_group_access',{p_workspace:workspace,p_group:active}):null,
    ])
    if(directory.error||members?.error) throw new Error('Could not load the workspace directory.')
    return {directory:directory.data,roster:members?.data?.map(row=>row.user_id)??null,permissions:(delegation?.data??[]) as string[]}
  },[active,archived,kind,manager,page,workspace])

  useEffect(()=>{
    const activeId=active
    let currentView=true
    const loadCurrent=async()=>{
      const current=++loadVersion.current
      try{
        const result=await load()
        if(currentView&&current===loadVersion.current){setItems(result.directory);setRoster(result.roster);setDelegate({group:activeId,permissions:result.permissions});setLoadError('')}
      }catch(error){
        if(currentView&&current===loadVersion.current){
          setItems(null);setRoster(null);setLoadError(formatError(error,'Could not load the workspace directory.'))
        }
      }
    }
    void loadCurrent()
    const reconnect=onReconnect(loadCurrent)
    const timer=window.setInterval(loadCurrent,8000)
    return()=>{currentView=false;reconnect();clearInterval(timer)}
  },[load,active])

  function reset(next:Kind,showArchived:boolean,nextPage=0){
    setKind(next);setArchived(showArchived);setPage(nextPage)
    setActive('');setItems(null);setRoster(null);setError('');setLoadError('')
  }

  async function create(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    if(busy)return
    const form=event.currentTarget
    const values=new FormData(form)
    const name=String(values.get('name')).trim()
    const description=String(values.get('description')).trim()
    const key=JSON.stringify([kind,name,description])
    if(pending.current?.key!==key)pending.current={key,id:crypto.randomUUID()}
    setBusy(true);setError('')
    try{
      const {data,error}=await db!.rpc('st_v6_workspace_group_create',{
        p_workspace:workspace,p_id:pending.current.id,p_kind:kind,p_name:name,p_description:description,
      })
      if(error)throw error
      pending.current=null
      form.reset()
      const version=++loadVersion.current
      const refreshed=await load()
      if(version===loadVersion.current){setItems(refreshed.directory);setLoadError('')}
      setRoster(null);setActive(data)
    }catch(error){setError(formatError(error,'Could not create the directory entry.'))}
    finally{setBusy(false)}
  }

  async function change(action:string,values:Record<string,unknown>={}){
    if(busy||!selected)return
    setBusy(true);setError('')
    try{
      const {error}=await db!.rpc('st_v6_workspace_group_change',{p_workspace:workspace,p_id:selected.id,p_action:action,...values})
      if(error)throw error
      const version=++loadVersion.current
      const refreshed=await load()
      if(version===loadVersion.current){setItems(refreshed.directory);setRoster(refreshed.roster);setLoadError('')}
      if(action==='archive'||action==='restore')setActive('')
    }catch(error){setError(formatError(error,'Could not update the directory entry.'))}
    finally{setBusy(false)}
  }

  const can=(permission:string)=>manager||(delegate?.group===selected?.id&&delegate?.permissions.includes(permission))
  const available=people.filter(person=>!(roster||[]).includes(person.user_id))
  return <section className="release-section" aria-label="Workspace groups and teams">
    <h2>Workspace directory</h2>
    <SectionTabs label="Directory sections" value={kind} onChange={next=>{if(!busy&&next!==kind)reset(next,archived)}} options={[
      ['group','Groups'],['team','Teams'],['department','Departments'],
    ]}/>
    <label><input type="checkbox" checked={archived} disabled={busy} onChange={event=>reset(kind,event.target.checked)}/> Show archived entries only</label>
    {manager&&!archived&&<details className="release-create" key={kind}><summary>New {title[kind].toLowerCase()}</summary>
      <form className="release-form" onSubmit={create}>
        <label>{title[kind]} name<input name="name" required maxLength={80}/></label>
        <label>Description<textarea name="description" maxLength={500}/></label>
        <button className="primary" disabled={busy}>Create {title[kind].toLowerCase()}</button>
      </form>
    </details>}
    {error&&<p role="alert" className="error">{error}</p>}
    {loadError&&<p role="alert" className="error">{loadError}</p>}
    {!items&&!loadError&&<p role="status">Loading directory…</p>}
    {items?.length===0&&<p>No {archived?'archived ':''}{title[kind].toLowerCase()}s.</p>}
    {items?.slice(0,pageSize).map(item=><button key={item.id} type="button" className={item.id===active?'primary':'secondary'}
      disabled={busy} aria-pressed={item.id===active} onClick={()=>{if(item.id!==active){setRoster(null);setActive(item.id)}}}>{item.name}</button>)}
    {(page>0||(items?.length||0)>pageSize)&&<div className="action-row">
      <button type="button" className="secondary" disabled={busy||page===0} onClick={()=>reset(kind,archived,page-1)}>Previous entries</button>
      <button type="button" className="secondary" disabled={busy||(items?.length||0)<=pageSize} onClick={()=>reset(kind,archived,page+1)}>More entries</button>
    </div>}
    {selected&&<article className="panel release-panel">
      <h3>{selected.name}</h3>{selected.description&&<p>{selected.description}</p>}
      {can('rename')&&!archived&&<details className="release-create" key={selected.id+selected.name+selected.description}><summary>Edit {title[kind].toLowerCase()}</summary>
        <form className="release-form" onSubmit={event=>{
          event.preventDefault()
          const values=new FormData(event.currentTarget)
          void change('rename',{p_name:values.get('name'),p_description:values.get('description')})
        }}>
          <label>New name<input name="name" required maxLength={80} defaultValue={selected.name}/></label>
          <label>New description<textarea name="description" maxLength={500} defaultValue={selected.description}/></label>
          <button className="secondary" disabled={busy}>Save changes</button>
        </form>
      </details>}
      <h4>Members</h4>
      {roster===null&&<p role="status">Loading members…</p>}
      {roster?.length===0&&<p>No members yet.</p>}
      {roster?.map(id=><div className="release-row" key={id}>
        <strong>{profiles[id]?.name||'Workspace member'}</strong>
        {manager&&!archived&&<button type="button" className="secondary" disabled={busy}
          aria-label={'Remove '+(profiles[id]?.name||'member')} onClick={()=>void change('member_removed',{p_user:id})}>Remove</button>}
      </div>)}
      {manager&&!archived&&roster!==null&&available.length>0&&<form className="release-form" onSubmit={event=>{
        event.preventDefault()
        void change('member_added',{p_user:new FormData(event.currentTarget).get('member')})
      }}>
        <label>Workspace member<select name="member" required defaultValue=""><option value="">Choose a member</option>
          {available.map(member=><option key={member.user_id} value={member.user_id}>{profiles[member.user_id]?.name||'Workspace member'}{profiles[member.user_id]?' @'+profiles[member.user_id].handle:''}</option>)}
        </select></label><button className="secondary" disabled={busy}>Add member</button>
      </form>}
      {can(archived?'restore':'archive')&&<button type="button" className="secondary" disabled={busy}
        onClick={()=>void change(archived?'restore':'archive')}>{archived?'Restore':'Archive'} {title[kind].toLowerCase()}</button>}
    </article>}
  </section>
}
