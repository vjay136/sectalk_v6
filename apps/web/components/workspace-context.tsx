'use client'

import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import { db, onReconnect } from '../lib/data'

type WorkspacePolicy={workspace_type:string;template:'standard'|'restricted';room_kinds:string[];bulk_admit:boolean;details:{label:string}|null;
  compliance:{label:string;invite_hours:number;require_domains:boolean}|null}
export type Workspace = { id:string; name:string; role:'owner'|'admin'|'member';policy:WorkspacePolicy|null }
type Membership = { role:Workspace['role']; workspace:Omit<Workspace,'role'>|null }
type WorkspaceContextValue = {
  workspaces:Workspace[]|null; active:Workspace|null; error:string
  select:(id:string)=>void; reload:(preferred?:string)=>Promise<void>
}

const WorkspaceContext=createContext<WorkspaceContextValue|null>(null)

function savedSelection(key:string){
  try{return localStorage.getItem(key)||''}catch{return ''}
}

export function WorkspaceContextProvider({user,children}:{ user:string;children:ReactNode }){
  const key='sectalk.workspace.v1:'+user
  const [selected,setSelected]=useState(()=>savedSelection(key))
  const [workspaces,setWorkspaces]=useState<Workspace[]|null>(null)
  const [error,setError]=useState('')
  const requestVersion=useRef(0)
  const preferredSelection=useRef<string|null>(null)

  const reload=useCallback(async(preferred?:string)=>{
    if(preferred)preferredSelection.current=preferred
    const version=++requestVersion.current
    const {data,error}=await db!.from('st_v2_members').select('role,workspace:st_v2_workspaces(id,name,policy:st_v6_workspace_policy(workspace_type,template,room_kinds,bulk_admit,details:st_v6_workspace_templates(label),compliance:st_v6_compliance_profiles(label,invite_hours,require_domains)))')
      .eq('user_id',user).order('joined_at').order('workspace_id').limit(100).returns<Membership[]>()
    if(version!==requestVersion.current)return
    if(error){setWorkspaces(null);setError('Could not load your workspaces.');return}
    const allowed=data.flatMap(row=>row.workspace?[{...row.workspace,role:row.role}]:[])
    const preferredId=preferredSelection.current
    preferredSelection.current=null
    setWorkspaces(allowed)
    setSelected(previous=>{
      const wanted=preferredId||previous
      return allowed.some(space=>space.id===wanted)?wanted:allowed[0]?.id||''
    })
    setError('')
  },[user])

  useEffect(()=>{
    const refresh=()=>void reload()
    refresh()
    const reconnect=onReconnect(refresh)
    const timer=window.setInterval(()=>{if(document.visibilityState==='visible')refresh()},12000)
    return()=>{++requestVersion.current;reconnect();window.clearInterval(timer)}
  },[reload])

  const active=workspaces?.find(space=>space.id===selected)||null
  const activeId=active?.id
  const noMemberships=workspaces?.length===0
  useEffect(()=>{
    try{
      if(activeId)localStorage.setItem(key,activeId)
      else if(noMemberships)localStorage.removeItem(key)
    }catch{/* Organization switching still works without browser storage. */}
  },[key,activeId,noMemberships])

  const select=useCallback((id:string)=>{
    if(workspaces?.some(space=>space.id===id)){
      preferredSelection.current=null
      setSelected(id)
    }
  },[workspaces])

  return <WorkspaceContext.Provider value={{workspaces,active,error,select,reload}}>{children}</WorkspaceContext.Provider>
}

export function useWorkspaceContext(){
  const value=useContext(WorkspaceContext)
  if(!value)throw new Error('Workspace context requires a signed-in account.')
  return value
}

export function WorkspaceSwitcher({onSwitch}:{onSwitch?:()=>void}={}){
  const {workspaces,active,error,select,reload}=useWorkspaceContext()
  if(error)return <div className="release-flex"><p className="error" role="alert">{error}</p>
    <button type="button" className="secondary" onClick={()=>void reload()}>Retry workspaces</button></div>
  if(!workspaces)return <p role="status">Loading workspaces…</p>
  if(!workspaces.length)return null
  return <label>Active workspace<select name="workspace" value={active?.id||''} onChange={event=>{
    select(event.target.value);onSwitch?.()
  }}>
    {workspaces.map(space=><option key={space.id} value={space.id}>{space.name}</option>)}
  </select></label>
}
