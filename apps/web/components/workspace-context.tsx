'use client'

import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import { db, onReconnect } from '../lib/data'
import { clearWorkspaceLink } from '../lib/workspace-link'
import { WorkspacePaymentStatus } from './workspace-payment-status'

type WorkspacePolicy={workspace_type:string;template:'standard'|'restricted';room_kinds:string[];bulk_admit:boolean;details:{label:string}|null;
  compliance:{label:string;invite_hours:number;require_domains:boolean}|null}
export type Workspace = { id:string; name:string; role:'owner'|'admin'|'member';policy:WorkspacePolicy|null;requiresSso?:boolean }
type Membership = { workspace_id:string; role:Workspace['role']; workspace:Omit<Workspace,'role'>|null }
type WorkspaceContextValue = {
  workspaces:Workspace[]|null; active:Workspace|null; error:string; workspaceLinkUnavailable:boolean
  select:(id:string)=>void; reload:(preferred?:string)=>Promise<void>
}

const WorkspaceContext=createContext<WorkspaceContextValue|null>(null)

function savedSelection(key:string){
  try{return localStorage.getItem(key)||''}catch{return ''}
}

export function WorkspaceContextProvider({user,requestedWorkspace,children}:{
  user:string;requestedWorkspace:{id:string|null}|null;children:ReactNode
}){
  const key='sectalk.workspace.v1:'+user
  const [selected,setSelected]=useState(()=>savedSelection(key))
  const [linkedWorkspace,setLinkedWorkspace]=useState(requestedWorkspace)
  const [workspaces,setWorkspaces]=useState<Workspace[]|null>(null)
  const [error,setError]=useState('')
  const requestVersion=useRef(0)
  const preferredSelection=useRef<string|null>(null)

  const reload=useCallback(async(preferred?:string)=>{
    if(preferred)preferredSelection.current=preferred
    const version=++requestVersion.current
    const pageSize=100
    const permitted=new Map<string,Workspace>()
    for(let offset=0;;offset+=pageSize){
      const {data,error}=await db!.from('st_v2_members').select('workspace_id,role,workspace:st_v2_workspaces(id,name,policy:st_v6_workspace_policy(workspace_type,template,room_kinds,bulk_admit,details:st_v6_workspace_templates(label),compliance:st_v6_compliance_profiles(label,invite_hours,require_domains)))')
        .eq('user_id',user).is('suspended_at',null).order('joined_at').order('workspace_id')
        .range(offset,offset+pageSize-1).returns<Membership[]>()
      if(version!==requestVersion.current)return
      if(error){setWorkspaces(null);setError('Could not load your workspaces.');return}
      const lockedIds=data.filter(row=>!row.workspace).map(row=>row.workspace_id)
      const shells=new Map<string,string>()
      if(lockedIds.length){
        const result=await db!.rpc('st_v8_workspace_entry_shells',{p_workspaces:lockedIds})
        if(version!==requestVersion.current)return
        if(result.error||!Array.isArray(result.data)){setWorkspaces(null);setError('Could not check workspace sign-in requirements.');return}
        for(const shell of result.data as {id:string;name:string}[])shells.set(shell.id,shell.name)
      }
      for(const row of data){
        if(row.workspace){
          permitted.set(row.workspace.id,{...row.workspace,role:row.role})
        }else{
          const name=shells.get(row.workspace_id)
          if(name)permitted.set(row.workspace_id,{id:row.workspace_id,name,role:row.role,policy:null,requiresSso:true})
        }
      }
      if(data.length<pageSize)break
    }
    const allowed=[...permitted.values()]
    const preferredId=preferredSelection.current
    preferredSelection.current=null
    if(preferredId&&permitted.has(preferredId)){
      setLinkedWorkspace(null)
      clearWorkspaceLink()
    }
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

  const active=workspaces?.find(space=>space.id===(linkedWorkspace?linkedWorkspace.id:selected))||null
  const workspaceLinkUnavailable=linkedWorkspace!==null&&workspaces!==null&&active===null
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
      setLinkedWorkspace(null)
      clearWorkspaceLink()
      setSelected(id)
    }
  },[workspaces])

  return <WorkspaceContext.Provider value={{workspaces,active,error,workspaceLinkUnavailable,select,reload}}>{children}</WorkspaceContext.Provider>
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
  return <><label>Active workspace<select name="workspace" value={active?.id||''} onChange={event=>{
    select(event.target.value);onSwitch?.()
  }}>
    {!active&&<option value="" disabled>Choose a workspace</option>}
    {workspaces.map(space=><option key={space.id} value={space.id}>{space.name}{space.requiresSso?' (SSO required)':''}</option>)}
  </select></label>{active&&!active.requiresSso&&<WorkspacePaymentStatus key={active.id} id={active.id} owner={active.role==='owner'}/>}</>
}
