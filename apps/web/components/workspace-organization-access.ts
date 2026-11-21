'use client'

import { useEffect, useState } from 'react'
import { db, onReconnect } from '../lib/data'

type Access = 'allowed' | 'required' | 'unavailable'
export const organizationSsoMessage = 'Sign in through your workspace provider to manage organization settings.'

export function useWorkspaceOrganizationAccess(workspace: string) {
  const [status,setStatus]=useState<{workspace:string;access:Access}>()
  useEffect(()=>{
    let request:AbortController|undefined
    const reload=async()=>{
      request?.abort()
      const controller=new AbortController()
      request=controller
      const {data,error}=await db!.rpc('st_v8_workspace_organization_requires_sso',{p_workspace:workspace})
        .abortSignal(controller.signal)
      if(!controller.signal.aborted)setStatus({workspace,access:error?'unavailable':data?'required':'allowed'})
    }
    void reload()
    const reconnect=onReconnect(reload)
    const timer=window.setInterval(reload,10000)
    return()=>{request?.abort();reconnect();window.clearInterval(timer)}
  },[workspace])
  return status?.workspace===workspace?status.access:undefined
}
