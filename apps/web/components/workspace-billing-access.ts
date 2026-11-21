'use client'

import { useEffect, useState } from 'react'
import { db, onReconnect } from '../lib/data'
import { workspaceBillingAccess, type WorkspaceBillingAccess } from '../lib/workspace-billing-access'

export function useWorkspaceBillingAccess(workspace?:string) {
  const [status,setStatus]=useState<{workspace:string;access:WorkspaceBillingAccess}>()
  useEffect(()=>{
    if(!workspace||!db)return
    const client=db
    let request:AbortController|undefined
    const load=async()=>{
      request?.abort()
      const controller=new AbortController()
      request=controller
      const access=await workspaceBillingAccess(client,workspace,controller.signal)
      if(!controller.signal.aborted)setStatus({workspace,access})
    }
    void load()
    const reconnect=onReconnect(load)
    const refresh=window.setInterval(load,10000)
    return()=>{request?.abort();reconnect();window.clearInterval(refresh)}
  },[workspace])
  return status?.workspace===workspace?status?.access:undefined
}
