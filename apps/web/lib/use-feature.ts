'use client'

import { useEffect, useState } from 'react'
import { db, onReconnect } from './data'

export type Feature='task_creation'|'recurring_meetings'|'integration_api'

export function useFeature(feature:Feature,workspace:string|null,needed=true){
  const [result,setResult]=useState<{key:string;value:boolean}|null>(null)
  const key=feature+':'+(workspace||'')

  useEffect(()=>{
    if(!needed)return
    let active=true
    let generation=0
    const reload=async()=>{
      const request=++generation
      const response=await db!.rpc('st_v6_feature_available',{p_feature:feature,p_workspace:workspace})
      if(active&&request===generation)setResult({key,value:!response.error&&response.data===true})
    }
    void reload()
    const stop=onReconnect(reload)
    const timer=window.setInterval(()=>{if(document.visibilityState==='visible')void reload()},12000)
    return()=>{active=false;stop();window.clearInterval(timer)}
  },[feature,key,needed,workspace])

  return needed&&result?.key===key?result.value:null
}
