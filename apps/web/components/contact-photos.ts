'use client'

import { useEffect, useRef, useState } from 'react'
import { db } from '../lib/data'

export async function downloadProfilePhoto(user: string, signal?: AbortSignal) {
  const {data,error}=await db!.storage.from('sectalk-avatars')
    .download(user+'.jpg',{}, {signal,cache:'no-store'})
  if(error) throw error
  return data
}

type Entry = {revision: string|null; url?: string; checked: number}

// Share one authorized cache between the inbox, thread and all direct call surfaces.
// Only the open thread/call is refreshed on a timer. The remaining contacts are
// revalidated on return to the tab, with a throttle and bounded parallel requests.
export function useContactPhotos(owner: string, eligible: string[], priority: string[]) {
  const ids=[...new Set(eligible)].sort().join(',')
  const active=[...new Set(priority)].filter(id=>eligible.includes(id)).join(',')
  const cache=useRef(new Map<string,Entry>())
  const [snapshot,setSnapshot]=useState<{owner:string;urls:Record<string,string>}>()

  useEffect(()=>()=>{
    for(const entry of cache.current.values()) if(entry.url) URL.revokeObjectURL(entry.url)
    cache.current.clear()
  },[owner])

  useEffect(()=>{
    const contacts=ids?ids.split(','):[]
    const activeIds=active?active.split(','):[]
    const permitted=new Set(contacts)
    const controller=new AbortController()
    const {signal}=controller
    const entries=cache.current
    const pending=new Set<string>()
    const publish=()=>setSnapshot({owner,urls:Object.fromEntries(
      [...entries].flatMap(([id,entry])=>entry.url?[[id,entry.url]]:[])
    )})
    for(const [id,entry] of entries){
      if(permitted.has(id))continue
      if(entry.url)URL.revokeObjectURL(entry.url)
      entries.delete(id)
    }
    publish()

    const update=async(id:string,ttl:number)=>{
      const prior=entries.get(id)
      if(signal.aborted||pending.has(id)||(prior&&Date.now()-prior.checked<ttl))return
      pending.add(id)
      try {
        const {data,error}=await db!.rpc('st_v6_profile_photo_revision',{p_user:id}).abortSignal(signal)
        if(signal.aborted)return
        const revision=!error&&typeof data==='string'?data:null
        if(prior?.revision===revision&&(prior.url||!revision)){
          prior.checked=Date.now()
          return
        }
        if(prior?.url){
          URL.revokeObjectURL(prior.url)
          entries.delete(id)
          publish()
        }
        const photo=revision?await downloadProfilePhoto(id,signal):undefined
        if(signal.aborted)return
        entries.set(id,{revision,checked:Date.now(),url:photo&&URL.createObjectURL(photo)})
        if(photo)publish()
      } catch {
        if(!signal.aborted)entries.set(id,{revision:null,checked:Date.now()})
      } finally { pending.delete(id) }
    }
    let sweepRunning=false
    const sweep=async()=>{
      if(sweepRunning||document.visibilityState!=='visible')return
      sweepRunning=true
      const order=[...new Set([...activeIds,...contacts])]
      let index=0
      const worker=async()=>{
        while(!signal.aborted&&index<order.length){
          const id=order[index++]
          await update(id,activeIds.includes(id)?15000:60000)
        }
      }
      try{await Promise.all(Array.from({length:Math.min(4,order.length)},worker))}
      finally{sweepRunning=false}
    }
    void sweep()
    const timer=activeIds.length?window.setInterval(()=>{
      if(!sweepRunning&&document.visibilityState==='visible')
        for(const id of activeIds)void update(id,15000)
    },30000):undefined
    document.addEventListener('visibilitychange',sweep)
    window.addEventListener('focus',sweep)
    return ()=>{
      controller.abort()
      window.clearInterval(timer)
      document.removeEventListener('visibilitychange',sweep)
      window.removeEventListener('focus',sweep)
    }
  },[owner,ids,active])

  return (id: string) => snapshot?.owner===owner&&eligible.includes(id)?snapshot.urls[id]:undefined
}
