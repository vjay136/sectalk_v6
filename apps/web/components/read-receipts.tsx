'use client'

import { useCallback, useEffect, useRef, useState, type RefObject } from 'react'
import { db, onReconnect } from '../lib/data'

type ReceiptSettings={personal_enabled:boolean;workspace_enabled:boolean;room_enabled:boolean}

export function useReadReceiptSettings(scope:'workspace'|'room',id:string|null) {
  const [settings,setSettings]=useState<{key:string;value:ReceiptSettings}|null>(null)
  const [saving,setSaving]=useState(false)
  const [error,setError]=useState('')
  const version=useRef(0)
  const refresh=useCallback(async()=>{
    if(!id)return
    const request=++version.current
    const result=await db!.rpc('st_v6_read_receipt_settings',scope==='workspace'?{p_workspace:id}:{p_room:id})
    if(request!==version.current)return
    const value=result.data as ReceiptSettings|null
    if(result.error||typeof value?.personal_enabled!=='boolean'){setSettings(null);return}
    setSettings(current=>current?.key===id&&current.value.personal_enabled===value.personal_enabled
      &&current.value.workspace_enabled===value.workspace_enabled&&current.value.room_enabled===value.room_enabled
      ?current:{key:id,value})
  },[scope,id])
  useEffect(()=>{
    void refresh()
    const timer=window.setInterval(refresh,5000)
    const reconnect=onReconnect(refresh)
    return ()=>{++version.current;clearInterval(timer);reconnect()}
  },[refresh])

  async function save(target:'personal'|'workspace'|'room',enabled:boolean) {
    setSaving(true);setError('')
    try{
      const input={p_enabled:enabled,...(target==='workspace'?{p_workspace:id}:target==='room'?{p_room:id}:{})}
      const result=await db!.rpc('st_v6_set_read_receipt_policy',input)
      if(result.error)throw result.error
      await refresh()
    }catch{setError('Could not update read receipt settings.')}
    finally{setSaving(false)}
  }
  return {settings:settings?.key===id?settings.value:null,saving,error,save}
}

export function useRoomReadReceipts(room:string|null,feed:RefObject<HTMLElement|null>,sharing:boolean|null,
  incoming:string[],outgoing:string[],showCounts:boolean) {
  const observedIds=incoming.join(',')
  const countIds=outgoing.join(',')
  const [result,setResult]=useState<{room:string;counts:Record<string,number>}|null>(null)
  const submitted=useRef(new Set<string>())

  useEffect(()=>{
    if(!room||sharing===null||!observedIds||!feed.current)return
    const ids=new Set(observedIds.split(','))
    const visible=new Set<string>()
    let active=true
    let timer:number|undefined
    function flush() {
      timer=undefined
      if(document.visibilityState!=='visible')return
      const batch=Array.from(visible).filter(id=>!submitted.current.has(id))
      if(!batch.length)return
      batch.forEach(id=>submitted.current.add(id))
      if(!sharing)return
      void db!.rpc('st_v6_share_room_reads',{p_room:room,p_posts:batch}).then(({error})=>{
        if(error&&active)batch.forEach(id=>submitted.current.delete(id))
      })
    }
    const schedule=()=>{
      if(timer===undefined)timer=window.setTimeout(flush,300)
    }
    const observer=new IntersectionObserver(entries=>{
      for(const entry of entries){
        const id=(entry.target as HTMLElement).dataset.roomPost
        if(!id)continue
        if(entry.isIntersecting)visible.add(id)
        else visible.delete(id)
      }
      schedule()
    })
    for(const post of feed.current.querySelectorAll<HTMLElement>('[data-room-post]')){
      if(ids.has(post.dataset.roomPost||''))observer.observe(post)
    }
    document.addEventListener('visibilitychange',schedule)
    const reconnect=onReconnect(schedule)
    return ()=>{
      active=false;clearTimeout(timer);observer.disconnect();reconnect()
      document.removeEventListener('visibilitychange',schedule)
    }
  },[room,feed,sharing,observedIds])

  useEffect(()=>{
    if(!room||!showCounts||!countIds){setResult(null);return}
    let version=0
    const refresh=async()=>{
      const request=++version
      const {data,error}=await db!.rpc('st_v6_room_read_counts',{p_room:room,p_posts:countIds.split(',')})
      if(request!==version)return
      if(error){setResult(null);return}
      const counts=Object.fromEntries((data as {post_id:string;amount:number}[]).map(row=>[row.post_id,row.amount]))
      setResult({room,counts})
    }
    void refresh()
    const timer=window.setInterval(refresh,5000)
    const reconnect=onReconnect(refresh)
    return ()=>{++version;clearInterval(timer);reconnect()}
  },[room,countIds,showCounts])

  return showCounts&&result?.room===room?result?.counts:null
}
