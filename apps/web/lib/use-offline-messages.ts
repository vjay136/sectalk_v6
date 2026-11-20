'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { db, onReconnect } from './data'
import { queueOfflineText, readOfflineTexts, removeOfflineText, setOfflineState, type OfflineEntry, type OfflineText } from './offline-message-store'

export function useOfflineMessages(owner:string,hints:EventTarget){
  const [entries,setEntries]=useState<OfflineEntry[]>([])
  const lifecycle=useRef<AbortController|null>(null)
  const channel=useRef<BroadcastChannel|null>(null)
  const refreshNumber=useRef(0)
  const serial=useRef<Promise<unknown>>(Promise.resolve())
  const refresh=useCallback(async()=>{
    const request=++refreshNumber.current
    const current=lifecycle.current
    const items=await readOfflineTexts(owner)
    if(current&&!current.signal.aborted&&request===refreshNumber.current)setEntries(items)
  },[owner])

  const changed=useCallback(async()=>{
    channel.current?.postMessage('changed')
    await refresh()
  },[refresh])

  const drain=useCallback((reconnected=false)=>{
    const current=lifecycle.current
    if(!current||current.signal.aborted||!navigator.onLine)return
    const run=async()=>{
      const attempted=new Set<string>()
      while(!current.signal.aborted&&navigator.onLine){
        const waiting=await readOfflineTexts(owner)
        const item=waiting.find(entry=>!attempted.has(entry.id)&&
          (entry.state==='queued'||(reconnected&&entry.state==='retry')))
        if(!item)break
        const {data:{session}}=await db!.auth.getSession()
        if(current.signal.aborted||session?.user.id!==owner)break
        attempted.add(item.id)
        const response=await db!.rpc(item.reply?'st_v2_send_reply':'st_send',{
          p_chat:item.chat,p_id:item.id,p_body:item.body,...(item.reply?{p_reply:item.reply}:{}),
        }).setHeader('Authorization','Bearer '+session.access_token).abortSignal(current.signal)
        if(current.signal.aborted)break
        if(response.error){
          if(!navigator.onLine||response.status===401)break
          const transient=response.status===0||response.status===408||response.status===429||response.status>=500
          await setOfflineState(owner,item.id,transient?'retry':'failed')
        }else{
          await removeOfflineText(owner,item.id)
          hints.dispatchEvent(new MessageEvent('inbox',{data:item.chat}))
        }
        await changed()
      }
    }
    // Serialize on this device. Stable database IDs remain the deduplication boundary.
    serial.current=serial.current.then(async()=>{
      if(current.signal.aborted)return
      if(navigator.locks)await navigator.locks.request('sectalk-outbox:'+owner,{signal:current.signal},run)
      else await run()
    }).catch(()=>undefined)
  },[changed,hints,owner])

  useEffect(()=>{
    const controller=new AbortController()
    lifecycle.current=controller
    if(typeof BroadcastChannel!=='undefined'){
      channel.current=new BroadcastChannel('sectalk-outbox:'+owner)
      channel.current.onmessage=()=>{void refresh().catch(()=>undefined)}
    }
    void refresh().catch(()=>undefined)
    drain(true)
    const reconnect=onReconnect(()=>drain(true))
    return ()=>{
      controller.abort()
      channel.current?.close()
      channel.current=null
      reconnect()
    }
  },[drain,owner,refresh])

  async function enqueue(item:OfflineText){
    await queueOfflineText(owner,item)
    await changed()
    drain()
  }
  async function retry(id:string){
    await setOfflineState(owner,id,'queued')
    await changed()
    drain()
  }
  async function dismiss(id:string){
    await removeOfflineText(owner,id)
    await changed()
  }
  return {entries,enqueue,retry,dismiss}
}
