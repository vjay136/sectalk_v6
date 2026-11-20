'use client'

import { useEffect, useRef, useState } from 'react'

const endpoint='/api/rooms/guests'
type RoomView={name:string;posts:string[];expiresAt:string}

export function GuestRoom() {
  const [view,setView]=useState<RoomView|null>(null)
  const [closed,setClosed]=useState(false)
  const initialFragment=useRef<string|null>(null)
  useEffect(()=>{
    const controller=new AbortController()
    let timer:number | undefined
    let deadline:number | undefined
    let credential=''
    if (initialFragment.current===null) {
      initialFragment.current=location.hash.slice(1)
      if (initialFragment.current) history.replaceState(history.state,'',location.pathname)
    }
    const ticket=initialFragment.current
    function close() {
      controller.abort()
      window.clearTimeout(timer)
      window.clearTimeout(deadline)
      credential=''
      setView(null)
      setClosed(true)
    }
    async function open() {
      try {
        const response=await fetch(endpoint,{method:'POST',signal:controller.signal,headers:{
          'Content-Type':'application/json',...(credential?{Authorization:'Guest '+credential}:{}),
        },body:JSON.stringify(credential?{action:'read'}:{action:'redeem',ticket})})
        if (!response.ok) throw new Error('Guest access closed')
        const result=await response.json()
        if (controller.signal.aborted) return
        if (!credential) {
          const remaining=Date.parse(result.expiresAt)-Date.now()
          if (!Number.isFinite(remaining) || remaining<=0) { close(); return }
          deadline=window.setTimeout(close,remaining)
        }
        credential ||= result.access
        initialFragment.current=''
        setView({name:result.name,posts:result.posts,expiresAt:result.expiresAt})
        timer=window.setTimeout(()=>void open(),2500)
      } catch {
        if (!controller.signal.aborted) close()
      }
    }
    if (/^[\w-]{43}$/.test(ticket)) void open()
    else setClosed(true)
    return ()=>{controller.abort();window.clearTimeout(timer);window.clearTimeout(deadline)}
  },[])
  return <main className="content-page">
    <section className="release-section" aria-label="Guest room">
      <h1>{view?.name ?? 'Guest room'}</h1>
      {closed && <p role="status">This guest room session is closed.</p>}
      {!view && !closed && <p role="status">Checking guest room access…</p>}
      {view && <>
        <p>Read-only guest access</p>
        {view.posts.length ? <ul aria-label="Shared room posts">
          {view.posts.map((post,index)=><li key={index}><p style={{whiteSpace:'pre-wrap'}}>{post}</p></li>)}
        </ul> : <p>No shared posts are available.</p>}
      </>}
    </section>
  </main>
}
