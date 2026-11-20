'use client'

import { useEffect, useRef, useState } from 'react'
import { db } from '../lib/data'

const endpoint='/api/meetings/guests'
type GuestView={live:boolean;enabled:boolean;ticket?:string;cleanupPending?:boolean;
  links:{id:string;expires_at:string;revoked_at:string|null}[];
  visitors:{id:string;display_name:string;state:'waiting'|'approved'}[]}

async function request(meeting:string,action:string,values:Record<string,string|boolean>,signal?:AbortSignal) {
  const {data}=await db!.auth.getSession()
  const response=await fetch(endpoint,{method:'POST',signal,headers:{
    Authorization:'Bearer '+data.session?.access_token,'Content-Type':'application/json',
  },body:JSON.stringify({meeting,action,...values})})
  if (!response.ok) throw new Error('Guest access unavailable.')
  return response.json() as Promise<GuestView>
}

export function MeetingGuestHost({meeting,locked}:{meeting:string;locked:boolean}) {
  const [view,setView]=useState<GuestView|null>(null)
  const [link,setLink]=useState<{url:string;expiresAt:number}|null>(null)
  const [busy,setBusy]=useState(false)
  const [notice,setNotice]=useState('')
  const [error,setError]=useState('')
  const generation=useRef(0)
  useEffect(()=>{
    const controller=new AbortController()
    let timer:number|undefined
    async function refresh() {
      const current=++generation.current
      const result=await request(meeting,'view',{},controller.signal).catch(()=>null)
      if (!controller.signal.aborted && current===generation.current) {
        setView(result)
        if (!result?.enabled) setLink(null)
      }
    }
    void fetch(endpoint,{signal:controller.signal}).then(response=>response.json()).then(result=>{
      if (!result.configured || controller.signal.aborted) return
      void refresh()
      timer=window.setInterval(()=>void refresh(),2500)
    }).catch(()=>{})
    return ()=>{controller.abort();window.clearInterval(timer)}
  },[meeting])

  async function act(action:string,values:Record<string,string|boolean>={}) {
    if (busy) return
    setBusy(true)
    setError('')
    setNotice('')
    ++generation.current
    try {
      const result=await request(meeting,action,values)
      ++generation.current
      setView(result)
      if (result.ticket) setLink({url:new URL('/meeting-guest#'+result.ticket,location.origin).href,
        expiresAt:Date.parse(result.links[0]?.expires_at)})
      else if (action==='revoke' || !result.enabled) setLink(null)
      if (result.cleanupPending) setError('New guest admission is blocked. The media service could not confirm disconnection.')
      else if (action==='revoke') setNotice('Guest link revoked.')
    } catch { setError('The guest access change could not be completed.') }
    finally { setBusy(false) }
  }

  if (!view) return null
  const links=view.links.filter(item=>!item.revoked_at && Date.parse(item.expires_at)>Date.now())
  return <section className="release-section" aria-label="Guest access">
    <h3>Guest access</h3>
    <p>Guests request admission after verification. Each link expires in up to 10 minutes.</p>
    <button type="button" className="secondary" disabled={busy || (!view.live && !view.enabled)}
      onClick={()=>void act('policy',{enabled:!view.enabled})}>{view.enabled?'Disable guest access':'Allow guest access'}</button>
    {view.enabled && view.live && <button type="button" className="secondary" disabled={busy || locked}
      onClick={()=>void act('create')}>Create guest link</button>}
    {link && link.expiresAt>Date.now() && <label>Guest link<input value={link.url} readOnly onFocus={event=>event.target.select()}/></label>}
    {links.length>0 && <ul>
      {links.map(item=><li className="release-row" key={item.id}>
        <span>Expires {new Date(item.expires_at).toLocaleTimeString([], {hour:'numeric',minute:'2-digit'})}</span>
        <button type="button" className="secondary" disabled={busy} onClick={()=>void act('revoke',{link:item.id})}>Revoke guest link</button>
      </li>)}
    </ul>}
    {view.visitors.length>0 && <ul aria-label="Guest lobby">
      {view.visitors.map(visitor=><li className="release-row" key={visitor.id}>
        <strong>{visitor.display_name}</strong><span>{visitor.state==='waiting'?'Waiting':'Approved'}</span>
        {visitor.state==='waiting' && <button type="button" className="primary" disabled={busy || locked}
          onClick={()=>void act('approve',{visitor:visitor.id})}>Admit guest</button>}
        <button type="button" className="secondary" disabled={busy}
          onClick={()=>void act('deny',{visitor:visitor.id})}>{visitor.state==='waiting'?'Decline guest':'Remove guest'}</button>
      </li>)}
    </ul>}
    {notice && <p role="status">{notice}</p>}
    {error && <p role="alert">{error}</p>}
  </section>
}
