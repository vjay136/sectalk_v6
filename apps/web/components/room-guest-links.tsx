'use client'

import { useEffect, useState } from 'react'
import { db } from '../lib/data'

const endpoint='/api/rooms/guests'
type Link={id:string;expires_at:string}
type View={allowed:boolean;links:Link[];posts:{id:string;preview:string}[];ticket?:string;created?:string}

async function request(room:string,action:string,values:Record<string,unknown>,signal?:AbortSignal) {
  const {data}=await db!.auth.getSession()
  const response=await fetch(endpoint,{method:'POST',signal,headers:{'Content-Type':'application/json',
    Authorization:'Bearer '+data.session?.access_token},body:JSON.stringify({room,action,...values})})
  if (!response.ok) throw new Error('Guest room access unavailable.')
  return response.json() as Promise<View>
}

export function RoomGuestLinks({room,policyVersion}:{room:string;policyVersion:string}) {
  const [view,setView]=useState<View|null>(null)
  const [selected,setSelected]=useState<string[]>([])
  const [shared,setShared]=useState<{url:string;id:string}|null>(null)
  const [busy,setBusy]=useState(false)
  const [notice,setNotice]=useState('')
  useEffect(()=>{
    const controller=new AbortController()
    void fetch(endpoint,{signal:controller.signal}).then(response=>response.json()).then(async status=>{
      if (!status.configured || controller.signal.aborted) return
      const result=await request(room,'view',{},controller.signal)
      if (!controller.signal.aborted) setView(result)
    }).catch(()=>{if (!controller.signal.aborted) setView(null)})
    return ()=>controller.abort()
  },[room,policyVersion])

  async function act(action:string,values:Record<string,unknown>) {
    if (busy) return
    setBusy(true)
    setNotice('')
    try {
      const result=await request(room,action,values)
      setView(result)
      if (result.ticket && result.created) {
        setShared({url:new URL('/room-guest#'+result.ticket,location.origin).href,id:result.created})
        setSelected([])
        setNotice('Guest link created.')
      } else if (action==='revoke') {
        if (shared?.id===values.link) setShared(null)
        setNotice('Guest link revoked.')
      }
    } catch { setNotice('The guest link change could not be completed.') }
    finally { setBusy(false) }
  }

  if (!view) return null
  const links=view.links.filter(link=>Date.parse(link.expires_at)>Date.now())
  const chosen=selected.filter(id=>view.posts.some(post=>post.id===id))
  return <section className="release-section" aria-label="Room guest links">
    <h3>Room guest links</h3>
    {view.allowed ? <>
      <p>Share selected posts you authored with read-only guests. Links expire in ten minutes.</p>
      {view.posts.length>0 ? <fieldset>
        <legend>Posts to share</legend>
        {view.posts.map(post=><label className="task-check" key={post.id}>
          <input type="checkbox" checked={chosen.includes(post.id)} disabled={busy || chosen.length===10&&!chosen.includes(post.id)}
            onChange={event=>setSelected(event.target.checked ? [...chosen,post.id] : chosen.filter(id=>id!==post.id))}/>
          {post.preview}
        </label>)}
      </fieldset> : <p>Write a room post to create a guest link.</p>}
      <button type="button" className="secondary" disabled={busy || !chosen.length || links.length>=6}
        onClick={()=>void act('create',{posts:chosen})}>Create room guest link</button>
    </> : <p>Guest links require an unlocked public room with Public classification and message forwarding enabled.</p>}
    {view.allowed && shared && links.some(link=>link.id===shared.id) && <label>Room guest link
      <input readOnly value={shared.url} onFocus={event=>event.target.select()}/>
    </label>}
    {links.length>0 && <ul>{links.map(link=><li key={link.id} className="release-row">
      <span>Expires {new Date(link.expires_at).toLocaleTimeString()}</span>
      <button type="button" className="secondary" disabled={busy} onClick={()=>void act('revoke',{link:link.id})}>Revoke room guest link</button>
    </li>)}</ul>}
    {notice && <p role="status">{notice}</p>}
  </section>
}
