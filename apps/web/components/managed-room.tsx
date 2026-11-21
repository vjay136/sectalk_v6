'use client'

import {useCallback,useEffect,useRef,useState,type FormEvent} from 'react'
import {db} from '../lib/data'
import {useSensitiveAction} from './sensitive-action'
import {RoomPostReport} from './room-reports'

export function ManagedRoomPolicy({workspace}:{workspace:string}){
  const {authorize,confirmation}=useSensitiveAction()
  const [enabled,setEnabled]=useState<boolean|null>(null)
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)
  useEffect(()=>{
    let current=true
    void db!.rpc('st_v8_managed_room_policy',{p_workspace:workspace}).then(({data,error})=>{
      if(current&&!error&&typeof data?.enabled==='boolean')setEnabled(data.enabled)
    })
    return ()=>{current=false}
  },[workspace])
  if(enabled===null)return null
  return <section aria-label="Managed room policy">
    {confirmation}
    <p>New blank private rooms {enabled?'use':'can use'} server-managed encryption. The mode stays fixed when a room is created.</p>
    <button type="button" className="secondary" disabled={busy} aria-pressed={enabled}
      onClick={()=>void authorize('room_role',async()=>{
        setBusy(true)
        setError('')
        try{
          const {data,error}=await db!.rpc('st_v8_managed_room_policy',{p_workspace:workspace,p_enabled:!enabled})
          if(error||typeof data?.enabled!=='boolean')throw new Error()
          setEnabled(data.enabled)
        }catch{setError('Could not update managed room policy. Verify your current workspace owner access.')}
        finally{setBusy(false)}
      })}>Manage encryption for new private rooms</button>
    {error&&<p role="alert">{error}</p>}
  </section>
}

type Post={id:string;sender:string;body:string;created_at:string;revision:string}
type Cursor={before:string;id:string}
type Page={messages:Post[];next:Cursor|null}
type SearchPage=Page&{query:string}
export function ManagedRoomPosts({room,user,canPost,name}:{room:string;user:string;canPost:boolean;name:(id:string)=>string}){
  const [recent,setRecent]=useState<Page|null>(null)
  const [older,setOlder]=useState<Page|null>(null)
  const [body,setBody]=useState('')
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)
  const [query,setQuery]=useState('')
  const [search,setSearch]=useState<SearchPage|null>(null)
  const [reporting,setReporting]=useState<Post|null>(null)
  const sendId=useRef<{body:string;id:string}|null>(null)
  const accessRevision=useRef(0)
  const request=useCallback(async(options?:RequestInit,cursor?:Cursor,signal?:AbortSignal)=>{
    const revision=accessRevision.current
    const token=(await db!.auth.getSession()).data.session?.access_token
    const query=cursor?'?'+new URLSearchParams(cursor):''
    const response=await fetch('/api/managed-room/'+room+query,{...options,signal,
      headers:{Authorization:'Bearer '+token,...options?.headers}})
    if(!response.ok){
      if([401,403,404,423].includes(response.status)){
        accessRevision.current++
        setRecent(null)
        setOlder(null)
        setSearch(null)
        setReporting(null)
      }
      const payload=await response.json().catch(()=>null)
      throw new Error(payload?.error||'Managed room unavailable.')
    }
    if(revision!==accessRevision.current)throw new Error('Room access changed.')
    return response
  },[room])
  const refresh=useCallback(async(signal?:AbortSignal)=>{
    try{
      const page=await (await request(undefined,undefined,signal)).json() as Page
      if(!signal?.aborted)setRecent(page)
    }catch(error){if(!signal?.aborted)setError(error instanceof Error?error.message:'Could not read messages.')}
  },[request])
  useEffect(()=>{
    const controller=new AbortController()
    void refresh(controller.signal)
    const timer=window.setInterval(()=>void refresh(controller.signal),10000)
    return ()=>{controller.abort();window.clearInterval(timer)}
  },[refresh])
  async function send(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    if(!body.trim()||busy)return
    const id=sendId.current?.body===body?sendId.current.id:crypto.randomUUID()
    sendId.current={body,id}
    setBusy(true)
    setError('')
    try{
      await request({method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id,body})})
      setBody('')
      sendId.current=null
      await refresh()
    }catch(error){setError(error instanceof Error?error.message:'Could not send the message.')}
    finally{setBusy(false)}
  }
  async function searchMessages(older=false){
    const value=older?search?.query:query.trim()
    const cursor=older?search?.next:null
    if(!value||value.length<2||busy||(older&&!cursor))return
    setBusy(true)
    setError('')
    try{
      const page=await (await request({method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({action:'search',query:value,...cursor})})).json() as Page
      setSearch({query:value,next:page.next,
        messages:[...(older?search?.messages??[]:[]),...page.messages]})
    }catch(error){setError(error instanceof Error?error.message:'Could not search this room.')}
    finally{setBusy(false)}
  }
  const pages=[...(recent?.messages??[]),...(older?.messages??[])]
  const posts=[...new Map(pages.map(post=>[post.id,post])).values()].reverse()
  const next=older?older.next:recent?.next
  const renderMessage=(post:Post)=><article key={post.id} className="release-row">
    <strong>{name(post.sender)}</strong>
    <p style={{whiteSpace:'pre-wrap',overflowWrap:'anywhere'}}>{post.body}</p>
    <time dateTime={post.created_at}>{new Date(post.created_at).toLocaleString()}</time>
    {post.sender!==user&&<button type="button" className="secondary" onClick={()=>setReporting(post)}>Report managed message</button>}
  </article>
  return <section aria-label="Managed room messages">
    <details>
      <summary>Search room messages</summary>
      <form className="release-form" onSubmit={event=>{event.preventDefault();void searchMessages()}}>
        <label>Search this managed room<input type="search" value={query} minLength={2} maxLength={120} required
          disabled={busy} onChange={event=>{setQuery(event.target.value);setSearch(null)}}/></label>
        <button type="submit" className="secondary" disabled={busy||query.trim().length<2}>Find messages</button>
      </form>
      {search&&<section aria-label="Managed room search results">
        {!search.messages.length&&<p>{search.next?'No matches so far.':'No matching messages.'}</p>}
        {search.messages.map(renderMessage)}
        {search.next&&<button type="button" className="secondary" disabled={busy}
          onClick={()=>void searchMessages(true)}>Search older messages</button>}
      </section>}
    </details>
    {!recent&&!error&&<p role="status">Loading messages…</p>}
    {recent&&!posts.length&&<p>No messages yet.</p>}
    {next&&<button type="button" disabled={busy} onClick={()=>void (async()=>{
      setBusy(true)
      setError('')
      try {
        const page=await (await request(undefined,next)).json() as Page
        setOlder({messages:[...(older?.messages??[]),...page.messages],next:page.next})
      }catch(error){setError(error instanceof Error?error.message:'Could not load older messages.')}
      finally{setBusy(false)}
    })()}>Load older messages</button>}
    {posts.map(renderMessage)}
    {reporting&&<div>
      <blockquote>{reporting.body}</blockquote>
      <RoomPostReport key={reporting.id} room={room} post={reporting.id} revision={reporting.revision}
        close={()=>setReporting(null)}/>
    </div>}
    {canPost&&<form onSubmit={send} className="release-form">
      <label>Managed room message<textarea value={body} maxLength={4000} required onChange={event=>setBody(event.target.value)}/></label>
      <button type="submit" disabled={busy} className="primary">Send managed message</button>
    </form>}
    {error&&<p role="alert">{error}</p>}
  </section>
}
