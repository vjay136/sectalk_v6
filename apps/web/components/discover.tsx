'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { Bell, Check, Search } from 'lucide-react'
import { db, liveChannel, onReconnect } from '../lib/data'
import { SectionTabs } from './section-tabs'

type Result = { kind:'direct'|'channel'|'board'|'meeting'; id:string; scope_id:string; title:string; snippet:string; at:string }
type Notification = { id:number; kind:string; meeting_id:string; created_at:string; read_at:string|null }
const notificationText:Record<string,string>={'meeting.scheduled':'A workspace meeting was scheduled','meeting.admitted':'The host admitted you to a meeting','meeting.declined':'A host declined your meeting request'}

export function GlobalSearch({ openChat,openMeeting }: { openChat:(id:string)=>void;openMeeting:(id:string)=>void }) {
  const [results,setResults]=useState<Result[]|null>(null)
  const [kind,setKind]=useState<Result['kind']|'all'>('all')
  const [loading,setLoading]=useState(false)
  const [error,setError]=useState('')
  async function search(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const values=new FormData(event.currentTarget)
    setLoading(true);setError('')
    try {
      const {data,error}=await db!.rpc('st_v3_search',{p_query:values.get('query'),p_kind:kind==='all'?null:kind})
      if(error) throw error
      const rows=data as Result[]
      const ids=rows.filter(row=>row.kind==='direct').map(row=>row.id)
      if(!ids.length){setResults(rows);return}
      const [hidden,removed]=await Promise.all([
        db!.from('st_v5_hidden_messages').select('message_id').in('message_id',ids),
        db!.from('st_messages').select('id').in('id',ids).not('revoked_at','is',null),
      ])
      if(hidden.error||removed.error)throw new Error('Search privacy check failed')
      const excluded=new Set([...hidden.data.map(row=>row.message_id),...removed.data.map(row=>row.id)])
      setResults(rows.filter(row=>row.kind!=='direct'||!excluded.has(row.id)))
    } catch {setError('Search is unavailable. Try again.')}
    finally {setLoading(false)}
  }
  return <section className="content-page">
    <header className="content-title"><div className="card-icon"><Search size={22}/></div><div><h1>Search</h1><p>Find messages, channel posts, board items, and meetings you can access.</p></div></header>
    <SectionTabs label="Search categories" value={kind} onChange={next=>{if(!loading){setKind(next);setResults(null);setError('')}}}
      options={ [['all','All content'],['direct','Direct messages'],['channel','Channel posts'],['board','Board items'],['meeting','Meetings']] }/>
    <form className="panel release-panel release-form" onSubmit={search}>
      <label>Search terms<input name="query" minLength={2} maxLength={120} required/></label>
      <button className="primary" disabled={loading}><Search size={16}/>{loading?'Searching…':'Search SecTalk'}</button>
    </form>
    {error&&<p role="alert" className="error">{error}</p>}
    {results?.length===0&&<p role="status">No matching items.</p>}
    {results?.map(item=><article className="panel release-panel" key={item.kind+item.id}>
      <div className="release-row"><h2>{item.title}</h2><time dateTime={item.at}>{new Date(item.at).toLocaleString()}</time></div>
      <p className="meeting-agenda">{item.snippet}</p>
      {item.kind==='meeting'&&<button className="secondary" onClick={()=>openMeeting(item.id)}>View meeting</button>}
      {item.kind==='direct'&&<button className="secondary" onClick={()=>openChat(item.scope_id)}>Open conversation</button>}
    </article>)}
  </section>
}

export function Notifications({user,openMeeting}: {user:string;openMeeting:(id:string)=>void}) {
  const [items,setItems]=useState<Notification[]|null>(null)
  const [filter,setFilter]=useState<'all'|'unread'>('all')
  const [headings,setHeadings]=useState<Record<string,string>>({})
  const [error,setError]=useState('')
  const reload=useCallback(async ()=>{
    const {data,error}=await db!.from('st_v3_notifications').select('id,kind,meeting_id,created_at,read_at').eq('recipient',user).order('id',{ascending:false}).limit(100)
    if(error){setError('Could not load notifications.');return}
    setItems(data as Notification[])
    const ids=[...new Set(data.flatMap(row=>row.meeting_id?[row.meeting_id]:[]))]
    if(ids.length){
      const result=await db!.from('st_v3_meetings').select('id,title').in('id',ids)
      if(result.data)setHeadings(Object.fromEntries(result.data.map(row=>[row.id,row.title])))
    }
    setError('')
  },[user])
  useEffect(()=>{
    void reload()
    const channel=liveChannel('notifications:'+user,reload).on('postgres_changes',{event:'*',schema:'public',table:'st_v3_notifications',filter:'recipient=eq.'+user},reload).subscribe()
    const reconnect=onReconnect(reload)
    const timer=window.setInterval(reload,10000)
    return ()=>{reconnect();window.clearInterval(timer);void db!.removeChannel(channel)}
  },[reload,user])
  async function mark(id:number|null) {
    const {error}=await db!.rpc('st_v3_mark_notification',{p_id:id})
    if(error)setError('Could not mark notifications as read.')
    else await reload()
  }
  const visible=items?.filter(item=>filter==='all'||!item.read_at)
  return <section className="content-page">
    <header className="content-title"><div className="card-icon"><Bell size={22}/></div><div><h1>Notifications</h1><p>Meeting updates from your workspaces.</p></div></header>
    {error&&<p role="alert" className="error">{error}</p>}
    <SectionTabs label="Notification filters" value={filter} onChange={setFilter} options={ [['all','All updates'], ['unread','Unread']] }/>
    <button className="secondary" disabled={!items?.some(item=>!item.read_at)} onClick={()=>void mark(null)}><Check size={15}/> Mark all read</button>
    <div className="panel release-panel">
      {items===null&&<p>Loading notifications…</p>}
      {visible?.length===0&&<p>{filter==='unread'?'You have no unread notifications.':'You have no notifications yet.'}</p>}
      {visible?.map(item=><article className="release-board-item" key={item.id}><div className="release-row">
        {!item.read_at&&<span className="status-dot" aria-label="Unread"/>}<strong>{notificationText[item.kind]||'Workspace update'}</strong>
        <time dateTime={item.created_at}>{new Date(item.created_at).toLocaleString()}</time>
      </div><p>{headings[item.meeting_id]}</p><div className="release-row">
        <button className="secondary" onClick={()=>{void mark(item.id);openMeeting(item.meeting_id)}}>View meeting</button>
        {!item.read_at&&<button className="text-button" onClick={()=>void mark(item.id)}>Mark read</button>}
      </div></article>)}
    </div>
  </section>
}
