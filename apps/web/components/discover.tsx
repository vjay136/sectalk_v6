'use client'

import { useCallback, useEffect, useState } from 'react'
import { Bell, Check, Search } from 'lucide-react'
import { db, liveChannel, onReconnect } from '../lib/data'
import { SectionTabs } from './section-tabs'
import { TaskNotices } from './scoped-tasks'

type Result = { kind:'direct'|'channel'|'board'|'meeting'; id:string; scope_id:string; title:string; snippet:string; at:string }
type SearchKind=Result['kind']|'all'
type SavedSearch={id:string;query:string;kind:SearchKind}
const searchOptions=[['all','All content'],['direct','Direct messages'],['channel','Channel posts'],['board','Board items'],['meeting','Meetings']] as const
type Notification = { id:number; kind:string; meeting_id:string; created_at:string; read_at:string|null }
const notificationText:Record<string,string>={'meeting.scheduled':'A workspace meeting was scheduled','meeting.started':'A workspace meeting has started','meeting.admitted':'The host admitted you to a meeting','meeting.declined':'A host declined your meeting request'}

function highlight(text:string,terms:string) {
  if(!terms)return text
  const escaped=terms.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')
  return text.split(new RegExp('('+escaped+')','giu')).map((part,index)=>
    index%2===1?<mark key={index}>{part}</mark>:part)
}

export function GlobalSearch({ openChat,openMeeting,openPalette,initialQuery='' }: {
  openChat:(id:string)=>void;openMeeting:(id:string)=>void;openPalette:()=>void;initialQuery?:string
}) {
  const [results,setResults]=useState<Result[]|null>(null)
  const [kind,setKind]=useState<SearchKind>('all')
  const [query,setQuery]=useState(initialQuery)
  const [view,setView]=useState<'search'|'saved'>('search')
  const [matchedQuery,setMatchedQuery]=useState('')
  const [saved,setSaved]=useState<SavedSearch[]|null>(null)
  const [loading,setLoading]=useState(false)
  const [editing,setEditing]=useState(false)
  const [error,setError]=useState('')
  const [notice,setNotice]=useState('')
  const refreshSaved=useCallback(async()=>{
    const {data,error}=await db!.from('st_v6_saved_searches').select('id,query,kind').order('created_at',{ascending:false}).order('id',{ascending:false}).limit(100)
    if(error){setError('Saved searches could not be loaded.');return}
    setSaved(data as SavedSearch[])
  },[])
  useEffect(()=>{if(view==='saved')void refreshSaved()},[view,refreshSaved])
  const search=useCallback(async(terms:string,category:SearchKind)=>{
    setLoading(true);setError('');setResults(null)
    try {
      const {data,error}=await db!.rpc('st_v6_search',{p_query:terms,p_kind:category==='all'?null:category})
      if(error) throw error
      setMatchedQuery(terms.trim());setResults(data as Result[])
    } catch {setError('Search is unavailable. Try again.')}
    finally {setLoading(false)}
  },[])
  useEffect(()=>{if(initialQuery)void search(initialQuery,'all')},[initialQuery,search])

  const directIds=results?.filter(row=>row.kind==='direct').map(row=>row.id).sort().join(',')
  useEffect(()=>{
    if(view!=='search'||!directIds)return
    let active=true
    let version=0
    const refresh=async()=>{
      const request=++version
      const {data,error}=await db!.rpc('st_v6_search',{p_query:matchedQuery,p_kind:kind==='all'?null:kind})
      if(!active||request!==version)return
      if(error){setResults(null);setError('Search is unavailable. Try again.');return}
      setResults(data as Result[])
    }
    const channel=liveChannel('search-results:'+crypto.randomUUID(),refresh)
      .on('postgres_changes',{event:'UPDATE',schema:'public',table:'st_messages',filter:'id=in.('+directIds+')'},event=>{
        if(event.new.revoked_at){
          ++version
          setResults(current=>current?.filter(row=>row.kind!=='direct'||row.id!==event.new.id)||null)
        }else void refresh()
      }).subscribe(status=>{if(status==='SUBSCRIBED')void refresh()})
    const reconnect=onReconnect(refresh)
    const timer=window.setInterval(()=>{if(document.visibilityState==='visible')void refresh()},15000)
    return ()=>{active=false;clearInterval(timer);reconnect();void db!.removeChannel(channel)}
  },[directIds,kind,matchedQuery,view])

  async function saveSearch() {
    if(editing||query.trim().length<2)return
    setEditing(true);setError('');setNotice('')
    try{
      const {error}=await db!.from('st_v6_saved_searches').upsert({query:query.trim(),kind},{onConflict:'user_id,query,kind',ignoreDuplicates:true})
      if(error)throw error
      setNotice('Search saved.')
    }catch{setError('Could not save the search.')}
    finally{setEditing(false)}
  }
  return <section className="content-page">
    <header className="content-title"><div className="card-icon"><Search size={22}/></div><div><h1>Search</h1><p>Find messages, channel posts, board items, and meetings you can access.</p>
      <button className="secondary" type="button" aria-keyshortcuts="Control+K Meta+K" onClick={openPalette}>Open command palette</button>
    </div></header>
    <SectionTabs label="Search tabs" value={view} onChange={next=>{if(!loading&&!editing){setView(next);setError('');setNotice('')}}}
      options={ [['search','Search SecTalk'],['saved','Saved searches']] }/>
    {error&&<p role="alert" className="error">{error}</p>}
    {notice&&<p role="status">{notice}</p>}
    {view==='saved'?<div className="panel release-panel">
      {!saved&&!error&&<p role="status">Loading your saved searches…</p>}
      {saved?.length===0&&<p>No saved searches yet.</p>}
      {saved?.map(item=><div className="release-row" key={item.id}>
        <strong>{item.query}</strong><span>{searchOptions.find(([category])=>category===item.kind)?.[1]}</span>
        <button type="button" className="primary" disabled={editing} onClick={()=>{
          setQuery(item.query);setKind(item.kind);setView('search');setResults(null);void search(item.query,item.kind)
        }}>Run search</button>
        <button type="button" className="secondary" disabled={editing} onClick={async()=>{
          setEditing(true);setError('')
          try{
            const {error}=await db!.from('st_v6_saved_searches').delete().eq('id',item.id)
            if(error)throw error
            setSaved(previous=>previous?.filter(row=>row.id!==item.id)||null)
          }catch{setError('Could not remove the saved search.')}
          finally{setEditing(false)}
        }}>Remove</button>
      </div>)}
    </div>:<>
    <SectionTabs label="Search categories" value={kind} onChange={next=>{if(!loading){setKind(next);setResults(null);setError('')}}}
      options={searchOptions}/>
    <form className="panel release-panel release-form" onSubmit={event=>{
      event.preventDefault();if(!loading&&query.trim().length>=2)void search(query.trim(),kind)
    }}>
      <label>Search terms<input name="query" minLength={2} maxLength={120} value={query} required onChange={event=>setQuery(event.target.value)}/></label>
      <button className="primary" disabled={loading}><Search size={16}/>{loading?'Searching…':'Search SecTalk'}</button>
      <button type="button" className="secondary" disabled={editing||query.trim().length<2} onClick={()=>void saveSearch()}>Save search</button>
    </form>
    {results?.length===0&&<p role="status">No matching items.</p>}
    {results?.map(item=><article className="panel release-panel" key={item.kind+item.id}>
      <div className="release-row"><h2>{highlight(item.title,matchedQuery)}</h2><time dateTime={item.at}>{new Date(item.at).toLocaleString()}</time></div>
      <p className="meeting-agenda">{highlight(item.snippet,matchedQuery)}</p>
      {item.kind==='meeting'&&<button className="secondary" onClick={()=>openMeeting(item.id)}>View meeting</button>}
      {item.kind==='direct'&&<button className="secondary" onClick={()=>openChat(item.scope_id)}>Open conversation</button>}
    </article>)}
    </>}
  </section>
}

export function Notifications({user,openMeeting}: {user:string;openMeeting:(id:string)=>void}) {
  const [items,setItems]=useState<Notification[]|null>(null)
  const [category,setCategory]=useState<'meetings'|'tasks'>('meetings')
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
    <header className="content-title"><div className="card-icon"><Bell size={22}/></div><div><h1>Notifications</h1></div></header>
    <SectionTabs label="Notification categories" value={category} onChange={setCategory} options={ [['meetings','Meetings'],['tasks','Task updates']] }/>
    {category==='tasks'?<TaskNotices user={user}/>:<>
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
    </>}
  </section>
}
