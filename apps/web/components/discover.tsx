'use client'

import { useCallback, useEffect, useState } from 'react'
import { Bell, Check, Search } from 'lucide-react'
import { db, liveChannel, onReconnect } from '../lib/data'
import { SectionTabs } from './section-tabs'
import { TaskNotices } from './scoped-tasks'
import { AuditSearch, type AuditWorkspace } from './audit-search'

type Result = { kind:'direct'|'channel'|'room'|'board'|'task'|'meeting'; id:string; scope_id:string; title:string; snippet:string; at:string }
type SearchKind=Result['kind']|'all'
type SearchFilters={room?:string;sender?:string;from?:string;until?:string;status?:string;has_file?:boolean;mentions_me?:boolean}
type SearchRequest={query:string;kind:SearchKind;filters:SearchFilters}
type SavedSearch=SearchRequest&{id:string}
type SearchRoom={id:string;name:string;workspace:{name:string}|null}
const searchOptions=[['all','All content'],['direct','Direct messages'],['channel','Channel posts'],['room','Room posts'],['board','Board items'],['task','Tasks'],['meeting','Meetings']] as const
const statusOptions=[['todo','To do'],['in_progress','In progress'],['blocked','Blocked'],['done','Done'],['cancelled','Cancelled'],['scheduled','Scheduled'],['live','Live'],['ended','Ended']] as const
const searchParams=({query,kind,filters}:SearchRequest)=>{
  const {from,until,...other}=filters
  const start=from?new Date(from+'T00:00:00'):null
  const end=until?new Date(until+'T00:00:00'):null
  if(end)end.setDate(end.getDate()+1)
  return {p_query:query,p_kind:kind==='all'?null:kind,p_filters:{...other,from:start?.toISOString(),until:end?.toISOString()}}
}
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
  const [filters,setFilters]=useState<SearchFilters>({})
  const [rooms,setRooms]=useState<SearchRoom[]>([])
  const [view,setView]=useState<'search'|'saved'|'audit'>('search')
  const [auditWorkspaces,setAuditWorkspaces]=useState<AuditWorkspace[]>([])
  const [matched,setMatched]=useState<SearchRequest|null>(null)
  const [saved,setSaved]=useState<SavedSearch[]|null>(null)
  const [loading,setLoading]=useState(false)
  const [editing,setEditing]=useState(false)
  const [error,setError]=useState('')
  const [notice,setNotice]=useState('')
  useEffect(()=>{
    let active=true
    let version=0
    const reload=async()=>{
      const request=++version
      const [{data,error},roomResult]=await Promise.all([
        db!.rpc('st_v6_audit_workspaces'),
        db!.from('st_v6_rooms').select('id,name,workspace:st_v2_workspaces(name)').order('name').order('id'),
      ])
      if(!active||request!==version)return
      const spaces=error?[]:data as AuditWorkspace[]
      setAuditWorkspaces(spaces)
      if(roomResult.data)setRooms(roomResult.data as unknown as SearchRoom[])
      if(!spaces.length)setView(previous=>previous==='audit'?'search':previous)
    }
    void reload()
    const reconnect=onReconnect(reload)
    return ()=>{active=false;reconnect()}
  },[])
  const refreshSaved=useCallback(async()=>{
    const {data,error}=await db!.from('st_v6_saved_searches').select('id,query,kind,filters').order('created_at',{ascending:false}).order('id',{ascending:false}).limit(100)
    if(error){setError('Saved searches could not be loaded.');return}
    setSaved(data as SavedSearch[])
  },[])
  useEffect(()=>{if(view==='saved')void refreshSaved()},[view,refreshSaved])
  const search=useCallback(async(request:SearchRequest)=>{
    setLoading(true);setError('');setResults(null)
    try {
      const {data,error}=await db!.rpc('st_v6_search',searchParams(request))
      if(error) throw error
      setMatched(request);setResults(data as Result[])
    } catch {setError('Search is unavailable. Try again.')}
    finally {setLoading(false)}
  },[])
  useEffect(()=>{if(initialQuery)void search({query:initialQuery,kind:'all',filters:{}})},[initialQuery,search])

  const directIds=results?.filter(row=>row.kind==='direct').map(row=>row.id).sort().join(',')
  useEffect(()=>{
    if(view!=='search'||!directIds||!matched)return
    let active=true
    let version=0
    const refresh=async()=>{
      const request=++version
      const {data,error}=await db!.rpc('st_v6_search',searchParams(matched))
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
  },[directIds,matched,view])

  const sender=filters.sender?.trim().replace(/^@/,'').toLowerCase()
  const normalizedFilters={...filters,sender:sender||undefined}
  const terms=query.trim()
  const invalidDates=!!(filters.from&&filters.until&&filters.from>filters.until)
  const invalidSender=!!sender&&!/^[a-z0-9_]{3,24}$/.test(sender)
  const canSearch=!invalidDates&&!invalidSender&&(terms.length>=2||(!terms&&(kind!=='all'||Object.values(normalizedFilters).some(Boolean))))

  function changeFilter<Key extends keyof SearchFilters>(key:Key,value:SearchFilters[Key]){
    setFilters(previous=>({...previous,[key]:value||undefined}))
  }

  async function saveSearch() {
    if(editing||!canSearch)return
    setEditing(true);setError('');setNotice('')
    try{
      const {error}=await db!.from('st_v6_saved_searches').upsert({query:terms,kind,filters:normalizedFilters},{onConflict:'user_id,query,kind,filters',ignoreDuplicates:true})
      if(error)throw error
      setNotice('Search saved.')
    }catch{setError('Could not save the search.')}
    finally{setEditing(false)}
  }
  return <section className="content-page">
    <header className="content-title"><div className="card-icon"><Search size={22}/></div><div><h1>Search</h1><p>Find messages, room and channel posts, board items, tasks, and meetings you can access.</p>
      <button className="secondary" type="button" aria-keyshortcuts="Control+K Meta+K" onClick={openPalette}>Open command palette</button>
    </div></header>
    <SectionTabs label="Search tabs" value={view} onChange={next=>{if(!loading&&!editing){setView(next);setError('');setNotice('')}}}
      options={ [['search','Search SecTalk'],['saved','Saved searches'],...(auditWorkspaces.length?[['audit','Audit logs'] as const]:[])] }/>
    {error&&<p role="alert" className="error">{error}</p>}
    {notice&&<p role="status">{notice}</p>}
    {view==='audit'?<AuditSearch workspaces={auditWorkspaces}/>:view==='saved'?<div className="panel release-panel">
      {!saved&&!error&&<p role="status">Loading your saved searches…</p>}
      {saved?.length===0&&<p>No saved searches yet.</p>}
      {saved?.map(item=><div className="release-row" key={item.id}>
        <strong>{item.query||'Filters only'}</strong><span>{[
          searchOptions.find(([category])=>category===item.kind)?.[1],
          item.filters.room&&(rooms.find(room=>room.id===item.filters.room)?.name||'Selected room'),
          item.filters.sender&&'@'+item.filters.sender,
          item.filters.from&&'From '+item.filters.from,item.filters.until&&'Through '+item.filters.until,
          statusOptions.find(([value])=>value===item.filters.status)?.[1],
          item.filters.has_file&&'Has file',item.filters.mentions_me&&'Mentions me',
        ].filter(Boolean).join(' · ')}</span>
        <button type="button" className="primary" disabled={editing} onClick={()=>{
          setQuery(item.query);setKind(item.kind);setFilters(item.filters);setView('search');void search(item)
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
      event.preventDefault();if(!loading&&canSearch)void search({query:terms,kind,filters:normalizedFilters})
    }}>
      <label>Search terms<input name="query" minLength={2} maxLength={120} value={query} onChange={event=>setQuery(event.target.value)}/></label>
      <fieldset className="release-form search-filters">
        <legend>Search filters</legend>
        <label>Room<select aria-label="Room" value={filters.room||''} onChange={event=>changeFilter('room',event.target.value)}>
          <option value="">Any room</option>
          {filters.room&&!rooms.some(room=>room.id===filters.room)&&<option value={filters.room}>Selected room</option>}
          {rooms.map(room=><option key={room.id} value={room.id}>{room.workspace?room.workspace.name+' / ':''}{room.name}</option>)}
        </select></label>
        <label>Sender handle<input value={filters.sender||''} placeholder="@handle" maxLength={25} onChange={event=>changeFilter('sender',event.target.value)}/></label>
        <label>From date<input type="date" value={filters.from||''} max={filters.until} onChange={event=>changeFilter('from',event.target.value)}/></label>
        <label>Through date<input type="date" value={filters.until||''} min={filters.from} onChange={event=>changeFilter('until',event.target.value)}/></label>
        <label>Status<select aria-label="Status" value={filters.status||''} onChange={event=>changeFilter('status',event.target.value)}>
          <option value="">Any status</option>
          {statusOptions.map(([value,label])=><option key={value} value={value}>{label}</option>)}
        </select></label>
        <label><input type="checkbox" checked={!!filters.has_file} onChange={event=>changeFilter('has_file',event.target.checked)}/> Has file</label>
        <label><input type="checkbox" checked={!!filters.mentions_me} onChange={event=>changeFilter('mentions_me',event.target.checked)}/> Mentions me</label>
        <button type="button" className="secondary" onClick={()=>{setFilters({});setKind('all')}}>Clear filters</button>
      </fieldset>
      {invalidSender&&<p role="alert">Enter a handle with 3 to 24 letters, numbers, or underscores.</p>}
      {invalidDates&&<p role="alert">The through date must be on or after the from date.</p>}
      <button className="primary" disabled={loading||!canSearch}><Search size={16}/>{loading?'Searching…':'Search SecTalk'}</button>
      <button type="button" className="secondary" disabled={editing||!canSearch} onClick={()=>void saveSearch()}>Save search</button>
    </form>
    {results?.length===0&&<p role="status">No matching items.</p>}
    {results?.map(item=><article className="panel release-panel" key={item.kind+item.scope_id+item.id}>
      <div className="release-row"><h2>{highlight(item.title,matched?.query||'')}</h2><time dateTime={item.at}>{new Date(item.at).toLocaleString()}</time></div>
      {item.snippet&&<p className="meeting-agenda">{highlight(item.snippet,matched?.query||'')}</p>}
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
