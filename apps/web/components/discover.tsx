'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { Bell, Check, Search, SlidersHorizontal } from 'lucide-react'
import { db, liveChannel, onReconnect } from '../lib/data'
import { SectionTabs } from './section-tabs'
import { TaskNotices } from './scoped-tasks'
import { AuditSearch, type AuditWorkspace } from './audit-search'
import { WebPushSettings } from './web-push-settings'
import { NotificationDelivery } from './notification-delivery'
import { NotificationEmailSettings } from './notification-email-settings'
import styles from './global-search.module.css'

type Result = { kind:'direct'|'channel'|'room'|'board'|'task'|'meeting'|'room_name'|'file'|'person'; id:string; scope_id:string; title:string; snippet:string; at:string }
type SearchKind=Result['kind']|'all'
type SearchFilters={room?:string;sender?:string;from?:string;until?:string;status?:string;has_file?:boolean;mentions_me?:boolean}
type SearchRequest={query:string;kind:SearchKind;filters:SearchFilters}
type SavedSearch=SearchRequest&{id:string}
type SearchRoom={id:string;name:string;workspace_id:string;workspace:{name:string}|null}
const searchOptions=[['all','All content'],['direct','Direct messages'],['channel','Channel posts'],['room','Room posts'],
  ['room_name','Rooms'],['file','Files'],['person','People'],['board','Board items'],['task','Tasks'],['meeting','Meetings']] as const
const statusOptions=[['todo','To do'],['in_progress','In progress'],['blocked','Blocked'],['done','Done'],['cancelled','Cancelled'],['scheduled','Scheduled'],['live','Live'],['ended','Ended']] as const
const searchParams=({query,kind,filters}:SearchRequest)=>{
  const {from,until,...other}=filters
  const start=from?new Date(from+'T00:00:00'):null
  const end=until?new Date(until+'T00:00:00'):null
  if(end)end.setDate(end.getDate()+1)
  return {p_query:kind==='person'?query.replace(/^@/,''):query,p_kind:kind==='all'?null:kind,
    p_filters:{...other,from:start?.toISOString(),until:end?.toISOString()}}
}
type Notification = { id:number; kind:string; meeting_id:string|null; room_id:string|null; workspace_id:string; created_at:string; read_at:string|null }
const notificationText:Record<string,string>={'meeting.scheduled':'A workspace meeting was scheduled','meeting.started':'A workspace meeting has started','meeting.admitted':'The host admitted you to a meeting','meeting.declined':'A host declined your meeting request'}
const mentionDetails:Record<string,{label:string;priority:number}>={
  'mention.user':{label:'You were mentioned directly',priority:4},
  'mention.group':{label:'Your group was mentioned',priority:3},
  'mention.here':{label:'Online room members were mentioned',priority:2},
  'mention.channel':{label:'Everyone in your room was mentioned',priority:1},
}

function highlight(text:string,terms:string) {
  if(!terms)return text
  const escaped=terms.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')
  return text.split(new RegExp('('+escaped+')','giu')).map((part,index)=>
    index%2===1?<mark key={index}>{part}</mark>:part)
}

export function GlobalSearch({ openChat,openMeeting,openRoom,openPalette,initialQuery='' }: {
  openChat:(id:string)=>void;openMeeting:(id:string)=>void;openRoom:(workspace:string,id:string)=>void;openPalette:()=>void;initialQuery?:string
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
  const searchVersion=useRef(0)
  const inputRef=useRef<HTMLInputElement>(null)
  useEffect(()=>{
    let active=true
    let version=0
    const reload=async()=>{
      const request=++version
      const [{data,error},roomResult]=await Promise.all([
        db!.rpc('st_v6_audit_workspaces'),
        db!.from('st_v6_rooms').select('id,name,workspace_id,workspace:st_v2_workspaces(name)').order('name').order('id'),
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
    const version=++searchVersion.current
    setLoading(true);setError('');setNotice('');setResults(null);setMatched(null)
    try {
      const {data,error}=await db!.rpc('st_v6_search',searchParams(request))
      if(version!==searchVersion.current)return
      if(error) throw error
      setMatched(request);setResults(data as Result[])
    } catch {
      if(version===searchVersion.current)setError('Search is unavailable. Try again.')
    } finally {
      if(version===searchVersion.current)setLoading(false)
    }
  },[])
  useEffect(()=>{
    if(initialQuery)void search({query:initialQuery,kind:'all',filters:{}})
    else if(window.matchMedia('(pointer: fine)').matches)inputRef.current?.focus({preventScroll:true})
    return ()=>{++searchVersion.current}
  },[initialQuery,search])

  const directIds=results?.filter(row=>row.kind==='direct').map(row=>row.id).sort().join(',')
  const roomPostIds=results?.filter(row=>row.kind==='room').map(row=>row.id).sort().join(',')
  const hasResults=!!results?.length
  useEffect(()=>{
    if(view!=='search'||!hasResults||!matched)return
    let active=true
    let version=0
    const refresh=async()=>{
      const request=++version
      const {data,error}=await db!.rpc('st_v6_search',searchParams(matched))
      if(!active||request!==version)return
      if(error){setResults(null);setError('Search is unavailable. Try again.');return}
      setResults(data as Result[])
    }
    const channel=directIds||roomPostIds?liveChannel('search-results:'+crypto.randomUUID(),refresh):null
    if(directIds)channel?.on('postgres_changes',{event:'UPDATE',schema:'public',table:'st_messages',filter:'id=in.('+directIds+')'},event=>{
        if(event.new.revoked_at){
          ++version
          setResults(current=>current?.filter(row=>row.kind!=='direct'||row.id!==event.new.id)||null)
        }else void refresh()
      })
    if(roomPostIds)channel?.on('postgres_changes',{event:'UPDATE',schema:'public',table:'st_v6_room_posts',
      filter:'id=in.('+roomPostIds+')'},event=>{
        if(event.new.removed_at){
          ++version
          setResults(current=>current?.filter(row=>row.kind!=='room'||row.id!==event.new.id||row.scope_id!==event.new.room_id)||null)
        }else void refresh()
      })
    channel?.subscribe(status=>{if(status==='SUBSCRIBED')void refresh()})
    const reconnect=onReconnect(refresh)
    const timer=window.setInterval(()=>{if(document.visibilityState==='visible')void refresh()},15000)
    return ()=>{active=false;clearInterval(timer);reconnect();if(channel)void db!.removeChannel(channel)}
  },[directIds,roomPostIds,hasResults,matched,view])

  const sender=filters.sender?.trim().replace(/^@/,'').toLowerCase()
  const normalizedFilters={...filters,sender:sender||undefined}
  const terms=query.trim()
  const searchTerm=kind==='person'?terms.replace(/^@/,''):terms
  const filterCount=Object.values(normalizedFilters).filter(Boolean).length
  const invalidDates=!!(filters.from&&filters.until&&filters.from>filters.until)
  const invalidSender=!!sender&&!/^[a-z0-9_]{3,24}$/.test(sender)
  const canSearch=!invalidDates&&!invalidSender&&(searchTerm.length>=2||
    (!terms&&kind!=='person'&&(kind!=='all'||filterCount>0)))

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
  return <section className={`content-page ${styles.page}`}>
    <header className="content-title"><div className="card-icon"><Search size={22}/></div><div><h1>Search</h1><p>Find messages, rooms, files, people, tasks, and meetings you can access.</p>
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
    <form className="panel release-panel release-form" onSubmit={event=>{
      event.preventDefault();if(!loading&&canSearch)void search({query:terms,kind,filters:normalizedFilters})
    }}>
      <div className={styles.lookup}>
        <label>Search terms<input ref={inputRef} type="search" name="query" maxLength={120} value={query}
          placeholder="Message, name, @handle, or file" enterKeyHint="search" onChange={event=>setQuery(event.target.value)}/></label>
        <button className="primary" disabled={loading||!canSearch}><Search size={16}/>Search SecTalk</button>
      </div>
      <div className={styles.categories}>
        <SectionTabs label="Search categories" value={kind} onChange={next=>{
          if(!loading&&next!==kind){setKind(next);setResults(null);setMatched(null);setError('')}
        }} options={searchOptions}/>
      </div>
      <details className={styles.filters}>
        <summary><SlidersHorizontal size={16} aria-hidden="true"/>Filters{filterCount>0?` (${filterCount})`:''}</summary>
        <fieldset className={`release-form search-filters ${styles.filterGrid}`}>
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
        <button type="button" className="secondary" onClick={()=>setFilters({})}>Clear filters</button>
        </fieldset>
      </details>
      {invalidSender&&<p role="alert">Enter a handle with 3 to 24 letters, numbers, or underscores.</p>}
      {invalidDates&&<p role="alert">The through date must be on or after the from date.</p>}
      <button type="button" className="text-button" disabled={editing||!canSearch} onClick={()=>void saveSearch()}>Save search</button>
    </form>
    <section aria-label="Search results" aria-busy={loading} className={styles.results}>
      {loading?<p role="status">Searching SecTalk…</p>:results===null?null:results.length===0?
        <p role="status">No matching items.</p>:<p role="status">{results.length===40?'Showing 40 matches. Refine your search for more specific results.':
          `${results.length} ${results.length===1?'match':'matches'}`}</p>}
      {results?.map(item=>{
        const room=rooms.find(candidate=>item.kind==='room'&&candidate.id===item.scope_id)
        return <article className={`panel release-panel ${styles.result}`} key={item.kind+item.scope_id+item.id}>
          <div className={styles.resultMeta}>
            <span>{searchOptions.find(([category])=>category===item.kind)?.[1]}</span>
            {item.kind!=='person'&&<time dateTime={item.at}>{new Date(item.at).toLocaleString()}</time>}
          </div>
          <h2>{highlight(item.title,matched?.query||'')}</h2>
          {item.snippet&&<p className="meeting-agenda">{highlight(item.snippet,matched?.query||'')}</p>}
          {item.kind==='meeting'&&<button className="secondary" onClick={()=>openMeeting(item.id)}>View meeting</button>}
          {(item.kind==='direct'||item.kind==='file')&&<button className="secondary" onClick={()=>openChat(item.scope_id)}>Open conversation</button>}
          {item.kind==='room_name'&&<button className="secondary" onClick={()=>openRoom(item.scope_id,item.id)}>Open room</button>}
          {room&&<button className="secondary" onClick={()=>openRoom(room.workspace_id,room.id)}>Open room</button>}
        </article>
      })}
    </section>
    </>}
  </section>
}

type DigestEntry={id:string;occurred_at:string;label:string}&(
  {kind:'call.missed';chat_id:string;video:boolean}
  |{kind:'mention.user'|'mention.group'|'mention.here'|'mention.channel';workspace_id:string;room_id:string}
)
type DigestNavigation={openRoom:(workspace:string,room:string)=>void;openChat:(id:string)=>void}

const preferenceCategories = [
  ['dm', 'Direct messages', 'New direct messages outside the open conversation.'],
  ['mention', 'Mentions', 'Room mentions addressed to you.'],
  ['thread', 'Thread replies', 'Replies in your rooms, including threads you follow.'],
  ['task', 'Task updates', 'Due and completed task notices.'],
  ['call', 'Calls', 'Incoming call prompts and updates.'],
  ['security', 'Safety and security', 'Updates to reports you filed.'],
  ['billing', 'Billing', 'Changes to your subscription.'],
  ['admin', 'Admin updates', 'New posts in workspace admin rooms.'],
] as const
type PreferenceCategory = typeof preferenceCategories[number][0]
type Preferences = Record<PreferenceCategory, boolean>

function NotificationPreferences({hints}: {hints: EventTarget}) {
  const [preferences, setPreferences] = useState<Preferences | null>(null)
  const [saving, setSaving] = useState(false)
  const [loadError, setLoadError] = useState(false)
  const [feedback, setFeedback] = useState<{message: string; error: boolean} | null>(null)
  const requestVersion = useRef(0)
  const reload = useCallback(async () => {
    const version = ++requestVersion.current
    const {data, error} = await db!.rpc('st_v6_notification_preferences')
    if (version !== requestVersion.current) return
    setLoadError(Boolean(error || !data))
    if (!error && data) setPreferences(data as Preferences)
  }, [])

  useEffect(() => {
    void reload()
    hints.addEventListener('availability', reload)
    hints.addEventListener('ready', reload)
    return () => {
      ++requestVersion.current
      hints.removeEventListener('availability', reload)
      hints.removeEventListener('ready', reload)
    }
  }, [hints, reload])

  async function save(category: PreferenceCategory, enabled: boolean) {
    if (saving) return
    setSaving(true)
    setFeedback(null)
    const {error} = await db!.rpc('st_v6_set_notification_preference', {p_category: category, p_enabled: enabled})
    if (error) setFeedback({message: 'Could not save your notification preference.', error: true})
    else {
      ++requestVersion.current
      setPreferences(current => current && {...current, [category]: enabled})
      setFeedback({message: 'Notification preference saved.', error: false})
      hints.dispatchEvent(new Event('availability'))
    }
    setSaving(false)
  }

  return <div className="panel release-panel">
    <h2>In-app alerts</h2>
    <p>Choose which live alerts appear while SecTalk is open.</p>
    <p>Direct and group mentions and due task reminders take priority over other optional alerts and follow quiet hours. Critical account notices appear even when quiet hours or alert preferences silence other alerts.</p>
    {loadError && <div className="actions"><p role="alert">Could not load your notification preferences.</p>
      <button className="secondary" onClick={() => void reload()}>Try again</button></div>}
    {!preferences && !loadError && <p role="status">Loading notification preferences…</p>}
    {preferences && <fieldset disabled={saving || loadError}>
      <legend>Alert categories</legend>
      {preferenceCategories.map(([category, label, description]) => <div className="release-board-item" key={category}>
        <label className="task-check"><input type="checkbox" checked={preferences[category]}
          aria-describedby={'notification-preference-' + category}
          onChange={event => void save(category, event.target.checked)}/> {label}</label>
        <p id={'notification-preference-' + category}>{description}</p>
      </div>)}
    </fieldset>}
    {feedback && <p role={feedback.error ? 'alert' : 'status'}>{feedback.message}</p>}
  </div>
}

function NotificationDigest({openRoom,openChat}:DigestNavigation) {
  const [days,setDays]=useState<'1'|'7'>('1')
  const [entries,setEntries]=useState<DigestEntry[]|null>(null)
  const [error,setError]=useState(false)
  const requestVersion=useRef(0)
  const reload=useCallback(async()=>{
    const version=++requestVersion.current
    setError(false)
    const result=await db!.rpc('st_v6_notification_digest',{p_days:Number(days)})
    if(version!==requestVersion.current)return
    if(result.error){setError(true);return}
    setEntries(result.data as DigestEntry[])
  },[days])

  useEffect(()=>{
    void reload()
    return ()=>{requestVersion.current++}
  },[reload])

  const calls=entries?.filter(item=>item.kind==='call.missed')
  const mentions=entries?.filter(item=>item.kind!=='call.missed')
  return <>
    <div className="release-row">
      <SectionTabs label="Digest period" value={days} onChange={next=>{if(next!==days){setEntries(null);setDays(next)}}} options={ [['1','Last 24 hours'],['7','Last 7 days']] }/>
      <button className="secondary" onClick={()=>void reload()}>Refresh digest</button>
    </div>
    {error&&<p role="alert" className="error">Could not load your digest.</p>}
    {!error&&entries===null&&<p role="status">Loading digest…</p>}
    {entries&&<div className="panel release-panel">
      <section aria-label="Missed calls">
        <h2>Missed calls</h2>
        {calls?.length===0&&<p>No missed calls in this period.</p>}
        {calls?.length===50&&<p>Showing the latest 50 missed calls.</p>}
        {calls?.map(item=><article className="release-board-item" key={item.id}>
          <div className="release-row"><strong>{item.label}</strong><DigestTime value={item.occurred_at}/></div>
          <p>Missed {item.video?'video':'audio'} call</p>
          <button className="secondary" onClick={()=>openChat(item.chat_id)}>Open conversation</button>
        </article>)}
      </section>
      <section aria-label="Mentions">
        <h2>Mentions</h2>
        {mentions?.length===0&&<p>No mentions in this period.</p>}
        {mentions?.length===50&&<p>Showing the latest 50 mentions.</p>}
        {mentions?.map(item=><article className="release-board-item" key={item.id}>
          <div className="release-row"><strong>{mentionDetails[item.kind].label}</strong><DigestTime value={item.occurred_at}/></div>
          <p>{item.label}</p>
          <button className="secondary" onClick={()=>openRoom(item.workspace_id,item.room_id)}>View room</button>
        </article>)}
      </section>
    </div>}
  </>
}

function DigestTime({value}:{value:string}) {
  return <time dateTime={value}>{new Date(value).toLocaleString()}</time>
}

export function Notifications({user,hints,openMeeting,openRoom,openChat}: DigestNavigation & {
  user:string;hints:EventTarget;openMeeting:(id:string)=>void
}) {
  const [items,setItems]=useState<Notification[]|null>(null)
  const [category,setCategory]=useState<'meetings'|'mentions'|'tasks'|'digest'|'delivery'|'preferences'>('meetings')
  const [filter,setFilter]=useState<'all'|'unread'>('all')
  const [headings,setHeadings]=useState<Record<string,string>>({})
  const [error,setError]=useState('')
  const requestVersion=useRef(0)
  const reload=useCallback(async ()=>{
    if(category!=='meetings'&&category!=='mentions')return
    const version=++requestVersion.current
    let query=db!.from('st_v3_notifications').select('id,kind,meeting_id,room_id,workspace_id,created_at,read_at').eq('recipient',user)
      .like('kind',category==='mentions'?'mention.%':'meeting.%')
    if(filter==='unread')query=query.is('read_at',null)
    const {data,error}=await query.order('id',{ascending:false}).limit(100)
    if(version!==requestVersion.current)return
    if(error){setError('Could not load notifications.');return}
    setItems(data as Notification[])
    setError('')
    if(category==='mentions'){
      const ids=[...new Set(data.flatMap(row=>row.room_id?[row.room_id]:[]))]
      if(!ids.length)return
      const result=await db!.from('st_v6_rooms').select('id,name').in('id',ids)
      if(result.data&&version===requestVersion.current)setHeadings(Object.fromEntries(result.data.map(row=>[row.id,row.name])))
    }else{
      const ids=[...new Set(data.flatMap(row=>row.meeting_id?[row.meeting_id]:[]))]
      if(!ids.length)return
      const result=await db!.from('st_v3_meetings').select('id,title').in('id',ids)
      if(result.data&&version===requestVersion.current)setHeadings(Object.fromEntries(result.data.map(row=>[row.id,row.title])))
    }
  },[category,filter,user])
  useEffect(()=>{
    if(category!=='meetings'&&category!=='mentions')return
    void reload()
    const channel=liveChannel('notifications:'+user,reload).on('postgres_changes',{event:'*',schema:'public',table:'st_v3_notifications',filter:'recipient=eq.'+user},reload).subscribe()
    const reconnect=onReconnect(reload)
    const timer=window.setInterval(reload,10000)
    return ()=>{requestVersion.current++;reconnect();window.clearInterval(timer);void db!.removeChannel(channel)}
  },[category,reload,user])
  async function mark(id:number|null) {
    const {error}=await db!.rpc('st_v3_mark_notification',{p_id:id,p_category:category==='mentions'?'mention':'meeting'})
    if(error)setError('Could not mark notifications as read.')
    else await reload()
  }
  const visible=items?.filter(item=>(category==='mentions'?Boolean(item.room_id):Boolean(item.meeting_id))
    &&(filter==='all'||!item.read_at))
  if(category==='mentions')visible?.sort((a,b)=>(mentionDetails[b.kind]?.priority||0)-(mentionDetails[a.kind]?.priority||0))
  return <section className="content-page">
    <header className="content-title"><div className="card-icon"><Bell size={22}/></div><div><h1>Notifications</h1></div></header>
    <SectionTabs label="Notification categories" value={category} onChange={next=>{if(next!==category){setItems(null);setCategory(next)}}} options={ [['meetings','Meetings'],['mentions','Mentions'],['tasks','Task updates'],['digest','Digest'],['delivery','Delivery'],['preferences','Preferences']] }/>
    {category==='preferences'?<><NotificationPreferences hints={hints}/><WebPushSettings/><NotificationEmailSettings/></>:category==='delivery'?<NotificationDelivery/>:category==='tasks'?<TaskNotices user={user}/>:category==='digest'?<NotificationDigest openRoom={openRoom} openChat={openChat}/>:<>
    {error&&<p role="alert" className="error">{error}</p>}
    <SectionTabs label="Notification filters" value={filter} onChange={setFilter} options={ [['all','All updates'], ['unread','Unread']] }/>
    <button className="secondary" disabled={!visible?.some(item=>!item.read_at)} onClick={()=>void mark(null)}><Check size={15}/> Mark all read</button>
    <div className="panel release-panel">
      {items===null&&<p>Loading notifications…</p>}
      {visible?.length===0&&<p>{filter==='unread'?'You have no unread notifications.':'You have no notifications yet.'}</p>}
      {visible?.map(item=><article className="release-board-item" key={item.id}><div className="release-row">
        {!item.read_at&&<span className="status-dot" aria-label="Unread"/>}<strong>{mentionDetails[item.kind]?.label||notificationText[item.kind]||'Workspace update'}</strong>
        <time dateTime={item.created_at}>{new Date(item.created_at).toLocaleString()}</time>
      </div>{(item.room_id||item.meeting_id)&&<p>{headings[(item.room_id||item.meeting_id)!]}</p>}<div className="release-row">
        {item.meeting_id&&<button className="secondary" onClick={()=>{void mark(item.id);openMeeting(item.meeting_id!)}}>View meeting</button>}
        {item.room_id&&<button className="secondary" onClick={()=>{void mark(item.id);openRoom(item.workspace_id,item.room_id!)}}>View room</button>}
        {!item.read_at&&<button className="text-button" onClick={()=>void mark(item.id)}>Mark read</button>}
      </div></article>)}
    </div>
    </>}
  </section>
}
