'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { CalendarDays, ListChecks } from 'lucide-react'
import { db, formatError, liveChannel, onReconnect, type Profile } from '../lib/data'
import { SectionTabs } from './section-tabs'

export type TaskScope={kind:'chat'|'room';id:string}
type Status='todo'|'in_progress'|'blocked'|'done'|'cancelled'
type Priority='low'|'normal'|'high'|'urgent'
type Task={id:string;author_id:string;room_id:string|null;chat_id:string|null;title:string;status:Status;priority:Priority;labels:string[];due_at:string|null}
type Person={task_id:string;user_id:string;kind:'assignee'|'watcher'}
type TaskEvent={id:number;actor_id:string;action:string;detail:Record<string,unknown>;created_at:string}
type Source={available:false}|{available:true;messageId:string;snapshot:string;currentText:string;edited:boolean}
type TaskNotice={id:number;task_id:string;kind:'completed'|'due';due_at:string|null;created_at:string;read_at:string|null;task:{title:string}|null}

const statuses:Record<Status,string>={todo:'To do',in_progress:'In progress',blocked:'Blocked',done:'Done',cancelled:'Cancelled'}
const priorities:Record<Priority,string>={low:'Low',normal:'Normal',high:'High',urgent:'Urgent'}
const fields='id,author_id,room_id,chat_id,title,status,priority,labels,due_at'

async function rpc(name:string,input:Record<string,unknown>){
  const result=await db!.rpc(name,input)
  if(result.error)throw result.error
  return result.data
}

function parseLabels(value:FormDataEntryValue|null){
  return String(value||'').split(',').map(label=>label.trim()).filter(Boolean)
}

function dateValue(value:FormDataEntryValue|null){
  return value?new Date(String(value)).toISOString():null
}

export function ScopedTasks({user,scope,source,people={},moderator=false,canCreate=false,onSourceUsed}:{
  user:string;scope?:TaskScope;source?:string|null;people?:Record<string,Profile>;
  moderator?:boolean;canCreate?:boolean;onSourceUsed?:()=>void;
}){
  const [tasks,setTasks]=useState<Task[]|null>(null)
  const [relations,setRelations]=useState<Person[]>([])
  const [view,setView]=useState<'list'|'board'|'calendar'>('list')
  const [filter,setFilter]=useState<'all'|'assigned'|'watching'>('all')
  const [error,setError]=useState('')
  const [active,setActive]=useState('')
  const [busy,setBusy]=useState(false)
  const [createOpen,setCreateOpen]=useState(Boolean(source))
  const pending=useRef<{key:string;id:string}|null>(null)
  const column=scope?.kind==='chat'?'chat_id':'room_id'
  const scopeId=scope?.id

  const load=useCallback(async()=>{
    let query=db!.from('st_v6_tasks').select(fields)
    if(scopeId)query=query.eq(column,scopeId)
    const result=await query.order('created_at',{ascending:false}).order('id',{ascending:false}).limit(100).returns<Task[]>()
    if(result.error){setError('Could not load tasks.');return}
    const ids=result.data.map(task=>task.id)
    const links=ids.length?await db!.from('st_v6_task_people').select('task_id,user_id,kind').in('task_id',ids).limit(1000).returns<Person[]>():null
    if(links?.error){setError('Could not load task assignments.');return}
    setTasks(result.data);setRelations(links?.data||[])
  },[column,scopeId])

  useEffect(()=>{
    void load()
    const configuration=scopeId?{filter:column+'=eq.'+scopeId}:{}
    const subscription=liveChannel('v6-tasks:'+(scopeId||user),load)
      .on('postgres_changes',{event:'INSERT',schema:'public',table:'st_v6_tasks',...configuration},load)
      .on('postgres_changes',{event:'UPDATE',schema:'public',table:'st_v6_tasks',...configuration},load)
      .subscribe(status=>{if(status==='SUBSCRIBED')void load()})
    const timer=window.setInterval(load,6000)
    const dispose=onReconnect(load)
    return()=>{clearInterval(timer);dispose();void db!.removeChannel(subscription)}
  },[column,load,scopeId,user])

  useEffect(()=>{if(source)setCreateOpen(true)},[source])

  async function create(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    if(!scope||busy)return
    const form=event.currentTarget
    const values=new FormData(form)
    setBusy(true);setError('')
    try{
      const input={p_room:scope.kind==='room'?scope.id:null,p_chat:scope.kind==='chat'?scope.id:null,
        p_title:values.get('title'),p_source:source||null,p_due_at:dateValue(values.get('due')),
        p_priority:values.get('priority'),p_labels:parseLabels(values.get('labels'))}
      const key=JSON.stringify(input)
      if(pending.current?.key!==key)pending.current={key,id:crypto.randomUUID()}
      const id=await rpc('st_v6_task_create',{...input,p_id:pending.current.id})
      pending.current=null
      form.reset();setCreateOpen(false);onSourceUsed?.();setActive(id)
      await load()
    }catch(error){setError(formatError(error,'Could not create the task.'))}
    finally{setBusy(false)}
  }

  const visible=tasks?.filter(task=>filter==='all'||relations.some(row=>row.task_id===task.id&&row.user_id===user&&row.kind===(filter==='assigned'?'assignee':'watcher')))
  const selected=tasks?.find(task=>task.id===active)
  function row(task:Task){
    const overdue=task.due_at&&Date.parse(task.due_at)<Date.now()&&!['done','cancelled'].includes(task.status)
    return <div className="release-board-item" key={task.id}>
      <button type="button" className="text-button" onClick={()=>setActive(task.id)}>{task.title}</button>
      <div className="release-row"><span className="pill">{statuses[task.status]}</span><span className="pill">{priorities[task.priority]}</span>
        {task.due_at&&<time dateTime={task.due_at}>{new Date(task.due_at).toLocaleString()}</time>}
        {overdue&&<strong className="error">Overdue</strong>}
      </div>
      {task.labels.length>0&&<div className="release-row">{task.labels.map(label=><span className="pill" key={label}>{label}</span>)}</div>}
    </div>
  }

  return <section className="release-section" aria-label="Scoped tasks">
    <div className="content-title"><ListChecks size={20}/><h2>{scope?'Tasks':'Room and chat tasks'}</h2></div>
    <SectionTabs label="Task views" value={view} onChange={setView} options={[['list','List'],['board','Board'],['calendar','Calendar']]}/>
    <SectionTabs label="Task filters" value={filter} onChange={setFilter} options={[['all','All tasks'],['assigned','Assigned to me'],['watching','Watching']]}/>
    {canCreate&&<details open={createOpen} onToggle={event=>setCreateOpen(event.currentTarget.open)}>
      <summary>{source?'Create task from message':'Create a task'}</summary>
      <form className="release-form" onSubmit={create}>
        {source&&<p>The source is visible to participants who can still access the message.</p>}
        <label>Task title<input name="title" required maxLength={120}/></label>
        <label>Task priority<select name="priority" defaultValue="normal">{Object.entries(priorities).map(([value,label])=><option key={value} value={value}>{label}</option>)}</select></label>
        <label>Task labels<input name="labels" placeholder="Comma-separated labels" maxLength={247}/></label>
        <label>Task due date<input type="datetime-local" name="due"/></label>
        <button className="primary" disabled={busy}>Create task</button>
        {source&&<button className="secondary" type="button" onClick={()=>{onSourceUsed?.();setCreateOpen(false)}}>Cancel source task</button>}
      </form>
    </details>}
    {error&&<p role="alert" className="error">{error}</p>}
    {!tasks&&!error&&<p role="status">Loading tasks…</p>}
    {visible?.length===0&&<p>No tasks match this view.</p>}
    {view==='list'&&visible?.map(row)}
    {view==='board'&&visible&&<div className="scoped-task-board">
      {Object.entries(statuses).map(([value,label])=><section className="panel release-panel" key={value} aria-label={label}>
        <h3>{label}</h3>{visible.filter(task=>task.status===value).map(row)}
      </section>)}
    </div>}
    {view==='calendar'&&visible&&<TaskCalendar tasks={visible} renderTask={row}/>}
    {selected&&<TaskDetail key={selected.id} task={selected} user={user} people={people}
      links={relations.filter(row=>row.task_id===selected.id)} moderator={moderator} reload={load} close={()=>setActive('')}/>}
  </section>
}

function TaskCalendar({tasks,renderTask}:{tasks:Task[];renderTask:(task:Task)=>ReactNode}){
  const scheduled=tasks.filter((task):task is Task&{due_at:string}=>Boolean(task.due_at))
    .sort((a,b)=>Date.parse(a.due_at)-Date.parse(b.due_at))
  const [view,setView]=useState<'agenda'|'month'>('agenda')
  const [day,setDay]=useState(()=>scheduled[0]?new Date(scheduled[0].due_at):new Date())
  const year=day.getFullYear()
  const month=day.getMonth()
  const start=new Date(year,month,1)
  const length=new Date(year,month+1,0).getDate()
  const dueOn=(date:Date)=>scheduled.filter(task=>new Date(task.due_at).toDateString()===date.toDateString())
  const weekdays=Array.from({length:7},(_,index)=>new Date(2023,0,1+index).toLocaleDateString(undefined,{weekday:'short'}))
  const days=Array.from({length:length},(_,index)=>new Date(year,month,index+1))
  return <div className="panel release-panel">
    <h3><CalendarDays size={16}/> Task deadlines</h3>
    <SectionTabs label="Calendar layout" value={view} onChange={setView} options={[['agenda','Agenda'],['month','Month']]}/>
    {view==='agenda'?scheduled.length?scheduled.map(renderTask):<p>No scheduled deadlines.</p>:<>
      <div className="release-row">
        <button className="secondary" type="button" onClick={()=>setDay(new Date(year,month-1,1))}>Previous month</button>
        <strong aria-live="polite">{start.toLocaleDateString(undefined,{month:'long',year:'numeric'})}</strong>
        <button className="secondary" type="button" onClick={()=>setDay(new Date(year,month+1,1))}>Next month</button>
      </div>
      <div className="task-calendar-month" role="group" aria-label="Calendar month">
        {weekdays.map(name=><span className="muted" key={name}>{name}</span>)}
        {Array.from({length:start.getDay()},(_,index)=><span key={'blank-'+index} aria-hidden="true"/>)}
        {days.map(date=>{
          const count=dueOn(date).length
          return <button type="button" className="secondary" key={date.getDate()} aria-pressed={date.toDateString()===day.toDateString()}
            aria-label={date.toLocaleDateString(undefined,{dateStyle:'full'})+', '+count+' tasks'} onClick={()=>setDay(date)}>
            {date.getDate()}{count>0&&<small>{count}</small>}
          </button>
        })}
      </div>
      <h4>{day.toLocaleDateString(undefined,{dateStyle:'long'})}</h4>
      {dueOn(day).length?dueOn(day).map(renderTask):<p>No deadlines on this date.</p>}
    </>}
  </div>
}

function TaskDetail({task,user,people,links,moderator,reload,close}:{
  task:Task;user:string;people:Record<string,Profile>;links:Person[];moderator:boolean;reload:()=>Promise<void>;close:()=>void;
}){
  const [view,setView]=useState<'details'|'source'|'audit'>('details')
  const [source,setSource]=useState<Source|null|undefined>()
  const [audit,setAudit]=useState<TaskEvent[]|null>(null)
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)
  const manager=moderator||task.author_id===user
  const assigned=links.filter(row=>row.kind==='assignee')
  const watching=links.some(row=>row.user_id===user&&row.kind==='watcher')
  const terminal=['done','cancelled'].includes(task.status)
  const next=terminal?(manager?['todo']:[]):Object.keys(statuses).filter(value=>value!==task.status)

  const refreshDetail=useCallback(async()=>{
    if(view==='source'){
      const result=await db!.rpc('st_v6_task_source',{p_id:task.id})
      if(result.error){setSource(undefined);setError('Could not verify the source.')}
      else setSource(result.data as Source|null)
    }
    if(view==='audit'){
      const result=await db!.from('st_v6_task_audit').select('id,actor_id,action,detail,created_at').eq('task_id',task.id)
        .order('id',{ascending:false}).limit(100).returns<TaskEvent[]>()
      if(result.error){setAudit(null);setError('Could not load the audit trail.')}
      else setAudit(result.data)
    }
  },[task.id,view])
  useEffect(()=>{
    void refreshDetail()
    const timer=window.setInterval(refreshDetail,4000)
    return()=>clearInterval(timer)
  },[refreshDetail])

  async function action(name:string,values:Record<string,unknown>){
    if(busy)return
    setBusy(true);setError('')
    try{await rpc('st_v6_task_update',{p_id:task.id,p_action:name,...values});await reload();await refreshDetail()}
    catch(error){setError(formatError(error,'Could not update the task.'))}
    finally{setBusy(false)}
  }

  return <section className="panel release-panel" aria-label="Task details">
    <div className="panel-header"><h3>{task.title}</h3><button className="secondary" type="button" onClick={close}>Close task</button></div>
    <SectionTabs label="Task detail tabs" value={view} onChange={value=>{setError('');setView(value)}} options={[['details','Details'],['source','Source'],['audit','Audit']]}/>
    {error&&<p role="alert" className="error">{error}</p>}
    {view==='details'&&<>
      <div className="action-row"><span className="pill">{statuses[task.status]}</span>
        <button type="button" className="secondary" disabled={busy} onClick={()=>void action('watch',{p_enabled:!watching})}>{watching?'Stop watching':'Watch task'}</button></div>
      {(manager||assigned.some(row=>row.user_id===user))&&next.length>0&&<form className="release-flex" onSubmit={event=>{
        event.preventDefault();void action('status',{p_value:new FormData(event.currentTarget).get('status')})
      }}><label>New task status<select key={task.status} name="status" required>
        {next.map(value=><option value={value} key={value}>{statuses[value as Status]}</option>)}
      </select></label><button className="secondary" disabled={busy}>Change status</button></form>}
      <h4>Assignees</h4>
      {!assigned.length&&<p>No assignees yet.</p>}
      {assigned.map(row=><div className="release-row" key={row.user_id}>
        <span>{people[row.user_id]?.name||(row.user_id===user?'You':'Participant')}</span>
        {manager&&<button type="button" className="secondary" disabled={busy} onClick={()=>void action('assign',{p_person:row.user_id,p_enabled:false})}>Remove assignee</button>}
      </div>)}
      {manager&&<>
        {Object.values(people).some(person=>!assigned.some(row=>row.user_id===person.id))&&<form className="release-flex" onSubmit={event=>{
          event.preventDefault();void action('assign',{p_person:new FormData(event.currentTarget).get('person'),p_enabled:true})
        }}><label>Choose assignee<select name="person" required><option value="">Choose someone</option>
          {Object.values(people).filter(person=>!assigned.some(row=>row.user_id===person.id)).map(person=><option key={person.id} value={person.id}>{person.name}</option>)}
        </select></label><button className="secondary" disabled={busy}>Assign</button></form>}
        <form className="release-flex" onSubmit={event=>{
          event.preventDefault();void action('priority',{p_value:new FormData(event.currentTarget).get('priority')})
        }}><label>Update priority<select key={task.priority} name="priority" defaultValue={task.priority}>
          {Object.entries(priorities).map(([value,label])=><option key={value} value={value}>{label}</option>)}
        </select></label><button className="secondary" disabled={busy}>Save priority</button></form>
        <form className="release-flex" onSubmit={event=>{
          event.preventDefault();void action('labels',{p_labels:parseLabels(new FormData(event.currentTarget).get('labels'))})
        }}><label>Update labels<input key={task.labels.join(',')} name="labels" defaultValue={task.labels.join(', ')} maxLength={247}/></label>
          <button className="secondary" disabled={busy}>Save labels</button></form>
        <form className="release-flex" onSubmit={event=>{
          event.preventDefault();void action('due',{p_due_at:dateValue(new FormData(event.currentTarget).get('deadline'))})
        }}><label>Reschedule deadline<input type="datetime-local" name="deadline" required/></label>
          <button className="secondary" disabled={busy}>Save deadline</button>
          {task.due_at&&<button type="button" className="secondary" disabled={busy} onClick={()=>void action('due',{p_due_at:null})}>Clear deadline</button>}
        </form>
      </>}
    </>}
    {view==='source'&&(source===undefined?<p role="status">Checking the source…</p>:source===null?<p>This task has no source message.</p>:
      source.available?<figure><figcaption>Original message snapshot {source.edited?'· Source has changed':''}</figcaption>
        <blockquote>{source.snapshot}</blockquote>
        {source.edited&&<details><summary>Current message</summary><blockquote>{source.currentText}</blockquote></details>}
      </figure>:<p>The source message is no longer available. The task record remains.</p>)}
    {view==='audit'&&(!audit?<p role="status">Loading audit trail…</p>:<ol className="audit">{audit.map(entry=><li key={entry.id}>
      <strong>{entry.action}</strong> <span>{people[entry.actor_id]?.name||(entry.actor_id===user?'You':'Participant')}</span>
      {typeof entry.detail.to==='string'&&<span> · {entry.detail.to.replaceAll('_',' ')}</span>}
      <time dateTime={entry.created_at}>{new Date(entry.created_at).toLocaleString()}</time>
    </li>)}</ol>)}
  </section>
}

export function TaskNotices({user}: {user:string}){
  const [items,setItems]=useState<TaskNotice[]|null>(null)
  const [filter,setFilter]=useState<'all'|'unread'>('all')
  const [error,setError]=useState('')
  const load=useCallback(async()=>{
    const result=await db!.from('st_v6_task_notices').select('id,task_id,kind,due_at,created_at,read_at,task:st_v6_tasks!st_v6_task_notices_task_id_fkey(title)')
      .eq('recipient',user).order('id',{ascending:false}).limit(100).returns<TaskNotice[]>()
    if(result.error){setError('Could not load task updates.');return}
    setError('');setItems(result.data)
  },[user])
  useEffect(()=>{
    void load()
    const channel=liveChannel('task-notices:'+user,load)
      .on('postgres_changes',{event:'INSERT',schema:'public',table:'st_v6_task_notices',filter:'recipient=eq.'+user},load).subscribe()
    const timer=window.setInterval(load,8000)
    const dispose=onReconnect(load)
    return()=>{clearInterval(timer);dispose();void db!.removeChannel(channel)}
  },[load,user])
  const visible=items?.filter(item=>filter==='all'||!item.read_at)
  return <div className="panel release-panel">
    <h2>Task updates</h2>
    <SectionTabs label="Task update filters" value={filter} onChange={setFilter} options={[['all','All task updates'],['unread','Unread task updates']]}/>
    {error&&<p role="alert" className="error">{error}</p>}
    {!items&&!error&&<p role="status">Loading task updates…</p>}
    {visible?.length===0&&<p>{filter==='unread'?'No unread task updates.':'No task updates.'}</p>}
    {visible?.map(item=><div className="release-row" key={item.id}>
      {!item.read_at&&<span className="status-dot" aria-label="Unread"/>}
      <strong>{item.kind==='due'?'Task deadline reminder':'Task completed'}</strong><span>{item.task?.title||'Task'}</span>
      <time dateTime={item.created_at}>{new Date(item.created_at).toLocaleString()}</time>
      {item.due_at&&<span>Due <time dateTime={item.due_at}>{new Date(item.due_at).toLocaleString()}</time></span>}
      {!item.read_at&&<button type="button" className="secondary" onClick={async()=>{
        try{await rpc('st_v6_task_notice_read',{p_notice:item.id});await load()}
        catch{setError('Could not mark the update as read.')}
      }}>Mark read</button>}
    </div>)}
  </div>
}
