'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { db, formatError, liveChannel, onReconnect, type Profile } from '../lib/data'
import { SectionTabs } from './section-tabs'
import { ScopedTasks } from './scoped-tasks'

type Kind='public'|'private'|'admin'|'announcement'|'broadcast'
type Role='owner'|'moderator'|'member'|'guest'|'read_only'
type Room={id:string;name:string;kind:Kind;template:Template;archived:boolean;locked:boolean;slow_seconds:number}
type Post={id:string;sender:string;body:string;kind:'message'|'announcement';created_at:string}
type Roster={user_id:string;role:Role}
type Entry={user_id:string;kind:'invite'|'request';invited_role:Role;expires_at:string}
type Audit={id:number;actor:string;action:string;target:string|null;occurred_at:string}
type ThreadState={post_id:string;replies:number;following:boolean;excerpt:string}
type DirectoryProps={space:string;user:string;manager:boolean;profiles:Record<string,Profile>;workspaceAdminIds:string[]}
const kinds:Record<Kind,string>={public:'Workspace-wide',private:'Private',admin:'Admins only',announcement:'Announcements',broadcast:'Broadcast'}
const templates={
  blank:{name:'Blank room',kinds:['public','private','admin','announcement','broadcast'],description:''},
  class:{name:'Class',kinds:['private'],description:'Requires room admission and starts with a 15-second posting interval for members. Pins guidance for lessons and assignments.'},
  incident:{name:'Incident',kinds:['admin'],description:'Workspace owners and admins can access this room. Pins a response guide for roles, status, and incident timelines.'},
  family:{name:'Family',kinds:['private'],description:'Requires room admission. Pins guidance for household plans and sharing personal details.'},
  project:{name:'Project',kinds:['public','private'],description:'Starts workspace-wide or can require room admission. Pins prompts for goals, ownership, and milestones.'},
} as const
type Template=keyof typeof templates
const roleLabel=(value:string)=>value.replaceAll('_',' ')

async function call(name:string,input:Record<string,unknown>) {
  const result=await db!.rpc(name,input)
  if(result.error)throw result.error
  return result.data
}

export function RoomDirectory({space,user,manager,profiles,workspaceAdminIds}:DirectoryProps) {
  const [rooms,setRooms]=useState<Room[]|null>(null)
  const [selected,setSelected]=useState('')
  const [filter,setFilter]=useState<'active'|'archived'>('active')
  const [template,setTemplate]=useState<Template>('blank')
  const [kind,setKind]=useState<Kind>('public')
  const [error,setError]=useState('')
  const [notice,setNotice]=useState('')
  const [working,setWorking]=useState(false)
  const [creating,setCreating]=useState(false)
  const newId=useRef<{key:string;id:string}|null>(null)
  const refresh=useCallback(async()=>{
    const {data,error}=await db!.from('st_v6_rooms').select('id,name,kind,template,archived,locked,slow_seconds').eq('workspace_id',space).order('name')
    if(error){setError('Could not load room directory.');return}
    setRooms(data as Room[])
  },[space])
  useEffect(()=>{
    void refresh()
    const timer=window.setInterval(refresh,5000)
    const reconnect=onReconnect(refresh)
    return ()=>{window.clearInterval(timer);reconnect()}
  },[refresh])

  async function perform(run:()=>Promise<void>){
    if(working)return
    setWorking(true);setError('');setNotice('')
    try{await run();await refresh()}
    catch(error){setError(formatError(error,'Could not update rooms.'))}
    finally{setWorking(false)}
  }

  const visible=rooms?.filter(room=>room.archived===(filter==='archived'))
  const current=visible?.find(room=>room.id===selected)
  const preset=templates[template]

  return <section aria-label="Room directory">
    <h2>Room directory</h2>
    <SectionTabs label="Room directory filters" value={filter} onChange={setFilter} options={ [['active','Active rooms'],['archived','Archived rooms']] }/>
    {error&&<p role="alert" className="error">{error}</p>}
    {notice&&<p role="status">{notice}</p>}
    {!rooms&&!error&&<p role="status">Loading rooms…</p>}
    {manager&&<details open={creating} onToggle={event=>setCreating(event.currentTarget.open)}><summary>Create a room</summary>
      <form className="release-form" onSubmit={event=>{
        event.preventDefault()
        const values=new FormData(event.currentTarget)
        void perform(async()=>{
          const input={p_workspace:space,p_name:values.get('name'),p_kind:kind,p_template:template}
          const key=JSON.stringify(input)
          if(newId.current?.key!==key)newId.current={key,id:crypto.randomUUID()}
          const id=await call('st_v6_room_create',{...input,p_id:newId.current.id})
          newId.current=null
          setFilter('active');setSelected(id);setCreating(false)
        })
      }}>
        <label>Room name<input name="name" required maxLength={64}/></label>
        <label>Room template<select name="template" value={template} onChange={event=>{
          const next=event.target.value as Template
          setTemplate(next);setKind(templates[next].kinds[0])
        }}>
          {Object.entries(templates).map(([id,entry])=><option key={id} value={id}>{entry.name}</option>)}
        </select></label>
        {preset.description&&<p aria-live="polite">{preset.description}</p>}
        <label>Room type<select value={kind} onChange={event=>setKind(event.target.value as Kind)}>
          {preset.kinds.map(option=><option key={option} value={option}>{kinds[option]}</option>)}
        </select></label>
        <button className="primary" disabled={working}>Create room</button>
      </form>
    </details>}
    <details><summary>Request access with a room code</summary>
      <form className="release-form" onSubmit={event=>{
        event.preventDefault()
        const values=new FormData(event.currentTarget)
        void perform(async()=>{
          await call('st_v6_room_membership',{p_room:values.get('code'),p_action:'request'})
          setNotice('Access request submitted. Approved rooms appear here.')
        })
      }}>
        <label>Room code<input name="code" required pattern="[0-9a-fA-F\-]{36}" maxLength={36}/></label>
        <button className="secondary" disabled={working}>Request access</button>
      </form>
    </details>
    {visible?.length===0&&<p>No rooms in this view.</p>}
    {visible?.map(room=><button className={selected===room.id?'primary':'secondary'} type="button" key={room.id}
      aria-pressed={selected===room.id} onClick={()=>setSelected(room.id)}>{room.name} <small>{kinds[room.kind]}</small></button>)}
    {current&&<RoomPanel key={current.id} room={current} user={user} profiles={profiles}
      workspaceAdminIds={workspaceAdminIds} refreshDirectory={refresh}/>}
  </section>
}

function RoomPanel({room,user,profiles,refreshDirectory,workspaceAdminIds}: {
  room:Room;user:string;profiles:Record<string,Profile>;refreshDirectory:()=>Promise<void>;workspaceAdminIds:string[]
}) {
  const [role,setRole]=useState<Role|null|undefined>(undefined)
  const [entries,setEntries]=useState<Entry[]>([])
  const [roster,setRoster]=useState<Roster[]>([])
  const [notes,setNotes]=useState<Audit[]>([])
  const [pins,setPins]=useState<Post[]>([])
  const [bans,setBans]=useState<string[]>([])
  const [posts,setPosts]=useState<Post[]>([])
  const [thread,setThread]=useState<string|null>(null)
  const activeThread=useRef<string|null>(null)
  const [threadStates,setThreadStates]=useState<ThreadState[]>([])
  const [threadRoot,setThreadRoot]=useState<Post|null>(null)
  const [view,setView]=useState<'messages'|'threads'|'pins'|'people'|'settings'|'audit'|'tasks'>('messages')
  const [taskSource,setTaskSource]=useState<string|null>(null)
  const [error,setError]=useState('')
  const [notice,setNotice]=useState('')
  const [working,setWorking]=useState(false)
  const pending=useRef<{key:string;id:string}|null>(null)
  const staff=role==='moderator'||role==='owner'
  const canPost=role&&role!=='read_only'&&!room.archived&&(staff||(!room.locked&&!['announcement','broadcast'].includes(room.kind)))
  const refresh=useCallback(async()=>{
    const [identity,requests,members,messages,pinned,activity,blocked]=await Promise.all([
      db!.rpc('st_v6_room_my_role',{p_room:room.id}),
      db!.from('st_v6_room_entries').select('*').eq('room_id',room.id).gt('expires_at',new Date().toISOString()).limit(100),
      db!.from('st_v6_room_members').select('user_id,role').eq('room_id',room.id).limit(500),
      db!.from('st_v6_room_posts').select('id,sender,body,kind,created_at').eq('room_id',room.id)
        .is('parent_id',null).order('created_at',{ascending:false}).order('id',{ascending:false}).limit(80),
      db!.from('st_v6_room_pins').select('post_id,message:st_v6_room_posts!st_v6_room_pins_room_id_post_id_fkey(id,sender,body,kind,created_at)').eq('room_id',room.id).limit(80)
        .returns<{post_id:string;message:Post|null}[]>(),
      db!.from('st_v6_room_audit').select('*').eq('room_id',room.id).order('id',{ascending:false}).limit(50),
      db!.from('st_v6_room_bans').select('user_id').eq('room_id',room.id).limit(100),
    ])
    if([identity,requests,members,messages,pinned,activity,blocked].some(result=>result.error)){
      setError('Could not load room data.');return
    }
    setRole(identity.data as Role|null)
    setEntries((requests.data||[]) as Entry[]);setRoster((members.data||[]) as Roster[])
    const roomPosts=(messages.data||[]) as Post[]
    setPosts(roomPosts);setNotes((activity.data||[]) as Audit[])
    setBans((blocked.data||[]).map(row=>row.user_id));setPins((pinned.data||[]).flatMap(row=>row.message?[row.message]:[]))
    if(!identity.data){setThreadStates([]);return}
    const summaries=await db!.rpc('st_v6_room_thread_state',{p_room:room.id,p_roots:roomPosts.map(post=>post.id)})
    if(summaries.error)setError('Could not load thread summaries.')
    else setThreadStates(summaries.data as ThreadState[])
  },[room.id])
  const [replies,setReplies]=useState<Post[]>([])
  const refreshReplies=useCallback(async()=>{
    if(!thread)return
    const fields='id,sender,body,kind,created_at'
    const [root,replies]=await Promise.all([
      db!.from('st_v6_room_posts').select(fields).eq('room_id',room.id).eq('id',thread).is('parent_id',null).maybeSingle(),
      db!.from('st_v6_room_posts').select(fields).eq('room_id',room.id).eq('parent_id',thread).order('created_at').order('id').limit(150),
    ])
    if(activeThread.current!==thread)return
    if(root.error||replies.error)setError('Could not load thread.')
    else{setReplies(replies.data as Post[]);setThreadRoot(root.data as Post|null)}
  },[room.id,thread])
  useEffect(()=>{
    const sync=()=>{void refresh();void refreshReplies()}
    sync()
    const channel=liveChannel('v6-room:'+room.id,sync)
      .on('postgres_changes',{event:'INSERT',schema:'public',table:'st_v6_room_posts',filter:'room_id=eq.'+room.id},sync)
      .subscribe(status=>{ if(status==='SUBSCRIBED')sync() })
    const timer=window.setInterval(sync,5000)
    const reconnect=onReconnect(sync)
    return ()=>{clearInterval(timer);reconnect();void db!.removeChannel(channel)}
  },[room.id,refresh,refreshReplies])

  async function perform(run:()=>Promise<void>){
    if(working)return
    setWorking(true);setError('');setNotice('')
    try{await run();await Promise.all([refresh(),refreshReplies(),refreshDirectory()])}
    catch(error){setError(formatError(error,'Could not update the room.'))}
    finally{setWorking(false)}
  }
  function member(action:string,target?:string,nextRole?:string){
    return perform(async()=>{await call('st_v6_room_membership',{p_room:room.id,p_action:action,
      ...(target?{p_target:target}:{}),...(nextRole?{p_role:nextRole}:{})})})
  }
  function settings(action:string,values:Record<string,unknown>={}){
    return perform(async()=>{await call('st_v6_room_settings',{p_room:room.id,p_action:action,...values})})
  }
  function send(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    const form=event.currentTarget
    const values=new FormData(form)
    const parent=view==='threads'?thread:null
    const input={p_room:room.id,p_body:values.get('body'),p_kind:room.kind==='announcement'||values.has('announce')?'announcement':'message',p_parent:parent}
    void perform(async()=>{
      const key=JSON.stringify(input)
      if(pending.current?.key!==key)pending.current={key,id:crypto.randomUUID()}
      await call('st_v6_room_post',{...input,p_id:pending.current.id})
      pending.current=null;form.reset()
    })
  }
  const invite=entries.some(entry=>entry.kind==='invite'&&entry.user_id===user)
  const name=(id:string|null)=>id?profiles[id]?.name||'Workspace member':''
  const actualView=(!staff&&(view==='settings'||view==='audit'))||(role==='guest'&&view==='people')?'messages':view
  const parent=posts.find(post=>post.id===thread)||threadRoot

  function openThread(id:string){
    activeThread.current=id;setReplies([]);setThreadRoot(null);setThread(id);setView('threads')
  }
  function follow(id:string,enabled:boolean){
    return perform(async()=>{
      const collection=db!.from('st_v6_thread_follows')
      const result=enabled
        ? await collection.upsert({room_id:room.id,post_id:id},{onConflict:'room_id,post_id,user_id',ignoreDuplicates:true})
        : await collection.delete().eq('room_id',room.id).eq('post_id',id)
      if(result.error)throw result.error
    })
  }

  function renderPost(post:Post,actions:boolean) {
    const pinned=pins.some(entry=>entry.id===post.id)
    const summary=threadStates.find(entry=>entry.post_id===post.id)
    return <article className="release-board-item" key={post.id}>
      <div className="release-row"><strong>{name(post.sender)}</strong><time dateTime={post.created_at}>{new Date(post.created_at).toLocaleString()}</time>
        {post.kind==='announcement'&&<span className="pill">Announcement</span>}</div>
      <p className="meeting-agenda">{post.body}</p>
      {actions&&<div className="action-row">
        <button className="secondary" type="button" onClick={()=>openThread(post.id)}>Open thread{summary?' ('+summary.replies+')':''}</button>
        {canPost&&<button className="secondary" type="button" onClick={()=>{setTaskSource(post.id);setView('tasks')}}>Create task from message</button>}
        {staff&&!room.archived&&<button className="secondary" type="button" disabled={working} onClick={()=>void settings(pinned?'unpin':'pin',{p_post:post.id})}>
          {pinned?'Unpin':'Pin'}
        </button>}
      </div>}
    </article>
  }

  return <section className="panel release-panel" aria-label={room.name}>
    <h2>{room.name}</h2><p>{kinds[room.kind]}{room.template!=='blank'?' · '+templates[room.template].name+' template':''}{room.archived?' · Archived':room.locked?' · Locked':''}{role?' · '+roleLabel(role):''}</p>
    {error&&<p role="alert" className="error">{error}</p>}
    {notice&&<p role="status">{notice}</p>}
    {role===undefined&&!error&&<p role="status">Loading room…</p>}
    {role===null&&(invite?<div className="action-row">
      <button className="primary" type="button" disabled={working} onClick={()=>void member('accept')}>Accept room invitation</button>
      <button className="secondary" type="button" disabled={working} onClick={()=>void member('decline')}>Decline invitation</button>
    </div>:room.kind!=='private'&&<button className="primary" type="button" disabled={working} onClick={()=>void member('join')}>Join room</button>)}
    {role&&<>
      <SectionTabs label="Room tabs" value={actualView} onChange={setView} options={[
        ['messages','Messages'],['threads','Threads'],['pins','Pins'],['tasks','Tasks'],
        ...(role!=='guest'?[['people','Members'] as const]:[]),
        ...(staff?[['settings','Settings'] as const,['audit','Audit'] as const]:[]),
      ]}/>
      {actualView==='messages'&&(posts.length?posts.map(post=>renderPost(post,true)):<p>No messages yet.</p>)}
      {actualView==='threads'&&<>
        {threadStates.some(item=>item.following)&&<div className="release-section"><h3>Followed threads</h3>
          {threadStates.filter(item=>item.following).map(item=><button className="secondary" type="button" key={item.post_id}
            onClick={()=>openThread(item.post_id)}>{item.excerpt} ({item.replies})</button>)}
        </div>}
        {parent&&<>{renderPost(parent,false)}
          <button className="secondary" type="button" disabled={working}
            onClick={()=>void follow(parent.id,!threadStates.some(item=>item.post_id===parent.id&&item.following))}>
            {threadStates.some(item=>item.post_id===parent.id&&item.following)?'Unfollow thread':'Follow thread'}
          </button></>}
        {thread?replies.map(post=>renderPost(post,false)):<p>Open a thread from a message.</p>}
        {thread&&replies.length===0&&<p>No replies yet.</p>}
      </>}
      {actualView==='pins'&&(pins.length?pins.map(post=>renderPost(post,true)):<p>No pinned messages.</p>)}
      {actualView==='tasks'&&<ScopedTasks user={user} scope={{kind:'room',id:room.id}} source={taskSource}
        moderator={staff} canCreate={Boolean(canPost)} onSourceUsed={()=>setTaskSource(null)}
        people={Object.fromEntries((room.kind==='admin'?workspaceAdminIds:roster.map(row=>row.user_id))
          .filter(id=>profiles[id]).map(id=>[id,profiles[id]]))}/>}
      {canPost&&(actualView==='messages'||(actualView==='threads'&&thread&&room.kind!=='announcement'))&&
        <form className="release-form" onSubmit={send}>
          <label>{actualView==='threads'?'Write a reply':'Write a room message'}<textarea name="body" required maxLength={4000}/></label>
          {staff&&room.kind!=='announcement'&&actualView==='messages'&&<label className="task-check"><input type="checkbox" name="announce"/> Post as announcement</label>}
          <button className="primary" disabled={working}>Send</button>
        </form>}
      {actualView==='people'&&<>
        {room.kind==='admin'?<p>Workspace owners and admins have access.</p>:roster.map(person=><div className="release-row" key={person.user_id}>
          <strong>{name(person.user_id)}</strong><span className="pill">{roleLabel(person.role)}</span>
          {staff&&!room.archived&&person.user_id!==user&&person.role!=='owner'&&(role==='owner'||person.role!=='moderator')&&
            <form className="release-flex" onSubmit={event=>{
              event.preventDefault()
              const data=new FormData(event.currentTarget)
              const action=String(data.get('action'))
              if(['remove','ban'].includes(action)&&!window.confirm('Apply this room restriction?'))return
              void member(action,person.user_id,String(data.get('role')))
            }}>
              <label>Action<select name="action"><option value="role">Change role</option><option value="mute">Mute</option>
                <option value="timeout">Timeout for 15 minutes</option><option value="unmute">Restore posting</option>
                <option value="remove">Remove</option><option value="ban">Ban</option></select></label>
              <label>Role<select name="role" defaultValue={person.role}>
                {(role==='owner'?['member','guest','read_only','moderator']:['member','guest','read_only']).map(value=><option value={value} key={value}>{roleLabel(value)}</option>)}
              </select></label><button className="secondary" disabled={working}>Apply</button>
            </form>}
        </div>)}
        {staff&&!room.archived&&room.kind!=='admin'&&<>
          <form className="release-form" onSubmit={event=>{
            event.preventDefault()
            const input=new FormData(event.currentTarget)
            void member('invite',String(input.get('person')),String(input.get('role')))
          }}>
            <label>Invite workspace member<select name="person" required><option value="">Choose someone</option>
              {Object.values(profiles).filter(person=>person.id!==user&&!roster.some(row=>row.user_id===person.id)&&!bans.includes(person.id))
                .map(person=><option value={person.id} key={person.id}>{person.name} (@{person.handle})</option>)}</select></label>
            <label>Invitation role<select name="role"><option value="member">Member</option><option value="guest">Guest</option><option value="read_only">Read only</option></select></label>
            <button className="secondary" disabled={working}>Invite</button>
          </form>
          {entries.filter(entry=>entry.kind==='request').map(entry=><div className="release-row" key={entry.user_id}>
            <strong>{name(entry.user_id)} requests access</strong>
            <button className="primary" type="button" disabled={working} onClick={()=>void member('approve',entry.user_id)}>Approve</button>
            <button className="secondary" type="button" disabled={working} onClick={()=>void member('deny',entry.user_id)}>Deny</button>
          </div>)}
          {bans.map(id=><div className="release-row" key={id}><span>{name(id)} · Banned</span>
            <button className="secondary" type="button" disabled={working} onClick={()=>void member('unban',id)}>Lift ban</button></div>)}
        </>}
      </>}
      {actualView==='settings'&&<>
        <div className="action-row">
          {room.kind==='private'&&<button className="secondary" type="button" onClick={async()=>{
            try{await navigator.clipboard.writeText(room.id);setNotice('Room request code copied.')}
            catch{setNotice(room.id)}
          }}>Copy room request code</button>}
          {!room.archived&&<button className="secondary" type="button" disabled={working} onClick={()=>void settings(room.locked?'unlock':'lock')}>
            {room.locked?'Unlock room':'Lock room'}</button>}
          {role==='owner'&&<button className="secondary" type="button" disabled={working} onClick={()=>{
            if(room.archived||window.confirm('Archive this room and stop new posts?'))void settings(room.archived?'restore':'archive')
          }}>{room.archived?'Restore room':'Archive room'}</button>}
        </div>
        {!room.archived&&<form className="release-flex" onSubmit={event=>{
          event.preventDefault();void settings('slow',{p_seconds:Number(new FormData(event.currentTarget).get('seconds'))})
        }}><label>Slow mode in seconds<input key={room.slow_seconds} name="seconds" type="number" min={0} max={300} required defaultValue={room.slow_seconds}/></label>
          <button className="secondary" disabled={working}>Save slow mode</button></form>}
      </>}
      {actualView==='audit'&&(notes.length?<ol className="audit">{notes.map(note=><li key={note.id}>
        <strong>{note.action.replaceAll('.',' ')}</strong><span>{name(note.actor)} · {new Date(note.occurred_at).toLocaleString()}</span>
      </li>)}</ol>:<p>No room audit entries.</p>)}
    </>}
  </section>
}
