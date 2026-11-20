'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { db, formatError, liveChannel, onReconnect, type Profile } from '../lib/data'
import { SectionTabs } from './section-tabs'
import { ScopedTasks } from './scoped-tasks'
import { QuietHoursSettings } from './quiet-hours'
import { RoomPostReactions, RoomReactionSettings, useRoomReactionCounts, useWorkspaceReactionPolicy, type RoomReactionPolicy } from './room-reactions'

type Kind='public'|'private'|'admin'|'announcement'|'broadcast'
type Role='owner'|'moderator'|'member'|'guest'|'read_only'
type Room={id:string;name:string;kind:Kind;template:Template;archived:boolean;locked:boolean;slow_seconds:number}
type Post={id:string;sender:string;body:string;kind:'message'|'announcement';created_at:string;edited_at:string|null;removed_at:string|null}
type Roster={user_id:string;role:Role}
type Entry={user_id:string;kind:'invite'|'request';invited_role:Role;expires_at:string}
type Audit={id:number;actor:string;action:string;target:string|null;occurred_at:string;details:{from?:Kind;to?:Kind;previous_owners?:string[]}}
type ThreadState={post_id:string;replies:number;following:boolean;excerpt:string}
type DirectoryProps={space:string;user:string;manager:boolean;profiles:Record<string,Profile>;workspaceAdminIds:string[];allowedRoomKinds?:string[];initialRoom?:string}
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
const postFields='id,sender,body,kind,created_at,edited_at,removed_at'

async function call(name:string,input:Record<string,unknown>) {
  const result=await db!.rpc(name,input)
  if(result.error)throw result.error
  return result.data
}

export function RoomDirectory({space,user,manager,profiles,workspaceAdminIds,allowedRoomKinds,initialRoom}:DirectoryProps) {
  const reactionPolicy=useWorkspaceReactionPolicy(space)
  const [rooms,setRooms]=useState<Room[]|null>(null)
  const [selected,setSelected]=useState(initialRoom||'')
  const [selectedFilter,setFilter]=useState<'active'|'archived'|null>(null)
  const [template,setTemplate]=useState<Template>('blank')
  const [kind,setKind]=useState<Kind>()
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

  const filter=selectedFilter||(rooms?.find(room=>room.id===initialRoom)?.archived?'archived':'active')
  const visible=rooms?.filter(room=>room.archived===(filter==='archived'))
  const current=visible?.find(room=>room.id===selected)
  const preset=templates[template]
  const allowed=(option:Kind)=>!allowedRoomKinds||allowedRoomKinds.includes(option)
  const roomKinds=preset.kinds.filter(allowed) as Kind[]
  const chosenKind=kind&&roomKinds.includes(kind)?kind:roomKinds[0]
  const description=template==='project'&&!allowed('public')
    ?'Requires room admission. Pins prompts for goals, ownership, and milestones.':preset.description

  return <section aria-label="Room directory">
    <h2>Room directory</h2>
    <SectionTabs label="Room directory filters" value={filter} onChange={setFilter} options={ [['active','Active rooms'],['archived','Archived rooms']] }/>
    {error&&<p role="alert" className="error">{error}</p>}
    {notice&&<p role="status">{notice}</p>}
    {!rooms&&!error&&<p role="status">Loading rooms…</p>}
    {reactionPolicy.error&&<p role="alert" className="error">{reactionPolicy.error}</p>}
    {manager&&reactionPolicy.policy&&<RoomReactionSettings key={space} workspace={space} policy={reactionPolicy.policy} onSaved={reactionPolicy.refresh}/>}
    {manager&&<details open={creating} onToggle={event=>setCreating(event.currentTarget.open)}><summary>Create a room</summary>
      <form className="release-form" onSubmit={event=>{
        event.preventDefault()
        const values=new FormData(event.currentTarget)
        if(!chosenKind)return
        void perform(async()=>{
          const input={p_workspace:space,p_name:values.get('name'),p_kind:chosenKind,p_template:template}
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
          setTemplate(next);setKind(undefined)
        }}>
          {Object.entries(templates).filter(([,entry])=>entry.kinds.some(allowed)).map(([id,entry])=><option key={id} value={id}>{entry.name}</option>)}
        </select></label>
        {description&&<p aria-live="polite">{description}</p>}
        <label>Room type<select value={chosenKind||''} onChange={event=>setKind(event.target.value as Kind)}>
          {roomKinds.map(option=><option key={option} value={option}>{kinds[option]}</option>)}
        </select></label>
        <button className="primary" disabled={working||!chosenKind}>Create room</button>
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
      workspaceAdminIds={workspaceAdminIds} manager={manager} allowedRoomKinds={allowedRoomKinds}
      onArchiveChange={archived=>setFilter(archived?'archived':'active')}
      refreshDirectory={refresh} reactionPolicy={reactionPolicy.policy}/>}
  </section>
}

function RoomPanel({room,user,profiles,refreshDirectory,workspaceAdminIds,reactionPolicy,manager,allowedRoomKinds,onArchiveChange}: {
  room:Room;user:string;profiles:Record<string,Profile>;refreshDirectory:()=>Promise<void>;workspaceAdminIds:string[]
  reactionPolicy:RoomReactionPolicy|null;manager:boolean;allowedRoomKinds?:string[];onArchiveChange:(archived:boolean)=>void
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
  const refreshVersion=useRef(0)
  const replyVersion=useRef(0)
  const [view,setView]=useState<'messages'|'threads'|'pins'|'people'|'settings'|'audit'|'tasks'>('messages')
  const [taskSource,setTaskSource]=useState<string|null>(null)
  const [editingPost,setEditingPost]=useState<string|null>(null)
  const [quietHours,setQuietHours]=useState(false)
  const [error,setError]=useState('')
  const [notice,setNotice]=useState('')
  const [working,setWorking]=useState(false)
  const pending=useRef<{key:string;id:string}|null>(null)
  const staff=role==='moderator'||role==='owner'
  const canPost=role&&role!=='read_only'&&!room.archived&&(staff||(!room.locked&&!['announcement','broadcast'].includes(room.kind)))
  const refresh=useCallback(async()=>{
    const version=++refreshVersion.current
    const [identity,requests,members,messages,pinned,activity,blocked]=await Promise.all([
      db!.rpc('st_v6_room_my_role',{p_room:room.id}),
      db!.from('st_v6_room_entries').select('*').eq('room_id',room.id).gt('expires_at',new Date().toISOString()).limit(100),
      db!.from('st_v6_room_members').select('user_id,role').eq('room_id',room.id).limit(500),
      db!.from('st_v6_room_posts').select(postFields).eq('room_id',room.id)
        .is('parent_id',null).order('created_at',{ascending:false}).order('id',{ascending:false}).limit(80),
      db!.from('st_v6_room_pins').select(`post_id,message:st_v6_room_posts!st_v6_room_pins_room_id_post_id_fkey(${postFields})`).eq('room_id',room.id).limit(80)
        .returns<{post_id:string;message:Post|null}[]>(),
      manager?db!.rpc('st_v6_room_management_audit',{p_room:room.id})
        :db!.from('st_v6_room_audit').select('*').eq('room_id',room.id).order('id',{ascending:false}).limit(50),
      db!.from('st_v6_room_bans').select('user_id').eq('room_id',room.id).limit(100),
    ])
    if(version!==refreshVersion.current)return
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
    if(version!==refreshVersion.current)return
    if(summaries.error)setError('Could not load thread summaries.')
    else setThreadStates(summaries.data as ThreadState[])
  },[room.id,manager])
  const [replies,setReplies]=useState<Post[]>([])
  const refreshReplies=useCallback(async()=>{
    if(!thread)return
    const version=++replyVersion.current
    const [root,replies]=await Promise.all([
      db!.from('st_v6_room_posts').select(postFields).eq('room_id',room.id).eq('id',thread).is('parent_id',null).maybeSingle(),
      db!.from('st_v6_room_posts').select(postFields).eq('room_id',room.id).eq('parent_id',thread).order('created_at').order('id').limit(150),
    ])
    if(activeThread.current!==thread||version!==replyVersion.current)return
    if(root.error||replies.error)setError('Could not load thread.')
    else{setReplies(replies.data as Post[]);setThreadRoot(root.data as Post|null)}
  },[room.id,thread])
  useEffect(()=>{
    const sync=()=>{void refresh();void refreshReplies()}
    sync()
    const channel=liveChannel('v6-room:'+room.id,sync)
      .on('postgres_changes',{event:'INSERT',schema:'public',table:'st_v6_room_posts',filter:'room_id=eq.'+room.id},sync)
      .on('postgres_changes',{event:'UPDATE',schema:'public',table:'st_v6_room_posts',filter:'room_id=eq.'+room.id},sync)
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
  function manage(action:string,values:Record<string,unknown>={}){
    return perform(async()=>{await call('st_v6_manage_room',{p_room:room.id,p_action:action,...values})})
  }
  async function toggleArchive(){
    const archive=!room.archived
    if(archive&&!window.confirm('Archive this room and stop new posts?'))return
    const action=archive?'archive':'restore'
    await perform(async()=>{
      await call(manager?'st_v6_manage_room':'st_v6_room_settings',{p_room:room.id,p_action:action})
      onArchiveChange(archive)
    })
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
  const canManage=manager||staff
  const actualView=manager&&!role&&!['people','settings','audit'].includes(view)?'settings'
    :(!canManage&&(view==='settings'||view==='audit'))||(!manager&&role==='guest'&&view==='people')?'messages':view
  const nextVisibility=room.kind==='public'?'private':'public'
  const canChangeVisibility=manager&&!room.archived&&(room.kind==='public'||room.kind==='private')
    &&(room.template==='blank'||room.template==='project')&&(!allowedRoomKinds||allowedRoomKinds.includes(nextVisibility))
  const ownerCandidates=roster.filter(person=>person.role!=='owner'&&profiles[person.user_id])
  const parent=threadRoot||posts.find(post=>post.id===thread)
  const visiblePosts=actualView==='messages'?posts:actualView==='threads'?(parent?[parent,...replies]:replies):actualView==='pins'?pins:[]
  const reactions=useRoomReactionCounts(role?room.id:null,visiblePosts.filter(post=>!post.removed_at).map(post=>post.id))

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

  function updatePost(post:Post,action:'edit'|'delete'|'redact',body?:FormDataEntryValue|null){
    return perform(async()=>{
      await call('st_v6_room_post_action',{p_room:room.id,p_post:post.id,p_action:action,...(action==='edit'?{p_body:body}:{})})
      setEditingPost(null)
    })
  }

  function renderPost(post:Post,actions:boolean) {
    const pinned=pins.some(entry=>entry.id===post.id)
    const summary=threadStates.find(entry=>entry.post_id===post.id)
    const canModify=Boolean(role&&role!=='read_only'&&!room.archived&&!post.removed_at)
    const canEdit=canModify&&canPost&&post.sender===user&&Date.now()-Date.parse(post.created_at)<=86400000
    const canDelete=canModify&&post.sender===user
    const senderRole=roster.find(person=>person.user_id===post.sender)?.role
    const senderIsStaff=room.kind==='admin'?workspaceAdminIds.includes(post.sender):senderRole==='owner'||senderRole==='moderator'
    const canRedact=canModify&&staff&&post.sender!==user&&(role==='owner'||!senderIsStaff)
    return <article className="release-board-item" key={post.id}>
      <div className="release-row"><strong>{name(post.sender)}</strong><time dateTime={post.created_at}>{new Date(post.created_at).toLocaleString()}</time>
        {post.kind==='announcement'&&<span className="pill">Announcement</span>}
        {post.edited_at&&!post.removed_at&&<span className="pill">Edited</span>}</div>
      <p className={post.removed_at?'meeting-agenda revoked-message':'meeting-agenda'}>{post.body}</p>
      {!post.removed_at&&<RoomPostReactions room={room.id} post={post.id} policy={reactionPolicy}
        reactions={reactions.items[post.id]} canAdd={Boolean(canPost)} canRemove={canModify} onChange={reactions.refresh}/>}
      {editingPost===post.id&&canEdit?<form className="release-form" onSubmit={event=>{
        event.preventDefault()
        void updatePost(post,'edit',new FormData(event.currentTarget).get('editedBody'))
      }}>
        <label>Edit room message<textarea name="editedBody" required maxLength={4000} defaultValue={post.body}/></label>
        <div className="action-row">
          <button className="primary" disabled={working}>Save edit</button>
          <button className="secondary" type="button" onClick={()=>setEditingPost(null)}>Cancel edit</button>
        </div>
      </form>:(canEdit||canDelete||canRedact)&&<details>
        <summary>Room message actions</summary>
        <div className="action-row">
          {canEdit&&<button className="secondary" type="button" onClick={()=>setEditingPost(post.id)}>Edit message</button>}
          {(canDelete||canRedact)&&<button className="danger" type="button" disabled={working} onClick={()=>{
            if(window.confirm('Remove this message? Replies and follows will remain.'))void updatePost(post,canDelete?'delete':'redact')
          }}>{canDelete?'Delete message':'Redact message'}</button>}
        </div>
      </details>}
      {actions&&<div className="action-row">
        <button className="secondary" type="button" onClick={()=>openThread(post.id)}>Open thread{summary?' ('+summary.replies+')':''}</button>
        {canPost&&!post.removed_at&&<button className="secondary" type="button" onClick={()=>{setTaskSource(post.id);setView('tasks')}}>Create task from message</button>}
        {staff&&!room.archived&&(pinned||!post.removed_at)&&<button className="secondary" type="button" disabled={working} onClick={()=>void settings(pinned?'unpin':'pin',{p_post:post.id})}>
          {pinned?'Unpin':'Pin'}
        </button>}
      </div>}
    </article>
  }

  return <section className="panel release-panel" aria-label={room.name}>
    <h2>{room.name}</h2><p>{kinds[room.kind]}{room.template!=='blank'?' · '+templates[room.template].name+' template':''}{room.archived?' · Archived':room.locked?' · Locked':''}{role?' · '+roleLabel(role):''}</p>
    {role&&<div>
      <button type="button" className="secondary" aria-expanded={quietHours}
        onClick={()=>setQuietHours(!quietHours)}>Room quiet hours</button>
      {quietHours&&<QuietHoursSettings room={room.id}/>}
    </div>}
    {error&&<p role="alert" className="error">{error}</p>}
    {notice&&<p role="status">{notice}</p>}
    {role===undefined&&!error&&<p role="status">Loading room…</p>}
    {role===null&&(invite?<div className="action-row">
      <button className="primary" type="button" disabled={working} onClick={()=>void member('accept')}>Accept room invitation</button>
      <button className="secondary" type="button" disabled={working} onClick={()=>void member('decline')}>Decline invitation</button>
    </div>:!room.archived&&['public','announcement','broadcast'].includes(room.kind)&&<button className="primary" type="button" disabled={working} onClick={()=>void member('join')}>Join room</button>)}
    {(role||manager)&&<>
      <SectionTabs label="Room tabs" value={actualView} onChange={setView} options={[
        ...(role?[['messages','Messages'] as const,['threads','Threads'] as const,['pins','Pins'] as const,['tasks','Tasks'] as const]:[]),
        ...(manager||role!=='guest'?[['people','Members'] as const]:[]),
        ...(canManage?[['settings','Settings'] as const,['audit','Audit'] as const]:[]),
      ]}/>
      {reactions.error&&<p role="alert" className="error">{reactions.error}</p>}
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
          <label>{actualView==='threads'?'Write a reply':'Write a room message'}<textarea name="body" required maxLength={4000} aria-describedby="room-mentions-help"/></label>
          <p id="room-mentions-help">Use <code>@handle</code> to mention a room member.
            {staff&&<> Use <code>@group:"Group name"</code> for a group, <code>@channel</code> for the room, or <code>@here</code> for online members.</>}</p>
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
        {canChangeVisibility&&<div className="release-section">
          <h3>Room visibility</h3>
          <p>{room.kind==='public'?'Private rooms require admission for new members.':'Workspace members will be able to find and join this room.'} Current members keep access.</p>
          <button className="secondary" type="button" disabled={working} onClick={()=>{
            if(window.confirm(`Change room visibility to ${kinds[nextVisibility].toLowerCase()}?`))
              void manage('visibility',{p_kind:nextVisibility})
          }}>Make room {kinds[nextVisibility].toLowerCase()}</button>
        </div>}
        {manager&&!room.archived&&room.kind!=='admin'&&<div className="release-section">
          <h3>Room ownership</h3>
          <p>Current owner{roster.filter(person=>person.role==='owner').length===1?'':'s'} {roster.filter(person=>person.role==='owner')
            .map(person=>name(person.user_id)).join(', ')||'—'}</p>
          {ownerCandidates.length>0&&<form className="release-flex" onSubmit={event=>{
            event.preventDefault()
            const target=String(new FormData(event.currentTarget).get('owner'))
            if(window.confirm('Transfer ownership? The previous owner becomes a moderator.'))
              void manage('transfer_owner',{p_target:target})
          }}>
            <label>New room owner<select name="owner" required><option value="">Choose a room member</option>
              {ownerCandidates.map(person=><option key={person.user_id} value={person.user_id}>{name(person.user_id)} (@{profiles[person.user_id].handle})</option>)}
            </select></label>
            <button className="secondary" disabled={working}>Transfer ownership</button>
          </form>}
        </div>}
        <div className="action-row">
          {staff&&room.kind==='private'&&<button className="secondary" type="button" onClick={async()=>{
            try{await navigator.clipboard.writeText(room.id);setNotice('Room request code copied.')}
            catch{setNotice(room.id)}
          }}>Copy room request code</button>}
          {staff&&!room.archived&&<button className="secondary" type="button" disabled={working} onClick={()=>void settings(room.locked?'unlock':'lock')}>
            {room.locked?'Unlock room':'Lock room'}</button>}
          {(manager||role==='owner')&&<button className="secondary" type="button" disabled={working} onClick={()=>void toggleArchive()}>
            {room.archived?'Restore room':'Archive room'}</button>}
        </div>
        {staff&&!room.archived&&<form className="release-flex" onSubmit={event=>{
          event.preventDefault();void settings('slow',{p_seconds:Number(new FormData(event.currentTarget).get('seconds'))})
        }}><label>Slow mode in seconds<input key={room.slow_seconds} name="seconds" type="number" min={0} max={300} required defaultValue={room.slow_seconds}/></label>
          <button className="secondary" disabled={working}>Save slow mode</button></form>}
      </>}
      {actualView==='audit'&&(notes.length?<ol className="audit">{notes.map(note=><li key={note.id}>
        <strong>{note.action.replaceAll('.',' ')}</strong><span>{name(note.actor)} · {new Date(note.occurred_at).toLocaleString()}</span>
        {note.action.startsWith('membership.')&&note.target&&<span>Member {name(note.target)}</span>}
        {note.details.from&&note.details.to&&<span>{kinds[note.details.from]} → {kinds[note.details.to]}</span>}
        {note.details.previous_owners?.length?<span>Previous owner {note.details.previous_owners.map(name).join(', ')}</span>:null}
      </li>)}</ol>:<p>No room audit entries.</p>)}
    </>}
  </section>
}
