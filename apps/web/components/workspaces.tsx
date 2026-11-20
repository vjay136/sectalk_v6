'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { CalendarDays, Hash, ListChecks, MessageCircle, Plus, Send, Users } from 'lucide-react'
import { db, formatError, formatTime, liveChannel, onReconnect, type Profile } from '../lib/data'
import { SectionTabs } from './section-tabs'
import { RoomDirectory } from './room-directory'

type Space = { id: string; name: string; owner: string }
type Invite = { id: string; workspace_name: string }
type Channel = { id: string; name: string }
type Member = { user_id: string; role: 'owner' | 'admin' | 'member' }
type Post = { id: string; sender: string; body: string; created_at: string }
type ItemKind = 'task' | 'note' | 'event' | 'announcement'
type Item = { id: string; kind: ItemKind; title: string; details: string; due_at: string | null; completed: boolean; created_by: string }
type Audit = { id: number; event: string; actor: string; created_at: string }
type WorkspaceView = 'workspaces' | 'rooms' | 'tasks' | 'calendar'
type Checklist = { id:string; task_id:string; label:string; completed:boolean }
const workspaceViews = {
  workspaces: { title:'Workspaces', description:'Manage workspace membership and activity.', icon:Users },
  rooms: { title:'Rooms', description:'Join conversations in your workspace channels.', icon:Hash },
  tasks: { title:'Tasks', description:'Assign tasks and track progress with checklists.', icon:ListChecks },
  calendar: { title:'Calendar', description:'See workspace events, meetings, and task deadlines.', icon:CalendarDays },
}
const itemLabels: Record<ItemKind, string> = { task: 'Task', note: 'Note', event: 'Calendar event', announcement: 'Announcement' }

function QuickForm({ label, button, children, send }: {
  label: string; button: string; children: ReactNode; send: (values: FormData) => Promise<unknown>
}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    const form = event.currentTarget
    setBusy(true)
    setError('')
    try {
      await send(new FormData(form))
      form.reset()
    } catch (error) {
      setError(formatError(error, 'Could not complete this action.'))
    } finally {
      setBusy(false)
    }
  }
  return <form aria-label={label} className="release-form" onSubmit={submit}>
    {children}
    {error && <p role="alert" className="error">{error}</p>}
    <button disabled={busy} className="secondary">{busy ? 'Saving…' : button}</button>
  </form>
}

async function rpc(name: string, values: Record<string, unknown>) {
  const { data, error } = await db!.rpc(name, values)
  if (error) throw error
  return data
}

export function Workspaces({ user, view = 'workspaces' }: { user:string;view?:WorkspaceView }) {
  const [spaces, setSpaces] = useState<Space[]>([])
  const [invites, setInvites] = useState<Invite[]>([])
  const [selected, setSelected] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const reload = useCallback(async () => {
    const [workspaceResult, inviteResult] = await Promise.all([
      db!.from('st_v2_workspaces').select('id,name,owner').order('created_at').limit(100),
      db!.from('st_v2_invites').select('id,workspace_name').eq('invitee', user).eq('status', 'pending').limit(50),
    ])
    if (workspaceResult.error || inviteResult.error) { setError('Could not load your workspaces.'); return }
    setError('')
    setSpaces(workspaceResult.data)
    setInvites(inviteResult.data)
    setSelected(previous => workspaceResult.data.some(space => space.id === previous) ? previous : workspaceResult.data[0]?.id ?? '')
  }, [user])

  useEffect(() => {
    void reload()
    const channel = liveChannel('workspace-invites:' + user, reload)
      .on('postgres_changes', { event: '*', schema: 'public', table: 'st_v2_invites', filter: 'invitee=eq.' + user }, reload)
      .subscribe()
    const reconnect = onReconnect(reload)
    const timer = window.setInterval(reload, 15000)
    return () => { reconnect(); window.clearInterval(timer); void db!.removeChannel(channel) }
  }, [reload, user])

  async function reply(id: string, accept: boolean) {
    setBusy(true)
    try {
      const result = await rpc('st_v2_reply_invite', { p_invite: id, p_accept: accept })
      await reload()
      if (result) setSelected(result)
    } catch (error) { setError(formatError(error, 'Could not respond to the invitation.')) }
    finally { setBusy(false) }
  }

  const space = spaces.find(row => row.id === selected)
  const {title, description, icon:Icon}=workspaceViews[view]
  return <section className="content-page">
    <header className="content-title"><div className="card-icon"><Icon size={22}/></div><div><h1>{title}</h1><p>{description}</p></div></header>
    {error && <p role="alert" className="error">{error}</p>}
    {view==='workspaces' && invites.length > 0 && <section className="panel release-panel"><h2>Invitations</h2>{invites.map(invite => <div className="release-row" key={invite.id}>
      <strong>{invite.workspace_name}</strong>
      <button className="primary" disabled={busy} onClick={() => void reply(invite.id, true)}>Join</button>
      <button className="secondary" disabled={busy} onClick={() => void reply(invite.id, false)}>Decline</button>
    </div>)}</section>}
    <div className="release-flex">
      {spaces.length > 0 && <label>Workspace<select value={selected} onChange={event => setSelected(event.target.value)}>
        {spaces.map(row => <option value={row.id} key={row.id}>{row.name}</option>)}
      </select></label>}
      {view==='workspaces' && <details className="release-create" open={!space || undefined}>
        <summary>Create a workspace</summary><QuickForm label="Create a workspace" button="Create workspace" send={async fields => {
          const id = await rpc('st_v2_create_workspace', { p_name: fields.get('name') })
          await reload()
          setSelected(id)
        }}><label>Workspace name<input name="name" required maxLength={64} placeholder="e.g. Eagle Security" /></label></QuickForm>
      </details>}
    </div>
    {space ? <WorkspaceArea key={space.id+view} space={space} user={user} view={view} /> :
      view!=='workspaces' && <p>Join or create a workspace to get started.</p>}
  </section>
}

function WorkspaceArea({ space, user, view }: { space:Space;user:string;view:WorkspaceView }) {
  const [tab, setTab] = useState<'channels' | 'board' | 'people' | 'activity'>('people')
  const [roomView,setRoomView]=useState<'rooms'|'channels'>('rooms')
  const [channels, setChannels] = useState<Channel[]>([])
  const [channelId, setChannelId] = useState('')
  const [members, setMembers] = useState<Member[]>([])
  const [profiles, setProfiles] = useState<Record<string, Profile>>({})
  const [audit, setAudit] = useState<Audit[]>([])
  const [error, setError] = useState('')
  const role = members.find(member => member.user_id === user)?.role
  const manager = role === 'owner' || role === 'admin'
  const load = useCallback(async () => {
    const [channelResult, memberResult] = await Promise.all([
      db!.from('st_v2_channels').select('id,name').eq('workspace_id', space.id).order('name'),
      db!.from('st_v2_members').select('user_id,role').eq('workspace_id', space.id).order('joined_at').limit(500),
    ])
    if (channelResult.error || memberResult.error) { setError('Could not load the workspace.'); return }
    setError('')
    const people = memberResult.data as Member[]
    setMembers(people)
    setChannels(channelResult.data)
    setChannelId(previous => channelResult.data.some(channel => channel.id === previous) ? previous : channelResult.data[0]?.id ?? '')
    if (people.length) {
      const { data } = await db!.from('st_profiles').select('id,name,handle').in('id', people.map(member => member.user_id))
      if (data) setProfiles(Object.fromEntries(data.map(profile => [profile.id, profile])))
    }
    if (people.some(person => person.user_id === user && person.role !== 'member')) {
      const { data } = await db!.from('st_v2_workspace_audit').select('id,event,actor,created_at').eq('workspace_id', space.id).order('id', { ascending: false }).limit(25)
      if (data) setAudit(data)
    }
  }, [space.id, user])

  useEffect(() => {
    void load()
    const reconnect = onReconnect(load)
    const timer = window.setInterval(load, 18000)
    return () => { reconnect(); window.clearInterval(timer) }
  }, [load])

  return <div className="panel release-panel">
    {view==='workspaces' && <SectionTabs label="Workspace sections" value={tab==='activity'&&!manager?'people':tab} onChange={setTab} options={[
      ['channels', <><Hash size={15}/> Channels</>], ['board', <><ListChecks size={15}/> Board</>],
      ['people', <><Users size={15}/> People</>], ...(manager ? [['activity','Activity'] as const] : []),
    ]}/>}
    {error && <p role="alert" className="error">{error}</p>}
    {view==='rooms'&&<SectionTabs label="Room sections" value={roomView} onChange={setRoomView} options={ [['rooms','Room directory'],['channels','Workspace channels']] }/>}
    {view==='rooms'&&roomView==='rooms'&&<RoomDirectory space={space.id} user={user} manager={manager} profiles={profiles}
      workspaceAdminIds={members.filter(member=>member.role!=='member').map(member=>member.user_id)}/>}
    {((view==='rooms'&&roomView==='channels')||(view==='workspaces'&&tab==='channels')) && <div className="release-section">
      <div className="release-flex">
        <label>Channel<select value={channelId} onChange={event => setChannelId(event.target.value)}>{channels.map(channel => <option key={channel.id} value={channel.id}>#{channel.name}</option>)}</select></label>
        {manager && <details className="release-create"><summary>New channel</summary><QuickForm label="New channel" button="Create channel" send={async fields => {
          const id = await rpc('st_v2_create_channel', { p_workspace: space.id, p_name: fields.get('name') })
          await load()
          setChannelId(id)
        }}><label>Channel name<input name="name" required maxLength={40} pattern="[a-z0-9][a-z0-9\-]{0,39}" placeholder="product-updates" /></label></QuickForm></details>}
      </div>
      {channelId && <ChannelFeed key={channelId} channelId={channelId} profiles={profiles} user={user}/>}
    </div>}
    {view==='workspaces' && tab==='board' && <Board space={space.id} manager={manager} />}
    {view==='tasks'&&<TaskList space={space.id} actor={user} manager={manager} members={members} profiles={profiles}/>}
    {view==='calendar'&&<WorkspaceCalendar space={space.id} />}
    {view==='workspaces'&&(tab==='people'||(tab==='activity'&&!manager)) && <div className="release-section">
      {manager && <QuickForm label="Invite a member" button="Send invitation" send={async fields => {
        if (!await rpc('st_v2_invite', { p_workspace: space.id, p_handle: fields.get('handle') })) throw new Error('This contact is unavailable or has already been invited.')
        await load()
      }}><label>Invite by SecTalk handle<input name="handle" required minLength={3} maxLength={24} /></label></QuickForm>}
      <h2>Members</h2>
      {members.map(member => <div className="release-row" key={member.user_id}>
        <strong>{profiles[member.user_id]?.name || 'Workspace member'}</strong><span className="pill">{member.role}</span>
        {role === 'owner' && member.role !== 'owner' && <QuickForm label="Manage member" button="Apply" send={async fields => {
          await rpc('st_v2_set_member', { p_workspace: space.id, p_member: member.user_id, p_role: fields.get('role') })
          await load()
        }}><label>Change access<select name="role" defaultValue={member.role}><option value="member">Member</option><option value="admin">Admin</option><option value="remove">Remove access</option></select></label></QuickForm>}
      </div>)}
    </div>}
    {view==='workspaces'&&tab==='activity'&&manager&&<div className="release-section"><h2>Recent workspace activity</h2>{audit.length===0&&<p>No activity yet.</p>}
      {audit.map(event => <div className="release-row" key={event.id}><strong>{event.event.replace('.', ' ')}</strong><span>{profiles[event.actor]?.name || 'Workspace member'}</span><time dateTime={event.created_at}>{new Date(event.created_at).toLocaleString()}</time></div>)}
    </div>}
  </div>
}

function ChannelFeed({ channelId, profiles, user }: { channelId: string; profiles: Record<string, Profile>; user: string }) {
  const [posts, setPosts] = useState<Post[]>([])
  const [error, setError] = useState('')
  const [older, setOlder] = useState(false)
  const draftId = useRef<{ id: string; body: string } | null>(null)
  const fetchPosts = useCallback(async (before?: Post) => {
    let query = db!.from('st_v2_posts').select('*').eq('channel_id', channelId)
    if (before) query = query.or('created_at.lt.' + before.created_at + ',and(created_at.eq.' + before.created_at + ',id.lt.' + before.id + ')')
    const { data, error } = await query.order('created_at', { ascending: false }).order('id', { ascending: false }).limit(51)
    if (error) { setError('Could not load channel messages.'); return }
    setError('')
    if (before || data.length > 50) setOlder(data.length > 50)
    setPosts(previous => [...new Map([...previous, ...data.slice(0, 50)].map(post => [post.id, post])).values()]
      .sort((a, b) => a.created_at.localeCompare(b.created_at) || a.id.localeCompare(b.id)))
  }, [channelId])
  useEffect(() => {
    const refresh = () => void fetchPosts()
    refresh()
    const channel = liveChannel('workspace-channel:' + channelId, refresh)
      .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'st_v2_posts', filter: 'channel_id=eq.' + channelId }, refresh)
      .subscribe()
    const reconnect = onReconnect(refresh)
    const timer = window.setInterval(refresh, 5000)
    return () => { reconnect(); window.clearInterval(timer); void db!.removeChannel(channel) }
  }, [channelId, fetchPosts])
  return <>
    {error && <p className="error" role="alert">{error}</p>}
    <div className="release-channel-feed" role="log" aria-label="Channel messages">
      {older && <button className="secondary" onClick={() => void fetchPosts(posts[0])}>Earlier messages</button>}
      {!posts.length && <p><MessageCircle size={16}/> Start the conversation.</p>}
      {posts.map(post => <article className={'release-post' + (post.sender === user ? ' release-own' : '')} key={post.id}><header><strong>{profiles[post.sender]?.name || 'Workspace member'}</strong> <time dateTime={post.created_at}>{formatTime(post.created_at)}</time></header><p>{post.body}</p></article>)}
    </div>
    <QuickForm label="Post to channel" button="Send message" send={async fields => {
      const body = String(fields.get('body')).trim()
      if (!body) return
      if (draftId.current?.body !== body) draftId.current = { id: crypto.randomUUID(), body }
      await rpc('st_v2_post', { p_channel: channelId, p_id: draftId.current.id, p_body: body })
      draftId.current = null
      await fetchPosts()
    }}><label><span><Send size={14}/> Channel message</span><textarea name="body" required maxLength={4000} rows={2} /></label></QuickForm>
  </>
}

function Board({ space, manager }: { space: string; manager: boolean }) {
  const [items, setItems] = useState<Item[]>([])
  const [kind, setKind] = useState<ItemKind>('task')
  const [filter, setFilter] = useState<ItemKind | 'all'>('all')
  const [error, setError] = useState('')
  const reload = useCallback(async () => {
    const { data, error } = await db!.from('st_v2_items').select('*').eq('workspace_id', space).order('created_at', { ascending: false }).limit(100)
    if (error) setError('Could not load the board.')
    else { setError(''); setItems(data) }
  }, [space])
  useEffect(() => {
    void reload()
    const channel = liveChannel('board:' + space, reload)
      .on('postgres_changes', { event: '*', schema: 'public', table: 'st_v2_items', filter: 'workspace_id=eq.' + space }, reload)
      .subscribe()
    const timer = window.setInterval(reload, 10000)
    return () => { window.clearInterval(timer); void db!.removeChannel(channel) }
  }, [reload, space])
  return <div className="release-section">
    <div className="release-flex"><label>Show<select value={filter} onChange={event => setFilter(event.target.value as typeof filter)}>
      <option value="all">All board items</option>{Object.entries(itemLabels).map(([key, label]) => <option key={key} value={key}>{label}</option>)}
    </select></label><details className="release-create"><summary><Plus size={15}/> Add to board</summary>
      <QuickForm label="Add to board" button="Add item" send={async fields => {
        const value = String(fields.get('due') || '')
        await rpc('st_v2_add_item', { p_workspace: space, p_kind: kind, p_title: fields.get('title'), p_details: fields.get('details'), p_due: value ? new Date(value).toISOString() : null })
        await reload()
      }}><label>Item type<select value={kind} onChange={event => setKind(event.target.value as ItemKind)}>
        {Object.entries(itemLabels).filter(([key]) => manager || key !== 'announcement').map(([key, label]) => <option key={key} value={key}>{label}</option>)}
      </select></label><label>Title<input name="title" required maxLength={120}/></label><label>Details<textarea name="details" maxLength={3000} rows={2}/></label>
        {(kind === 'event' || kind === 'task') && <label>{kind === 'event' ? 'Starts at' : 'Due date'}<input name="due" type="datetime-local" required={kind === 'event'}/></label>}
      </QuickForm></details></div>
    {error && <p role="alert" className="error">{error}</p>}
    {!items.some(item => filter === 'all' || item.kind === filter) && <p>No matching items.</p>}
    {items.filter(item => filter === 'all' || item.kind === filter).map(item => <article key={item.id} className="release-board-item">
      <div className="release-row"><span className="pill">{itemLabels[item.kind]}</span><strong>{item.title}</strong></div>
      {item.details && <p>{item.details}</p>}
      {item.due_at && <p><CalendarDays size={15}/> <time dateTime={item.due_at}>{new Date(item.due_at).toLocaleString()}</time></p>}
      {item.kind === 'task' && <button className="secondary" onClick={async () => {
        try { await rpc('st_v2_complete_task', { p_item: item.id, p_complete: !item.completed }); await reload() }
        catch (error) { setError(formatError(error, 'Could not update task.')) }
      }}>{item.completed ? 'Reopen completed task' : 'Mark complete'}</button>}
    </article>)}
  </div>
}

function TaskList({ space,actor,manager,members,profiles }: {
  space:string;actor:string;manager:boolean;members:Member[];profiles:Record<string,Profile>
}) {
  const [items,setItems]=useState<Item[]|null>(null)
  const [assignments,setAssignments]=useState<Record<string,string>>({})
  const [checks,setChecks]=useState<Checklist[]>([])
  const [filter,setFilter]=useState<'open'|'mine'|'done'>('open')
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)
  const checklistKey=useRef<{ task:string;label:string;id:string }|null>(null)
  const reload=useCallback(async () => {
    const result=await db!.from('st_v2_items').select('*').eq('workspace_id',space).eq('kind','task').order('created_at',{ascending:false}).limit(100)
    if(result.error) { setError('Could not load tasks.'); return }
    const ids=result.data.map(item=>item.id)
    if(ids.length) {
      const [assigned,list]=await Promise.all([
        db!.from('st_v4_task_assignments').select('task_id,assignee').in('task_id',ids),
        db!.from('st_v4_checklist').select('id,task_id,label,completed').in('task_id',ids).order('created_at').limit(1000),
      ])
      if(assigned.error||list.error){ setError('Could not load assignments or checklists.');return }
      setAssignments(Object.fromEntries(assigned.data.map(row=>[row.task_id,row.assignee])))
      setChecks(list.data)
    } else { setAssignments({});setChecks([]) }
    setItems(result.data)
    setError('')
  },[space])
  useEffect(()=>{
    void reload()
    const channel=liveChannel('v4-tasks:'+space,reload)
      .on('postgres_changes',{event:'*',schema:'public',table:'st_v2_items',filter:'workspace_id=eq.'+space},reload).subscribe()
    const reconnect=onReconnect(reload)
    const timer=window.setInterval(reload,8000)
    return ()=>{reconnect();window.clearInterval(timer);void db!.removeChannel(channel)}
  },[reload,space])

  async function change(task:string, action:string, input:Record<string,unknown>={}) {
    await rpc('st_v4_task_change',{p_task:task,p_action:action,...input})
    await reload()
  }
  async function toggle(task:string, action:string, input:Record<string,unknown>) {
    if(busy)return
    setBusy(true)
    try{ await change(task,action,input) }catch(error){setError(formatError(error,'Could not update the task.'))}
    finally{setBusy(false)}
  }

  const visible=items?.filter(item=>filter==='mine'?assignments[item.id]===actor:filter==='done'?item.completed:!item.completed)
  return <div className="release-section">
    <SectionTabs label="Task filters" value={filter} onChange={setFilter} options={[
      ['open','Open tasks'],['mine','Assigned to me'],['done','Completed'],
    ]}/>
    <details className="release-create"><summary>Create a task</summary>
      <QuickForm label="Create a task" button="Create task" send={async fields=>{
        const due=String(fields.get('due')||'')
        await rpc('st_v2_add_item',{p_workspace:space,p_kind:'task',p_title:fields.get('title'),p_details:fields.get('details'),p_due:due?new Date(due).toISOString():null})
        setFilter('open');await reload()
      }}>
        <label>Title<input name="title" required maxLength={120}/></label>
        <label>Details<textarea name="details" maxLength={3000} rows={2}/></label>
        <label>Due date (optional)<input name="due" type="datetime-local"/></label>
      </QuickForm>
    </details>
    {error&&<p role="alert" className="error">{error}</p>}
    {!items&&!error&&<p role="status">Loading tasks…</p>}
    {visible?.length===0&&<p>No tasks in this view.</p>}
    {visible?.map(item=>{
      const assigned=members.some(member=>member.user_id===assignments[item.id])?assignments[item.id]:''
      const owner=manager||item.created_by===actor
      const canEdit=owner||assigned===actor
      const checklist=checks.filter(check=>check.task_id===item.id)
      return <article className="release-board-item" key={item.id}>
        <div className="release-row"><h2>{item.title}</h2><span className="pill">{item.completed?'Completed':'Open'}</span></div>
        {item.details&&<p>{item.details}</p>}
        {item.due_at&&<p>Due <time dateTime={item.due_at}>{new Date(item.due_at).toLocaleString()}</time></p>}
        <p>{assigned?'Assigned to '+(profiles[assigned]?.name||'workspace member'):'Unassigned'}</p>
        {owner&&<details className="release-create"><summary>Assign task</summary>
          <QuickForm label={'Assign '+item.title} button="Save assignment" send={fields=>change(item.id,'assign',{p_person:fields.get('assignee')||null})}>
            <label>Assignee<select key={assigned} name="assignee" defaultValue={assigned}>
              <option value="">Unassigned</option>{members.map(member=><option key={member.user_id} value={member.user_id}>
                {profiles[member.user_id]?.name||'Workspace member'}
              </option>)}
            </select></label>
          </QuickForm>
        </details>}
        {checklist.length>0&&<ul>{checklist.map(check=><li key={check.id}><label className="task-check">
          <input type="checkbox" checked={check.completed} disabled={!canEdit||busy} onChange={event=>void toggle(item.id,'checklist.toggle',{p_item:check.id,p_done:event.target.checked})}/>
          {check.label}
        </label></li>)}</ul>}
        {canEdit&&<div className="release-flex">
          <details className="release-create"><summary>Add checklist item</summary>
            <QuickForm label="Add checklist item" button="Add item" send={async fields=>{
              const label=String(fields.get('label')).trim()
              if(checklistKey.current?.task!==item.id||checklistKey.current.label!==label) checklistKey.current={task:item.id,label,id:crypto.randomUUID()}
              await change(item.id,'checklist.add',{p_item:checklistKey.current.id,p_label:label})
              checklistKey.current=null
            }}><label>Checklist item<input name="label" required maxLength={150}/></label></QuickForm>
          </details>
          <button className="secondary" disabled={busy} onClick={()=>void toggle(item.id,'complete',{p_done:!item.completed})}>
            {item.completed?'Reopen task':'Mark complete'}
          </button>
        </div>}
      </article>
    })}
  </div>
}

function WorkspaceCalendar({space}: {space:string}) {
  const [entries,setEntries]=useState<{id:string;title:string;at:string;kind:'events'|'meetings'|'deadlines'}[]|null>(null)
  const [filter,setFilter]=useState<'all'|'events'|'meetings'|'deadlines'>('all')
  const [error,setError]=useState('')
  const reload=useCallback(async()=>{
    const [items,meetings]=await Promise.all([
      db!.from('st_v2_items').select('id,title,kind,due_at').eq('workspace_id',space).in('kind',['event','task']).not('due_at','is',null).order('due_at').limit(100),
      db!.from('st_v3_meetings').select('id,title,starts_at').eq('workspace_id',space).neq('status','ended').order('starts_at').limit(100),
    ])
    if(items.error||meetings.error){setError('Could not load your calendar.');return}
    setEntries([
      ...items.data.map(row=>({id:row.id,title:row.title,at:row.due_at,kind:row.kind==='task'?'deadlines' as const:'events' as const})),
      ...meetings.data.map(row=>({id:row.id,title:row.title,at:row.starts_at,kind:'meetings' as const})),
    ].sort((first,second)=>Date.parse(first.at)-Date.parse(second.at)))
    setError('')
  },[space])
  useEffect(()=>{
    void reload()
    const timer=window.setInterval(reload,10000)
    const reconnect=onReconnect(reload)
    return ()=>{window.clearInterval(timer);reconnect()}
  },[reload])
  const visible=entries?.filter(entry=>filter==='all'||entry.kind===filter)
  return <div className="release-section">
    <SectionTabs label="Calendar filters" value={filter} onChange={setFilter} options={[
      ['all','Agenda'],['events','Events'],['meetings','Meetings'],['deadlines','Task deadlines'],
    ]}/>
    <details className="release-create"><summary>Add a calendar event</summary>
      <QuickForm label="Add a calendar event" button="Add event" send={async fields=>{
        await rpc('st_v2_add_item',{p_workspace:space,p_kind:'event',p_title:fields.get('title'),p_details:fields.get('details'),p_due:new Date(String(fields.get('start'))).toISOString()})
        setFilter('events');await reload()
      }}>
        <label>Title<input name="title" required maxLength={120}/></label>
        <label>Starts at<input name="start" type="datetime-local" required/></label>
        <label>Details<textarea name="details" maxLength={3000} rows={2}/></label>
      </QuickForm>
    </details>
    {error&&<p role="alert" className="error">{error}</p>}
    {!entries&&!error&&<p role="status">Loading calendar…</p>}
    {visible?.length===0&&<p>No calendar entries in this view.</p>}
    {visible?.map(entry=><div className="release-row" key={entry.kind+entry.id}>
      <strong>{entry.title}</strong><span className="pill">{entry.kind==='deadlines'?'Task':entry.kind==='events'?'Event':'Meeting'}</span>
      <time dateTime={entry.at}>{new Date(entry.at).toLocaleString()}</time>
    </div>)}
  </div>
}
