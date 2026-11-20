'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import dynamic from 'next/dynamic'
import { CalendarDays, Hash, ListChecks, MessageCircle, Plus, Send, Users } from 'lucide-react'
import { db, formatError, formatTime, liveChannel, onReconnect, type Profile } from '../lib/data'
import { SectionTabs } from './section-tabs'
import { RoomDirectory } from './room-directory'
import { QuietHoursSettings } from './quiet-hours'
import { WorkspaceSwitcher, useWorkspaceContext, type Workspace } from './workspace-context'
import { WorkspaceGroups } from './workspace-groups'
import { WorkspaceOnboarding } from './workspace-onboarding'
import { WorkspaceNotificationPolicy } from './workspace-notification-policy'
import { PendingWorkspaceInvite, WorkspaceLinkInvites } from './workspace-link-invites'
import { WorkspaceLegalHolds } from './workspace-legal-holds'
import { WorkspaceAdminOverview } from './workspace-admin-overview'
import { WorkspaceFiles } from './workspace-files'
import { WorkspaceIntegrations } from './workspace-integrations'
import { WorkspaceFeatures } from './workspace-features'
import { ComplianceExports } from './compliance-exports'
import { WorkspacePeople } from './workspace-people'
import { WorkspaceAISettings } from './workspace-ai-settings'

const ImpersonationWatch = dynamic(() => import('./impersonation-watch').then(module => module.ImpersonationWatch), {
  loading: () => <p role="status">Loading impersonation watch…</p>,
})

type Invite = { id: string; workspace_name: string }
type Channel = {id:string;name:string;owner:string;visibility:'workspace'|'private';archived:boolean}
type ChannelEvent = {id:number;actor:string;action:string;target:string|null;detail:string|null;occurred_at:string}
type ChannelDetails = {can_read:boolean;can_manage:boolean;members?:string[];audit?:ChannelEvent[]}
type Member = { user_id: string; role: 'owner' | 'admin' | 'member'; suspended_at: string | null }
type BulkInviteResult = { handle: string; sent: boolean }
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
  label: string; button: string; children?: ReactNode; send: (values: FormData) => Promise<unknown>
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

async function readInviteHandles(file: File) {
  if (file.size > 16000) throw new Error('Choose a CSV file up to 16 KB.')
  const rows = (await file.text()).replace(/^\uFEFF/, '').split(/\r\n|\n|\r/)
  const handles: string[] = []
  let firstField = true
  for (const [index, row] of rows.entries()) {
    const value = row.trim().toLowerCase()
    if (!value) continue
    const field = /^(?:"([a-z0-9_]{3,24})"|([a-z0-9_]{3,24}))$/.exec(value)
    if (!field) throw new Error('Enter one SecTalk handle on CSV row ' + (index + 1) + '.')
    const handle = field[1] || field[2]
    if (!firstField || handle !== 'handle') handles.push(handle)
    firstField = false
  }
  if (handles.length < 1 || handles.length > 100) throw new Error('Include between 1 and 100 handles.')
  return handles
}

export function Workspaces({ user, view = 'workspaces', requestedRoom }: {
  user:string;view?:WorkspaceView;requestedRoom?:{workspace:string;id:string}|null
}) {
  const {active:space,workspaces,reload:reloadWorkspaces}=useWorkspaceContext()
  const [invites, setInvites] = useState<Invite[]>([])
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const reload = useCallback(async () => {
    const inviteResult=await db!.from('st_v2_invites').select('id,workspace_name').eq('invitee', user).eq('status', 'pending').limit(50)
    if (inviteResult.error) { setError('Could not load your workspace invitations.'); return }
    setError('')
    setInvites(inviteResult.data)
  }, [user])

  useEffect(() => {
    if(view!=='workspaces')return
    void reload()
    const channel = liveChannel('workspace-invites:' + user, reload)
      .on('postgres_changes', { event: '*', schema: 'public', table: 'st_v2_invites', filter: 'invitee=eq.' + user }, reload)
      .subscribe()
    const reconnect = onReconnect(reload)
    const timer = window.setInterval(reload, 15000)
    return () => { reconnect(); window.clearInterval(timer); void db!.removeChannel(channel) }
  }, [reload, user, view])

  async function reply(id: string, accept: boolean) {
    setBusy(true)
    try {
      const result = await rpc('st_v2_reply_invite', { p_invite: id, p_accept: accept })
      await Promise.all([reload(),reloadWorkspaces(result||undefined)])
    } catch (error) { setError(formatError(error, 'Could not respond to the invitation.')) }
    finally { setBusy(false) }
  }

  const {title, description, icon:Icon}=workspaceViews[view]
  return <section className="content-page">
    <header className="content-title"><div className="card-icon"><Icon size={22}/></div><div><h1>{title}</h1><p>{description}</p></div></header>
    {error && <p role="alert" className="error">{error}</p>}
    {view==='workspaces'&&<PendingWorkspaceInvite onJoined={reloadWorkspaces}/>}
    {view==='workspaces' && invites.length > 0 && <section className="panel release-panel"><h2>Invitations</h2>{invites.map(invite => <div className="release-row" key={invite.id}>
      <strong>{invite.workspace_name}</strong>
      <button className="primary" disabled={busy} onClick={() => void reply(invite.id, true)}>Join</button>
      <button className="secondary" disabled={busy} onClick={() => void reply(invite.id, false)}>Decline</button>
    </div>)}</section>}
    <div className="release-flex">
      <WorkspaceSwitcher/>
      {view==='workspaces' && workspaces && <WorkspaceOnboarding openByDefault={!space} onCreated={reloadWorkspaces}/>}
    </div>
    {space ? <WorkspaceArea key={space.id+view+space.role} space={space} user={user} view={view}
      initialRoom={space.id===requestedRoom?.workspace?requestedRoom.id:undefined} /> :
      workspaces?.length===0&&view!=='workspaces'&&<p>Join or create a workspace to get started.</p>}
  </section>
}

function WorkspaceArea({ space, user, view, initialRoom }: { space:Workspace;user:string;view:WorkspaceView;initialRoom?:string }) {
  const [tab, setTab] = useState<'channels' | 'board' | 'people' | 'teams' | 'files' | 'activity' | 'impersonation' | 'governance' | 'overview' | 'integrations' | 'features' | 'ai' | 'compliance-exports'>('people')
  const [roomView,setRoomView]=useState<'rooms'|'channels'>('rooms')
  const [channels, setChannels] = useState<Channel[]>([])
  const [channelId, setChannelId] = useState('')
  const [archivedChannels,setArchivedChannels] = useState(false)
  const [members, setMembers] = useState<Member[]>([])
  const [profiles, setProfiles] = useState<Record<string, Profile>>({})
  const [audit, setAudit] = useState<Audit[]>([])
  const [presenceRequired,setPresenceRequired] = useState<boolean|null>(null)
  const [bulkResults, setBulkResults] = useState<BulkInviteResult[]>([])
  const [error, setError] = useState('')
  const activeMembers = members.filter(member => !member.suspended_at)
  const role = activeMembers.find(member => member.user_id === user)?.role
  const manager = role === 'owner' || role === 'admin'
  const visibleTab = (!manager && ['activity','impersonation','governance','overview','features','ai','compliance-exports'].includes(tab)) ||
    (tab==='integrations'&&role!=='owner') ? 'people' : tab
  const load = useCallback(async () => {
    const [channelResult, memberResult, presencePolicy] = await Promise.all([
      db!.from('st_v2_channels').select('id,name,owner,visibility,archived').eq('workspace_id', space.id).order('name'),
      db!.from('st_v2_members').select('user_id,role,suspended_at').eq('workspace_id', space.id).order('joined_at').limit(500),
      view==='workspaces' ? db!.rpc('st_v6_workspace_presence_policy',{p_workspace:space.id}) : null,
    ])
    if (channelResult.error || memberResult.error) { setError('Could not load the workspace.'); return }
    setError('')
    const people = memberResult.data as Member[]
    setMembers(people)
    setChannels(channelResult.data)
    setPresenceRequired(typeof presencePolicy?.data==='boolean'?presencePolicy.data:null)
    setChannelId(previous => channelResult.data.some(channel => channel.id === previous) ? previous : channelResult.data[0]?.id ?? '')
    if (people.length) {
      const { data } = await db!.from('st_profiles').select('id,name,handle').in('id', people.map(member => member.user_id))
      if (data) setProfiles(Object.fromEntries(data.map(profile => [profile.id, profile])))
    }
    if (people.some(person => person.user_id === user && person.role !== 'member')) {
      const { data } = await db!.from('st_v2_workspace_audit').select('id,event,actor,created_at').eq('workspace_id', space.id).order('id', { ascending: false }).limit(25)
      if (data) setAudit(data)
    }
  }, [space.id, user, view])

  useEffect(() => {
    void load()
    const reconnect = onReconnect(load)
    const timer = window.setInterval(load, 18000)
    return () => { reconnect(); window.clearInterval(timer) }
  }, [load])

  const visibleChannels=channels.filter(channel=>channel.archived===archivedChannels)
  const selectedChannel=visibleChannels.find(channel=>channel.id===channelId)||visibleChannels[0]

  return <div className="panel release-panel">
    {view==='workspaces'&&space.policy&&<p className="muted">{space.policy.details?.label||space.policy.workspace_type} · {
      space.policy.compliance?.label||(space.policy.template==='restricted'?'Restricted policy':'Standard policy')}</p>}
    {view==='workspaces' && <SectionTabs label="Workspace sections" value={visibleTab} onChange={setTab} options={[
      ...(manager ? [['overview','Overview'] as const,['features','Features'] as const] : []),
      ['channels', <><Hash size={15}/> Channels</>], ['board', <><ListChecks size={15}/> Board</>],
      ['people', <><Users size={15}/> People</>], ['teams','Groups & teams'], ['files','Files'],
      ...(role==='owner' ? [['integrations','Integrations'] as const] : []),
      ...(manager ? [['activity','Activity'] as const,['impersonation','Impersonation watch'] as const,
        ['governance','Governance'] as const,['ai','AI settings'] as const,['compliance-exports','Compliance exports'] as const] : []),
    ]}/>}
    {error && <p role="alert" className="error">{error}</p>}
    {view==='rooms'&&<SectionTabs label="Room sections" value={roomView} onChange={setRoomView} options={ [['rooms','Room directory'],['channels','Workspace channels']] }/>}
    {view==='rooms'&&roomView==='rooms'&&<RoomDirectory key={initialRoom} initialRoom={initialRoom} space={space.id} user={user} manager={manager} profiles={profiles}
      allowedRoomKinds={space.policy?.room_kinds}
      workspaceAdminIds={activeMembers.filter(member=>member.role!=='member').map(member=>member.user_id)}/>}
    {((view==='rooms'&&roomView==='channels')||(view==='workspaces'&&tab==='channels')) && <div className="release-section">
      <SectionTabs label="Channel filters" value={archivedChannels?'archived':'active'}
        onChange={next=>setArchivedChannels(next==='archived')} options={ [['active','Active channels'],['archived','Archived channels']] }/>
      <div className="release-flex">
        {selectedChannel&&<label>Channel<select value={selectedChannel.id} onChange={event => setChannelId(event.target.value)}>
          {visibleChannels.map(channel => <option key={channel.id} value={channel.id}>#{channel.name}</option>)}</select></label>}
        {manager && <details className="release-create"><summary>New channel</summary><QuickForm label="New channel" button="Create channel" send={async fields => {
          const id = await rpc('st_v2_create_channel', { p_workspace: space.id, p_name: fields.get('name') })
          await load()
          setChannelId(id)
          setArchivedChannels(false)
        }}><label>Channel name<input name="name" required maxLength={40} pattern="[a-z0-9][a-z0-9\-]{0,39}" placeholder="product-updates" /></label></QuickForm></details>}
      </div>
      {selectedChannel?<ChannelPanel key={selectedChannel.id+selectedChannel.visibility} channel={selectedChannel} profiles={profiles} activeMembers={activeMembers} user={user}
        refresh={load} onArchiveChange={archived=>{setChannelId(selectedChannel.id);setArchivedChannels(archived)}}/>
        :<p>No {archivedChannels?'archived':'active'} channels.</p>}
    </div>}
    {view==='workspaces' && tab==='board' && <Board space={space.id} manager={manager} />}
    {view==='workspaces' && tab==='files' && <WorkspaceFiles workspace={space.id} owner={role==='owner'} />}
    {view==='workspaces' && visibleTab==='integrations' && <WorkspaceIntegrations key={space.id} workspace={space.id}/>}
    {view==='workspaces' && visibleTab==='ai' && manager && <WorkspaceAISettings key={space.id} workspace={space.id}/>}
    {view==='workspaces' && tab==='impersonation' && manager && <ImpersonationWatch workspace={space.id}
      accounts={activeMembers.flatMap(member => profiles[member.user_id] ? [profiles[member.user_id]] : [])} />}
    {view==='workspaces' && tab==='governance' && manager && <WorkspaceLegalHolds key={space.id} workspace={space.id} owner={role==='owner'}
      members={members.flatMap(member => profiles[member.user_id] ? [profiles[member.user_id]] : [])}/>}
    {view==='workspaces' && tab==='overview' && manager && <WorkspaceAdminOverview key={space.id} workspace={space.id}/>}
    {view==='workspaces' && tab==='features' && manager && <WorkspaceFeatures key={space.id} workspace={space.id}/>}
    {view==='workspaces' && visibleTab==='compliance-exports' && manager && <ComplianceExports key={space.id} workspace={space.id}/>}
    {view==='workspaces' && tab==='teams' && <WorkspaceGroups workspace={space.id} manager={manager} people={activeMembers} profiles={profiles}/>}
    {view==='tasks'&&<TaskList space={space.id} actor={user} manager={manager} members={members} profiles={profiles}/>}
    {view==='calendar'&&<WorkspaceCalendar space={space.id} />}
    {view==='workspaces'&&visibleTab==='people' && <div className="release-section">
      {role && <WorkspaceNotificationPolicy workspace={space.id} manager={manager}/>}
      {manager&&<WorkspaceLinkInvites workspace={space.id} profile={space.policy?.compliance}/>}
      {presenceRequired!==null&&<div>
        {manager ? <QuickForm label="Workspace availability policy" button="Save availability policy" send={async fields => {
          await rpc('st_v6_set_workspace_presence_policy',{p_workspace:space.id,p_required:fields.get('presence')==='required'})
          await load()
        }}><label>Availability sharing<select key={String(presenceRequired)} name="presence" defaultValue={presenceRequired?'required':'choice'}>
          <option value="choice">Let members choose</option><option value="required">Require sharing</option>
        </select></label>
          <p className="muted">Requiring sharing disables Invisible and new changes to hide availability for active members. Existing private settings stay private until the member chooses a state.</p>
        </QuickForm> : <p className="muted">{presenceRequired?'This workspace requires availability sharing.':'Members choose how to share their availability.'}</p>}
      </div>}
      {manager && <QuickForm label="Invite a member" button="Send invitation" send={async fields => {
        if (!await rpc('st_v2_invite', { p_workspace: space.id, p_handle: fields.get('handle') })) throw new Error('This contact is unavailable or has already been invited.')
        await load()
      }}><label>Invite by SecTalk handle<input name="handle" required minLength={3} maxLength={24} /></label></QuickForm>}
      {manager && <details className="release-create"><summary>Import invitations from CSV</summary>
        <QuickForm label="Import invitations" button="Send invitations" send={async fields => {
          setBulkResults([])
          const file = fields.get('csv')
          if (!(file instanceof File) || !file.size) throw new Error('Choose a CSV file.')
          const handles = await readInviteHandles(file)
          const results = await rpc('st_v6_bulk_workspace_invite', { p_workspace:space.id, p_handles:handles })
          setBulkResults(results as BulkInviteResult[])
          await load()
        }}>
          <label>CSV file<input name="csv" type="file" accept=".csv,text/csv" required /></label>
          <p className="muted">Use one SecTalk handle per row, with an optional handle header. Include up to 100 handles.</p>
        </QuickForm>
        {bulkResults.length > 0 && <div role="status">
          <p>{bulkResults.filter(result => result.sent).length} of {bulkResults.length} invitations sent.</p>
          <ul>{bulkResults.map(result => <li key={result.handle}>@{result.handle} · {result.sent ? 'Sent' : 'Unavailable or already invited'}</li>)}</ul>
        </div>}
      </details>}
      {role === 'owner' || role === 'admin' ? <WorkspacePeople key={space.id} workspace={space.id} role={role} user={user} onChanged={load}/> : <>
        <h2>Members</h2>
        {members.map(member => <div className="release-row" key={member.user_id}>
          <strong>{profiles[member.user_id]?.name || 'Workspace member'}</strong><span className="pill">{member.role}</span>
          {member.suspended_at && <span className="pill">Suspended</span>}
        </div>)}
      </>}
    </div>}
    {view==='workspaces'&&tab==='activity'&&manager&&<div className="release-section"><h2>Recent workspace activity</h2>{audit.length===0&&<p>No activity yet.</p>}
      {audit.map(event => <div className="release-row" key={event.id}><strong>{event.event.replace('.', ' ')}</strong><span>{profiles[event.actor]?.name || 'Workspace member'}</span><time dateTime={event.created_at}>{new Date(event.created_at).toLocaleString()}</time></div>)}
    </div>}
  </div>
}

function ChannelPanel({channel,profiles,activeMembers,user,refresh,onArchiveChange}: {
  channel:Channel;profiles:Record<string,Profile>;activeMembers:Member[];user:string;refresh:()=>Promise<void>;onArchiveChange:(archived:boolean)=>void
}) {
  const [details,setDetails]=useState<ChannelDetails|null>(null)
  const [error,setError]=useState('')
  const version=useRef(0)
  const load=useCallback(async()=>{
    const request=++version.current
    const result=await db!.rpc('st_v6_channel_details',{p_channel:channel.id})
    if(request!==version.current)return
    if(result.error){setDetails(null);setError('Could not load channel access.');return}
    setDetails(result.data as ChannelDetails);setError('')
  },[channel.id])
  useEffect(()=>{
    void load()
    const timer=window.setInterval(load,5000)
    const reconnect=onReconnect(load)
    return ()=>{version.current++;window.clearInterval(timer);reconnect()}
  },[load])

  const name=(id:string)=>profiles[id]?.name||'Workspace member'
  const people=activeMembers.flatMap(member=>member.user_id!==channel.owner&&profiles[member.user_id]?[profiles[member.user_id]]:[])
  const memberIds=details?.members||[]
  const candidates=people.filter(person=>!memberIds.includes(person.id))
  const peopleOptions=(available:Profile[])=><><option value="">Choose a workspace member</option>{available.map(person=>
    <option key={person.id} value={person.id}>{person.name} (@{person.handle})</option>)}</>
  const change=async(action:string,values:Record<string,unknown>={})=>{
    await rpc('st_v6_manage_channel',{p_channel:channel.id,p_action:action,...values})
    await Promise.all([load(),refresh()])
    if(action==='archive'||action==='restore')onArchiveChange(action==='archive')
  }
  return <section aria-label={'#'+channel.name}>
    <h2>#{channel.name}</h2>
    <p>{channel.visibility==='private'?'Private':'Workspace-wide'}{channel.archived?' · Archived':''}</p>
    {error&&<p role="alert" className="error">{error}</p>}
    {details?.can_manage&&<details className="release-create">
      <summary>Channel settings</summary>
      <p>Channel owner {name(channel.owner)}</p>
      {!channel.archived&&<>
        <QuickForm label="Change channel visibility" button={channel.visibility==='private'?'Make channel workspace-wide':'Make channel private'} send={async()=>{
          const next=channel.visibility==='private'?'workspace':'private'
          const prompt=next==='private'?'Make this channel private? Only the owner and listed members will be able to open it.'
            :'Make channel history available to the workspace?'
          if(window.confirm(prompt))await change('visibility',{p_visibility:next})
        }}/>
        <h3>Private channel access</h3>
        <p>Listed members can open the channel when it is private.</p>
        {memberIds.map(id=><div className="release-row" key={id}><span>{name(id)}</span>
          <QuickForm label={'Remove '+name(id)+' from the channel'} button="Remove access" send={async()=>{
            if(window.confirm('Remove this member’s private channel access?'))await change('remove_member',{p_target:id})
          }}/>
        </div>)}
        {candidates.length>0&&<QuickForm label="Add private channel member" button="Add channel member" send={fields=>
          change('add_member',{p_target:fields.get('member')})}>
          <label>Workspace member<select name="member" required>{peopleOptions(candidates)}</select></label>
        </QuickForm>}
        {people.length>0&&<QuickForm label="Transfer channel ownership" button="Transfer ownership" send={async fields=>{
          if(window.confirm('Transfer channel ownership? The previous owner loses owner access.'))
            await change('transfer_owner',{p_target:fields.get('owner')})
        }}><label>New channel owner<select name="owner" required>{peopleOptions(people)}</select></label></QuickForm>}
      </>}
      <QuickForm label="Change channel archive status" button={channel.archived?'Restore channel':'Archive channel'} send={async()=>{
        if(channel.archived||window.confirm('Archive this channel and stop new posts?'))
          await change(channel.archived?'restore':'archive')
      }}/>
      <h3>Channel audit</h3>
      {details.audit?.length?<ol className="audit">{details.audit.map(event=><li key={event.id}>
        <strong>{event.action.replaceAll('_',' ')}</strong><span>{name(event.actor)} · {new Date(event.occurred_at).toLocaleString()}</span>
        {event.target&&<span>Member {name(event.target)}</span>}
        {event.detail&&<span>{event.action==='transfer_owner'?'Previous owner '+name(event.detail):event.detail}</span>}
      </li>)}</ol>:<p>No channel audit entries.</p>}
    </details>}
    {details?.can_read&&<ChannelFeed channelId={channel.id} archived={channel.archived} profiles={profiles} user={user}/>}
  </section>
}

function ChannelFeed({ channelId, archived, profiles, user }: { channelId: string; archived:boolean; profiles: Record<string, Profile>; user: string }) {
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
    <details className="release-create"><summary>Channel quiet hours</summary>
      <QuietHoursSettings channel={channelId}/>
    </details>
    <div className="release-channel-feed" role="log" aria-label="Channel messages">
      {older && <button className="secondary" onClick={() => void fetchPosts(posts[0])}>Earlier messages</button>}
      {!posts.length && <p><MessageCircle size={16}/> Start the conversation.</p>}
      {posts.map(post => <article className={'release-post' + (post.sender === user ? ' release-own' : '')} key={post.id}><header><strong>{profiles[post.sender]?.name || 'Workspace member'}</strong> <time dateTime={post.created_at}>{formatTime(post.created_at)}</time></header><p>{post.body}</p></article>)}
    </div>
    {!archived&&<QuickForm label="Post to channel" button="Send message" send={async fields => {
      const body = String(fields.get('body')).trim()
      if (!body) return
      if (draftId.current?.body !== body) draftId.current = { id: crypto.randomUUID(), body }
      await rpc('st_v2_post', { p_channel: channelId, p_id: draftId.current.id, p_body: body })
      draftId.current = null
      await fetchPosts()
    }}><label><span><Send size={14}/> Channel message</span><textarea name="body" required maxLength={4000} rows={2} /></label></QuickForm>}
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
              <option value="">Unassigned</option>{members.filter(member=>!member.suspended_at || member.user_id===assigned).map(member=><option key={member.user_id} value={member.user_id}>
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
