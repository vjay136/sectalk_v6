'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import dynamic from 'next/dynamic'
import {
  ArrowLeft, Ban, Bell, BellOff, Bookmark, CalendarClock, CalendarDays, Check, CheckCheck, ChevronRight, CircleHelp, Copy, CreditCard, Flag, Folder, Inbox as InboxIcon, LogOut, ShieldAlert,
  Download, Hash, ListChecks, MessageCircle, MoreHorizontal, Paperclip, Phone, Pin, Search, Send, Shield, ShieldCheck, Smile, UserPlus, UserRound, Users, Video, X,
} from 'lucide-react'
import { db, formatError, formatTime, liveChannel, onReconnect, peerId, type Call, type Chat, type Message, type Profile } from '../lib/data'
import { useCalling } from '../lib/calling'
import { riskIndicators } from '../lib/safety.mjs'
import { CallPanel } from './call-panel'
import { Brand } from './entry'
import { ReportDialog, Safety } from './safety'
import { Workspaces } from './workspaces'
import { Billing } from './billing'
import { Meetings } from './meetings'
import { FilesLibrary } from './files-library'
import { GlobalSearch, Notifications } from './discover'
import { InProductHelp } from './in-product-help'
import { meetingFromQuery } from '../lib/meeting-calendar'
import { ScopedTasks } from './scoped-tasks'
import { SectionTabs } from './section-tabs'
import { CommandPalette, type Command } from './command-palette'
import { ScheduledMessages } from './scheduled-messages'
import { downloadChatFile, extensions, sendChatFile, supportedFile, type ChatFile } from '../lib/chat-files'
import { EmojiText } from './emoji-text'
import { SavedMessages, setSavedMessage } from './saved-messages'
import { ProfileActivity, ProfileAppearance, useProfileExtras } from './profile-settings'

const ChatEmoji=dynamic(()=>import('./chat-emoji'))
const Friends=dynamic(()=>import('./friends').then(module=>module.Friends))
const DiscoverySettings=dynamic(()=>import('./friends').then(module=>module.DiscoverySettings))

export function Avatar({ name, tint = 'green', photo }: { name:string; tint?:string; photo?:string }) {
  const initials = name.trim().split(/\s+/).slice(0, 2).map(word => [...word][0]).join('').toUpperCase()
  return <span className={'avatar ' + tint} aria-hidden="true">{photo?<img src={photo} alt="" width={42} height={42}/>:initials||'?'}</span>
}

type InboxStatus = { chat_id: string; muted: boolean; unread: boolean; latest_id: string | null; latest_at: string | null }
type Presence = { user_id:string; state:'online'|'away'|'busy'|'offline'; expires_at:string }

export function Inbox({ user }: { user: string }) {
  const [profile, setProfile] = useState<Profile | null | undefined>()
  const [profiles, setProfiles] = useState<Record<string, Profile>>({})
  const [chats, setChats] = useState<Chat[]>([])
  const [blocks, setBlocks] = useState<string[]>([])
  const [staff, setStaff] = useState('none')
  const [selected, setSelected] = useState<string | null>(null)
  const [requestedMeeting,setRequestedMeeting] = useState<string|null>(()=>typeof window==='undefined'?null:meetingFromQuery(window.location.search))
  const [tab, setTab] = useState<'inbox' | 'calls' | 'safety' | 'profile' | 'workspaces' | 'billing' | 'meetings' | 'vault' | 'search' | 'notifications' | 'rooms' | 'tasks' | 'calendar' | 'friends' | 'saved'>(() =>
    requestedMeeting?'meetings':typeof window !== 'undefined' && new URLSearchParams(window.location.search).has('billing') ? 'billing' : 'inbox')
  const [mode, setMode] = useState<'chats' | 'requests' | 'sent'>('chats')
  const [taskSection,setTaskSection]=useState<'scoped'|'workspace'>('scoped')
  const [paletteOpen,setPaletteOpen]=useState(false)
  const [paletteSearch,setPaletteSearch]=useState({query:'',sequence:0})
  const [chatTasks,setChatTasks]=useState(false)
  const [sourceTask,setSourceTask]=useState<string|null>(null)
  const [profileTab, setProfileTab] = useState<'account' | 'availability' | 'discovery' | 'activity' | 'blocked' | 'help'>('account')
  const [managedBlock,setManagedBlock]=useState<Chat|null>(null)
  const [search, setSearch] = useState('')
  const [notice, setNotice] = useState('')
  const [onboarding,setOnboarding]=useState(false)
  const [report, setReport] = useState<{ chat: string; message: Message | null; file?:ChatFile } | null>(null)
  const [lastSeen,setLastSeen]=useState<{chat:string;at:string}|null>(null)
  const [blockCheck, setBlockCheck] = useState(false)
  const [online, setOnline] = useState(false)
  const [broadcastOnline, setBroadcastOnline] = useState(false)
  const [working, setWorking] = useState(false)
  const [presence,setPresence] = useState<Record<string,Presence>>({})
  const [inboxStatus, setInboxStatus] = useState<Record<string, InboxStatus>>({})
  const activeChat = useRef<string | null>(null)
  const announced = useRef(new Map<string, string>())
  const readVersion = useRef(0)
  const [hints] = useState(() => new EventTarget())
  const call = useCalling(user, setNotice, hints)
  useEffect(() => { activeChat.current = tab === 'inbox' ? selected : null }, [tab, selected])
  const refreshInboxStatus = useCallback(async (changedChat?: string) => {
    const { data, error } = await db!.rpc('st_v2_inbox_status')
    if (error) return
    setInboxStatus(Object.fromEntries((data as InboxStatus[]).map(row => [row.chat_id,row])))
    if (changedChat) {
      const row = (data as InboxStatus[]).find(item => item.chat_id === changedChat)
      if (row?.unread && !row.muted && row.latest_id && row.latest_at && activeChat.current !== changedChat
        && Date.now() - Date.parse(row.latest_at) < 12000 && announced.current.get(changedChat) !== row.latest_id) {
        announced.current.set(changedChat,row.latest_id)
        setNotice('New direct message in your inbox.')
      }
    }
  }, [])

  const refresh = useCallback(async () => {
    const version = ++readVersion.current
    const [own, related, muted, role] = await Promise.all([
      db!.from('st_profiles').select('*').eq('id', user).maybeSingle(),
      db!.from('st_chats').select('*').order('updated_at', { ascending: false }).limit(250),
      db!.from('st_blocks').select('target'),
      db!.rpc('st_staff_status'),
    ])
    if (version !== readVersion.current) return
    if (own.error || related.error || muted.error || role.error) {
      setNotice('Could not load your workspace. Check your connection and try again.')
      return
    }
    const list = related.data as Chat[]
    setProfile(own.data as Profile | null)
    setChats(list)
    setBlocks(muted.data.map(row => row.target))
    setStaff(role.data)
    const ids = [...new Set(list.map(row => peerId(row, user)))]
    const [people,state] = await Promise.all([
      ids.length ? db!.from('st_profiles').select('*').in('id', ids) : Promise.resolve({data:[]}),
      db!.from('st_v3_presence').select('user_id,state,expires_at').in('user_id',[user,...ids]),
    ])
    if (version !== readVersion.current) return
    if (people.data) setProfiles(Object.fromEntries(people.data.map(person => [person.id, person])))
    if (state.data) setPresence(Object.fromEntries((state.data as Presence[]).map(row=>[row.user_id,row])))
  }, [user])

  useEffect(() => {
    void refresh()
    const syncStatus = () => void refreshInboxStatus()
    syncStatus()
    hints.addEventListener('read_local', syncStatus)
    const account = db!.channel('st:account:' + user, { config: { private: true } })
      .on('broadcast', { event: 'inbox' }, ({ payload }) => {
        if (typeof payload?.chat_id === 'string') {
          hints.dispatchEvent(new MessageEvent('inbox', { data: payload.chat_id }))
          void refresh()
          void refreshInboxStatus(payload.chat_id)
        }
      })
      .on('broadcast', { event: 'call' }, () => hints.dispatchEvent(new Event('call')))
      .on('broadcast', { event: 'presence' }, () => void refresh())
      .on('broadcast', { event: 'chat_activity' }, ({ payload }) => {
        if (typeof payload?.chat_id === 'string') hints.dispatchEvent(new MessageEvent('chat_activity', { data: payload.chat_id }))
      })
      .on('broadcast', { event: 'signal' }, ({ payload }) => {
        if (typeof payload?.call_id === 'string') hints.dispatchEvent(new MessageEvent('signal', { data: payload.call_id }))
      })
      .subscribe(status => {
        setBroadcastOnline(status === 'SUBSCRIBED')
        if (status === 'SUBSCRIBED') {
          hints.dispatchEvent(new Event('ready'))
          void refresh()
          syncStatus()
        }
      })
    const channel = liveChannel('inbox:' + user, () => { setOnline(true); void refresh() })
      .on('postgres_changes', { event: '*', schema: 'public', table: 'st_chats', filter: 'member_a=eq.' + user }, refresh)
      .on('postgres_changes', { event: '*', schema: 'public', table: 'st_chats', filter: 'member_b=eq.' + user }, refresh)
      .subscribe(status => {
        if (status === 'SUBSCRIBED') void refresh()
        else setOnline(false)
      })
    const timer = window.setInterval(refresh, 16000)
    const removeReconnect = onReconnect(refresh)
    const subscription = db!.auth.onAuthStateChange(event => {
      if (event === 'MFA_CHALLENGE_VERIFIED' || event === 'TOKEN_REFRESHED') window.setTimeout(refresh, 0)
    })
    return () => {
      ++readVersion.current
      hints.removeEventListener('read_local', syncStatus)
      removeReconnect()
      window.clearInterval(timer)
      subscription.data.subscription.unsubscribe()
      void db!.removeChannel(account)
      void db!.removeChannel(channel)
    }
  }, [user, refresh, hints, refreshInboxStatus])

  useEffect(() => {
    function shortcut(event: KeyboardEvent) {
      if ((event.ctrlKey || event.metaKey) && !event.altKey && !event.shiftKey && event.key.toLowerCase()==='k' && !document.querySelector('dialog[open]')) {
        event.preventDefault()
        setPaletteOpen(true)
      }
    }
    window.addEventListener('keydown',shortcut)
    return () => window.removeEventListener('keydown',shortcut)
  },[])
  useEffect(() => {
    if (!profile) return
    const ping=()=>{if(document.visibilityState==='visible') void db!.rpc('st_v3_ping')}
    ping()
    const timer=window.setInterval(ping,45000)
    const disconnect=onReconnect(ping)
    return ()=>{disconnect();window.clearInterval(timer)}
  },[profile?.id])

  const chat = chats.find(item => item.id === selected)
  const peer = chat ? profiles[peerId(chat, user)] : undefined
  const peerPresence = peer ? presence[peer.id] : undefined
  const peerState = peerPresence && Date.parse(peerPresence.expires_at)>Date.now() && peerPresence.state!=='offline' ? peerPresence.state : null
  const peerPresenceId=peerPresence?.user_id
  const peerExpiresAt=peerPresence?.expires_at
  useEffect(()=>{
    if(!peerPresenceId||!peerExpiresAt)return
    const expiresIn=Date.parse(peerExpiresAt)-Date.now()
    if(expiresIn<=0)return
    const timer=window.setTimeout(()=>{
      setPresence(previous=>{
        if(previous[peerPresenceId]?.expires_at!==peerExpiresAt)return previous
        const next={...previous}
        delete next[peerPresenceId]
        return next
      })
      void refresh()
    },expiresIn+20)
    return ()=>window.clearTimeout(timer)
  },[peerPresenceId,peerExpiresAt,refresh])
  const blocked = chat ? blocks.includes(peerId(chat, user)) : false
  const acceptedChat=chat?.status==='accepted'&&!blocked?chat.id:null
  const myExtras=useProfileExtras(profile?.id)
  const peerExtras=useProfileExtras(acceptedChat?peer?.id:undefined)
  useEffect(()=>{
    if(!acceptedChat) return
    let active=true
    const check=async()=>{
      const {data,error}=await db!.rpc('st_v5_last_seen',{p_chat:acceptedChat})
      if(active) setLastSeen(!error&&typeof data==='string'?{chat:acceptedChat,at:data}:null)
    }
    void check()
    const timer=window.setInterval(check,12000)
    return ()=>{active=false;window.clearInterval(timer)}
  },[acceptedChat])
  const lastSeenLabel=lastSeen&&lastSeen.chat===acceptedChat
    ? 'Last seen '+new Date(lastSeen.at).toLocaleString(undefined,{dateStyle:'medium',timeStyle:'short'}) : ''
  const requests = chats.filter(item => item.status === 'pending' && item.requester !== user && !blocks.includes(peerId(item, user)))
  const visible = chats.filter(item => (mode==='chats'?item.status==='accepted':
    item.status==='pending'&&(mode==='sent'?item.requester===user:item.requester!==user&&!blocks.includes(peerId(item,user)))) &&
    (!search || [profiles[peerId(item, user)]?.name, profiles[peerId(item, user)]?.handle]
      .some(value => value?.toLowerCase().includes(search.toLowerCase().trim()))))
  const callerId = call.call ? (call.call.caller === user ? call.call.callee : call.call.caller) : ''

  function showSearch(query='') {
    setPaletteSearch(previous=>({query,sequence:previous.sequence+1}))
    setTab('search')
  }

  function showHelp() {
    setProfileTab('help')
    setTab('profile')
  }

  const destinations=[
    ['inbox','Inbox','chats messages'],['friends','Friends','contacts people'],['calls','Calls','audio video history'],
    ['workspaces','Workspaces','organizations'],['rooms','Rooms','channels'],['tasks','Tasks','board assignments'],
    ['calendar','Calendar','schedule'],['meetings','Meetings','video'],['vault','Files','attachments vault'],
    ['notifications','Notifications','updates'],['safety','Safety','reports'],['billing','Billing','plans subscription'],
    ['profile','Profile','settings account'],
  ] as const
  const commands:Command[]=[
    ...destinations.map(([destination,label,keywords])=>({label:'Go to '+label,keywords,run:()=>{
      if(destination==='meetings')setRequestedMeeting(null)
      setTab(destination)
    }})),
    {label:'Open saved messages',keywords:'bookmarks',run:()=>setTab('saved')},
    {label:'Review incoming contact requests',keywords:'friends',run:openRequests},
    {label:'Open advanced search',keywords:'find filters',run:()=>showSearch()},
    {label:'Open help and keyboard shortcuts',keywords:'learn getting started',run:showHelp},
  ]
  if(acceptedChat)commands.push({label:'Open tasks for this chat',keywords:'assignments',run:()=>{
    setSourceTask(null);setChatTasks(true);setTab('inbox')
  }})

  function select(id: string | null) {
    setSelected(id)
    setBlockCheck(false)
    setChatTasks(false)
    setSourceTask(null)
    setTab('inbox')
  }
  function openMeeting(id:string) {
    setRequestedMeeting(id)
    setTab('meetings')
  }
  function openRequests() {
    setMode('requests');select(null)
  }
  async function sendRequest(handle:string) {
    if(working)return
    setWorking(true)
    try{
      const request=await db!.rpc('st_request',{p_handle:handle})
      if(request.error)throw request.error
      if(!request.data)throw new Error('This contact is unavailable.')
      const {data,error}=await db!.from('st_chats').select('id,status,requester').eq('id',request.data).single()
      if(error)throw error
      const sent=data.requester===user
      setMode(data.status==='accepted'?'chats':sent?'sent':'requests')
      setNotice(data.status==='accepted'?'You’re already connected.':data.status==='declined'?'This request is closed.':
        sent?'Contact request is pending.':'This person already sent you a request.')
      await refresh()
      select(data.id)
    }catch(error){setNotice(formatError(error,'Could not send the request.'))}
    finally{setWorking(false)}
  }

  async function run(name: string, input: Record<string, unknown>, success: () => void = () => {}) {
    if (working) return
    setWorking(true)
    try {
      const { error } = await db!.rpc(name, input)
      if (error) throw error
      success()
      await refresh()
    } catch (error) {
      setNotice(formatError(error, 'Please try again.'))
    } finally {
      setWorking(false)
    }
  }

  if (profile === undefined) return <main className="center-page"><Brand /><p role="status">{notice || 'Loading your workspace…'}</p>{notice && <button className="secondary" onClick={refresh}>Try again</button>}<button className="text-button" onClick={() => void db!.auth.signOut({ scope: 'local' })}>Sign out</button></main>
  if (!profile) return <main className="center-page"><Brand /><ProfileForm profile={null} onSave={async()=>{setOnboarding(true);await refresh()}}/><button className="text-button" onClick={() => void db!.auth.signOut({ scope: 'local' })}>Sign out</button></main>
  if(onboarding) return <main className="discovery-onboarding"><Brand/><DiscoverySettings user={user} complete={()=>setOnboarding(false)}/></main>

  return <main className={'workspace ' + (selected && tab === 'inbox' ? 'thread-open' : '') + (tab !== 'inbox' ? ' full-panel' : '')}>
    <nav className="rail" aria-label="SecTalk features">
      <Brand compact />
      <button className={tab === 'inbox' || tab === 'saved' ? 'active' : ''} aria-current={tab === 'inbox' || tab === 'saved' ? 'page' : undefined} onClick={() => setTab('inbox')}><MessageCircle size={20} /><span>Inbox</span></button>
      <button className={tab==='friends'?'active':''} aria-current={tab==='friends'?'page':undefined} onClick={()=>setTab('friends')}><UserPlus size={19}/><span>Friends</span></button>
      <button className={tab === 'calls' ? 'active' : ''} aria-current={tab === 'calls' ? 'page' : undefined} onClick={() => setTab('calls')}><Phone size={19} /><span>Calls</span></button>
      <button className={tab === 'workspaces' ? 'active' : ''} aria-current={tab === 'workspaces' ? 'page' : undefined} onClick={() => setTab('workspaces')}><Users size={19} /><span>Workspaces</span></button>
      <button className={tab==='rooms'?'active':''} aria-current={tab==='rooms'?'page':undefined} onClick={()=>setTab('rooms')}><Hash size={19}/><span>Rooms</span></button>
      <button className={tab==='tasks'?'active':''} aria-current={tab==='tasks'?'page':undefined} onClick={()=>setTab('tasks')}><ListChecks size={19}/><span>Tasks</span></button>
      <button className={tab==='calendar'?'active':''} aria-current={tab==='calendar'?'page':undefined} onClick={()=>setTab('calendar')}><CalendarDays size={19}/><span>Calendar</span></button>
      <button className={tab==='meetings'?'active':''} aria-current={tab==='meetings'?'page':undefined} onClick={()=>{setRequestedMeeting(null);setTab('meetings')}}><CalendarDays size={19}/><span>Meetings</span></button>
      <button className={tab==='vault'?'active':''} aria-current={tab==='vault'?'page':undefined} onClick={()=>setTab('vault')}><Folder size={19}/><span>Files</span></button>
      <button className={tab==='search'?'active':''} aria-current={tab==='search'?'page':undefined} onClick={()=>showSearch()}><Search size={19}/><span>Search</span></button>
      <button className={tab==='notifications'?'active':''} aria-current={tab==='notifications'?'page':undefined} onClick={()=>setTab('notifications')}><Bell size={19}/><span>Notifications</span></button>
      <button className={tab === 'safety' ? 'active' : ''} aria-current={tab === 'safety' ? 'page' : undefined} onClick={() => setTab('safety')}><Shield size={20} /><span>Safety</span></button>
      <div className="rail-end"><button className={tab === 'billing' ? 'active' : ''} aria-current={tab === 'billing' ? 'page' : undefined} onClick={() => setTab('billing')}><CreditCard size={19} /><span>Billing</span></button><button className={tab === 'profile' ? 'active' : ''} aria-current={tab === 'profile' ? 'page' : undefined} onClick={() => setTab('profile')}><UserRound size={20} /><span>Profile</span></button>
        <button onClick={async () => { await call.end(); void db!.auth.signOut({ scope: 'local' }) }}><LogOut size={19} /><span>Sign out</span></button></div>
    </nav>
    <aside className="inbox-list">
      <header><Brand /><div className="inbox-heading"><h1>Inbox</h1><button className="primary" onClick={()=>setTab('friends')}><UserPlus size={17}/> Find Friends</button></div>
        <div className="input-icon search"><Search size={17} /><input aria-label="Search contacts" placeholder="Search contacts" value={search} onChange={e => setSearch(e.target.value)} /></div>
      </header>
      <div className="tabs" aria-label="Conversation filters">
        <button aria-pressed={mode === 'chats'} className={mode === 'chats' ? 'active' : ''} onClick={() => setMode('chats')}>Chats</button>
        <button aria-pressed={mode === 'requests'} className={mode === 'requests' ? 'active' : ''} onClick={openRequests}>Incoming {requests.length > 0 && <span>{requests.length}</span>}</button>
        <button aria-pressed={mode==='sent'} className={mode==='sent'?'active':''} onClick={()=>{setMode('sent');select(null)}}>Sent</button>
      </div>
      <button type="button" className="secondary saved-shortcut" onClick={()=>setTab('saved')}><Bookmark size={16}/> Saved messages</button>
      <div className="chat-list">
        {visible.length === 0 && <div className="list-empty"><InboxIcon size={22} /><strong>{search ? 'No matching contacts' : mode==='chats'?'No conversations yet':mode==='sent'?'No sent requests':'No incoming requests'}</strong><p>{!search&&mode==='chats'?'Send a request to someone you know.':''}</p></div>}
        {visible.map(item => {
          const person = profiles[peerId(item, user)]
          return <button key={item.id} className={'chat-item ' + (item.id === selected ? 'selected' : '')} onClick={() => select(item.id)}>
            <Avatar name={person?.name || 'Contact'} tint={item.status === 'pending' ? 'peach' : 'green'} />
            <span><strong>{person?.name || 'Contact'}</strong><small>{blocks.includes(peerId(item, user)) ? 'Blocked' : person ? '@' + person.handle : 'Contact'}</small></span>
            {inboxStatus[item.id]?.muted && <BellOff size={13} aria-label="Muted"/>}
            {inboxStatus[item.id]?.unread ? <span className="status-dot" aria-label="Unread messages"/> : <ChevronRight size={15} />}
          </button>
        })}
      </div>
      <div className="list-footer"><Avatar name={profile.name} photo={myExtras.photo}/><div><strong>{profile.name}</strong><small>@{profile.handle}</small></div><span className={'status-dot ' + (online || broadcastOnline ? '' : 'offline')} title={online || broadcastOnline ? 'Live updates connected' : 'Syncing'} /></div>
    </aside>
    {tab === 'profile' ? <section className="content-page"><h1>Profile</h1>
      <SectionTabs label="Profile sections" value={profileTab} onChange={setProfileTab} options={ [['account','Account'],['availability','Availability'],['discovery','Discovery'],['activity','Activity & reports'],['blocked','Blocked contacts'],['help','Help']] }/>
      {profileTab === 'account' ? <><div className="profile-handle"><code>@{profile.handle}</code><button className="secondary" onClick={async () => {
        try { await navigator.clipboard.writeText(profile.handle); setNotice('Handle copied.') }
        catch { setNotice('Could not copy your handle. Select and copy it from your profile.') }
      }}><Copy size={15} /> Copy handle</button></div>
      <ProfileForm profile={profile} onSave={refresh} /><ProfileAppearance user={user} profile={myExtras}/></> :
      profileTab==='discovery'?<DiscoverySettings user={user}/>:
      profileTab==='activity'?<ProfileActivity openReports={()=>setTab('safety')}/>:
      profileTab==='help'?<InProductHelp openFriends={()=>setTab('friends')} openSafety={()=>setTab('safety')}/>:
      profileTab==='blocked'?<div className="panel release-panel"><h2>Contact controls</h2>
        <p>Blocking prevents new messages, audio calls, and video calls from the contact. Existing messages remain in your chat.</p>
        {!chats.length&&<p>No contacts to manage.</p>}
        {[...chats].sort((a,b)=>Number(blocks.includes(peerId(b,user)))-Number(blocks.includes(peerId(a,user)))).map(item=>{
          const contact=peerId(item,user)
          const restricted=blocks.includes(contact)
          return <div className="release-row" key={item.id}><strong>{profiles[contact]?.name||'Contact'}</strong>
            <span className="pill">{restricted?'Blocked':item.status==='accepted'?'Accepted':'Request'}</span>
            <button type="button" className={restricted?'secondary':'danger'} disabled={working} onClick={()=>setManagedBlock(item)}>
              {restricted?'Unblock':'Block'}
            </button>
          </div>
        })}
      </div> :
      <div className="panel release-panel"><label>Availability for approved contacts
        <select value={presence[user]?.state||'offline'} disabled={working} onChange={event=>void run('st_v3_set_presence',{p_state:event.target.value})}>
          <option value="offline">Offline (hidden)</option><option value="online">Online</option><option value="away">Away</option><option value="busy">Busy</option>
        </select></label>
        <label className="task-check"><input type="checkbox" checked={myExtras.details?.share_last_seen||false} disabled={working}
          onChange={event=>void run('st_v5_set_last_seen',{p_enabled:event.target.checked},()=>void myExtras.refresh())}/> Share last seen</label>
        <p>Accepted contacts can see your last activity for up to seven days when both availability and last seen are shared.</p></div>}
      </section> :
      tab==='friends'?<Friends user={user} pending={requests.length} working={working} send={sendRequest} openRequests={openRequests}/>:
      tab==='saved'?<SavedMessages openChat={select}/>:
      tab === 'safety' ? <Safety staff={staff} refresh={refresh} /> :
      tab==='workspaces'||tab==='rooms'||tab==='calendar' ? <Workspaces key={tab} user={user} view={tab} /> :
      tab==='tasks' ? <div className="task-center">
        <SectionTabs label="Task sections" value={taskSection} onChange={setTaskSection} options={[
          ['scoped','Room and chat tasks'],['workspace','Workspace tasks'],
        ]}/>
        {taskSection==='scoped'?<div className="content-page"><ScopedTasks user={user} people={{...profiles,[user]:profile}}/></div>:
          <Workspaces user={user} view="tasks"/>}
      </div> :
      tab === 'billing' ? <Billing user={user} /> :
      tab === 'meetings' ? <Meetings key={requestedMeeting||'all'} requested={requestedMeeting} user={user}/> :
      tab === 'vault' ? <FilesLibrary user={user} openChat={select}/> :
      tab === 'search' ? <GlobalSearch key={paletteSearch.sequence} initialQuery={paletteSearch.query} openChat={select} openMeeting={openMeeting} openPalette={()=>setPaletteOpen(true)}/> :
      tab === 'notifications' ? <Notifications user={user} openMeeting={openMeeting}/> :
      tab === 'calls' ? <Calls user={user} chats={chats} profiles={profiles} blocks={blocks} state={call} openChat={select} openInbox={() => setTab('inbox')} /> :
      chat ? <section className="thread">
        <header className="thread-header"><button className="icon mobile-back" aria-label="Back to inbox" onClick={() => select(null)}><ArrowLeft size={20} /></button><Avatar name={peer?.name || 'Contact'} photo={peerExtras.photo}/>
          <div><h2>{peer?.name || 'Contact'}</h2><p aria-label="Contact availability">{blocked ? 'Blocked' : peerState ? peerState[0].toUpperCase()+peerState.slice(1) : chat.status==='accepted' ? ['Offline',lastSeenLabel].filter(Boolean).join(' · ') : 'Contact request'}</p>
            {peerExtras.details?.status_message&&<p className="thread-profile-status" title={peerExtras.details.status_message}>{peerExtras.details.status_message}</p>}</div>
          <div className="thread-actions">
            {chat.status === 'accepted' && !blocked && <>
              <button className="icon" aria-pressed={chatTasks} aria-label="Chat tasks" title="Chat tasks" onClick={()=>{
                setChatTasks(!chatTasks);setSourceTask(null)
              }}><ListChecks size={18}/></button>
              <button className="icon" disabled={call.busy || !!call.call} aria-label="Start audio call" title="Start audio call" onClick={() => void call.start(chat.id, false)}><Phone size={18} /></button>
              <button className="icon" disabled={call.busy || !!call.call} aria-label="Start video call" title="Start video call" onClick={() => void call.start(chat.id, true)}><Video size={20} /></button>
            </>}
            <button className="icon" title="Report contact" aria-label="Report contact" onClick={() => setReport({ chat: chat.id, message: null })}><Flag size={18} /></button>
            <button className="icon" title={blocked ? 'Unblock contact' : 'Block contact'} aria-label={blocked ? 'Unblock contact' : 'Block contact'} onClick={() => setBlockCheck(true)}><Ban size={18} /></button>
          </div>
        </header>
        {blockCheck && <div className="inline-warning"><span>{blocked ? 'Allow this contact to reach you again?' : 'Block new messages and calls from this contact?'}</span><button className="danger" disabled={working} onClick={() => void run('st_set_block', { p_chat: chat.id, p_block: !blocked }, () => { setBlockCheck(false); setNotice(blocked ? 'Contact unblocked.' : 'Contact blocked.') })}>{blocked ? 'Unblock' : 'Block'}</button><button className="secondary" onClick={() => setBlockCheck(false)}>Cancel</button></div>}
        {chat.status === 'accepted' ? <Thread key={chat.id} chat={chat} self={user} selfName={profile.name} peerName={peer?.name||'Contact'} hints={hints}
          blocked={blocked} inform={setNotice} onReport={(message,file) => setReport({ chat:chat.id,message,file })}
          onTask={id=>{setSourceTask(id);setChatTasks(true)}} taskPanel={chatTasks&&!blocked?<div className="feed">
            <ScopedTasks user={user} scope={{kind:'chat',id:chat.id}} source={sourceTask}
              people={peer?{[profile.id]:profile,[peer.id]:peer}:{[profile.id]:profile}} canCreate onSourceUsed={()=>setSourceTask(null)}/>
          </div>:null}/> :
          <div className="empty-thread"><div className="card-icon"><ShieldCheck size={26} /></div>
            <h2>{chat.status === 'declined' ? 'Request declined' : chat.requester === user ? 'Request sent' : 'New contact request'}</h2>
            <p>{chat.status === 'declined' ? 'This conversation is closed.' : chat.requester === user ? 'You can chat and call once this contact accepts.' : 'Accept to allow this person to message or call you.'}</p>
            {chat.status === 'pending' && chat.requester !== user && !blocked && <div className="action-row">
              <button className="primary" disabled={working} onClick={() => void run('st_respond', { p_chat: chat.id, p_accept: true }, () => setMode('chats'))}><Check size={17} /> Accept</button>
              <button className="secondary" disabled={working} onClick={() => void run('st_respond', { p_chat: chat.id, p_accept: false })}>Decline</button>
            </div>}
          </div>}
      </section> : <section className="thread"><header className="thread-header default-header"><h2>Messages</h2><span className="pill"><span className={'status-dot ' + (online || broadcastOnline ? '' : 'offline')} />{online || broadcastOnline ? 'Live updates' : 'Syncing'}</span></header>
        <div className="empty-thread welcome-thread"><div className="card-icon"><MessageCircle size={27}/></div><h2>Your conversations</h2><p>Choose a chat or add a contact to start talking.</p><button className="primary" onClick={()=>setTab('friends')}><UserPlus size={17}/> Find Friends</button><button className="secondary" onClick={showHelp}>Getting started</button></div>
      </section>}
    {notice && <div className="toast" role="status"><CircleHelp size={18} /><span>{notice}</span><button className="icon" aria-label="Dismiss notice" onClick={() => setNotice('')}><X size={17}/></button></div>}
    {managedBlock&&<Dialog title={blocks.includes(peerId(managedBlock,user))?'Unblock contact?':'Block contact?'} close={()=>setManagedBlock(null)}>
      <p>{blocks.includes(peerId(managedBlock,user))?'Allow new messages and calls from this contact.':'Stop new messages and calls from this contact.'}</p>
      <button className="danger" type="button" disabled={working} onClick={()=>{
        const block=!blocks.includes(peerId(managedBlock,user))
        void run('st_set_block',{p_chat:managedBlock.id,p_block:block},()=>{setManagedBlock(null);setNotice(block?'Contact blocked.':'Contact unblocked.')})
      }}>{blocks.includes(peerId(managedBlock,user))?'Unblock':'Block'}</button>
    </Dialog>}
    {paletteOpen&&<CommandPalette commands={commands} onClose={()=>setPaletteOpen(false)} onSearch={showSearch}/>}
    {report && <ReportDialog chat={report.chat} message={report.message} file={report.file} close={() => setReport(null)} inform={setNotice} />}
    {call.call && <CallPanel key={call.call.id} state={call} self={user} name={profiles[callerId]?.name || 'Contact'}
      openChat={select} reportContact={chatId => setReport({chat:chatId,message:null})} />}
  </main>
}

function Calls({ user, chats, profiles, blocks, state, openChat, openInbox }: {
  user: string; chats: Chat[]; profiles: Record<string, Profile>; blocks: string[];
  state: ReturnType<typeof useCalling>; openChat: (id: string) => void; openInbox: () => void
}) {
  const [rows, setRows] = useState<Call[] | null>(null)
  const [filter, setFilter] = useState<'all' | 'missed' | 'audio' | 'video'>('all')
  const [now,setNow]=useState(()=>Date.now())
  const [error, setError] = useState(false)
  const reload = useCallback(async () => {
    const { data, error } = await db!.from('st_calls').select('*')
      .or('caller.eq.' + user + ',callee.eq.' + user).order('created_at', { ascending: false }).order('id',{ascending:false}).limit(40)
    setError(!!error)
    if (data) {setRows(data as Call[]);setNow(Date.now())}
  }, [user])
  useEffect(() => { void reload() }, [reload, state.historyVersion])
  const nextExpiry=rows?.reduce((earliest,row)=>{
    const expiry=Date.parse(row.expires_at)
    return row.status!=='ended'&&expiry>now?Math.min(earliest,expiry):earliest
  },Infinity)
  useEffect(()=>{
    if(nextExpiry===undefined||!Number.isFinite(nextExpiry))return
    const timer=window.setTimeout(()=>setNow(Date.now()),Math.max(0,nextExpiry-Date.now())+10)
    return ()=>window.clearTimeout(timer)
  },[nextExpiry])
  const missed=(row:Call)=>row.end_reason==='missed'||(row.status==='ringing'&&Date.parse(row.expires_at)<=now)
  const visibleCalls = rows?.filter(row=>filter==='all'||(filter==='missed'?row.callee===user&&missed(row):row.video===(filter==='video')))

  return <section className="content-page">
    <header className="content-title"><div className="card-icon"><Phone size={22} /></div><div><h1>Calls</h1><p>Start a call from an approved conversation or return a recent call.</p></div></header>
    <SectionTabs label="Call history" value={filter} onChange={setFilter} options={ [['all', 'All calls'], ['missed','Missed'], ['audio', 'Audio'], ['video', 'Video']] }/>
    <div className="panel">
      <div className="panel-header"><h2>Recent calls</h2><button className="secondary" onClick={openInbox}>Open inbox <ChevronRight size={16} /></button></div>
      {error && <div className="list-empty"><p role="alert">Could not load call history.</p><button className="secondary" onClick={reload}>Try again</button></div>}
      {!error && rows === null && <div className="list-empty" role="status">Loading calls…</div>}
      {!error && visibleCalls?.length === 0 && <div className="list-empty"><Phone size={22} /><strong>{filter === 'all' ? 'No calls yet' : 'No ' + filter + ' calls yet'}</strong><p>Open a chat and choose Audio or Video.</p></div>}
      {visibleCalls?.map(row => {
        const incoming = row.callee === user
        const peer = incoming ? row.caller : row.callee
        const name = profiles[peer]?.name || 'Contact'
        const reachable = chats.some(chat => chat.id === row.chat_id && chat.status === 'accepted') && !blocks.includes(peer)
        const status=missed(row)?(incoming?'Missed':'No answer'):
          row.end_reason==='declined'?'Declined':row.end_reason==='cancelled'?'Cancelled':
          row.status==='active'&&Date.parse(row.expires_at)>now?'In progress':row.status==='ringing'?'Ringing':'Ended'
        return <div className="report-row" key={row.id}>
          <Avatar name={name} />
          <div><strong>{name}</strong><small>{incoming ? 'Incoming' : 'Outgoing'} {row.video ? 'video' : 'audio'} · {new Date(row.created_at).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}</small><span className="call-state">{status}</span></div>
          {reachable && <span className="call-history-controls">
            {incoming&&missed(row)&&<button className="secondary" aria-label={'Call back '+name}
              disabled={state.busy||!!state.call} onClick={()=>void state.start(row.chat_id,row.video)}>Call back</button>}
            <button className="icon" aria-label={'Open conversation with ' + name} title="Open conversation" onClick={() => openChat(row.chat_id)}><MessageCircle size={17} /></button>
            <button className="icon" aria-label={'Start audio call with ' + name} title="Audio call" disabled={state.busy || !!state.call} onClick={() => void state.start(row.chat_id, false)}><Phone size={17} /></button>
            <button className="icon" aria-label={'Start video call with ' + name} title="Video call" disabled={state.busy || !!state.call} onClick={() => void state.start(row.chat_id, true)}><Video size={17} /></button>
          </span>}
        </div>
      })}
    </div>
  </section>
}

export function Dialog({ title, close, children }: { title: string; close: () => void; children: React.ReactNode }) {
  const ref = useRef<HTMLDialogElement>(null)
  useEffect(() => { ref.current?.showModal() }, [])
  return <dialog ref={ref} onCancel={close} aria-labelledby="dialog-label" className="dialog"><div className="dialog-title"><h2 id="dialog-label">{title}</h2><button className="icon" aria-label="Close dialog" onClick={close}><X size={19}/></button></div>{children}</dialog>
}

function ProfileForm({ profile, onSave }: { profile: Profile | null; onSave: () => Promise<void> }) {
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)
  const [busy, setBusy] = useState(false)
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const values = new FormData(event.currentTarget)
    setBusy(true)
    setError('')
    setSaved(false)
    const { error } = await db!.rpc('st_save_profile', { p_handle: profile?.handle ?? values.get('handle'), p_name: values.get('name') })
    if (error) setError(error.code === '23505' ? 'That handle is already taken.' : 'Could not save your profile.')
    else { setSaved(true); await onSave() }
    setBusy(false)
  }
  return <form className="auth-card profile-card" onSubmit={submit}>
    <div className="card-icon"><UserRound size={20}/></div>
    <h2>{profile ? 'Your identity' : 'Set up your profile'}</h2>
    <p>People use your handle to send you a contact request.</p>
    <label>Display name<input name="name" required maxLength={50} defaultValue={profile?.name} /></label>
    <label>Handle<input name="handle" required pattern="[a-z0-9_]{3,24}" autoCapitalize="none" disabled={!!profile} defaultValue={profile?.handle} placeholder="e.g. avery_m" /></label>
    {!!error && <p className="error" role="alert">{error}</p>}
    {saved && <p role="status">Profile saved.</p>}
    <button className="primary" disabled={busy}>Save profile <Check size={17}/></button>
  </form>
}

type Reaction = { message_id: string; user_id: string; reaction: string }
type ChatActivity = { muted: boolean; read_at: string | null; read_id: string | null; typing_until: string | null }
const reactionOptions = [
  { emoji: '👍', label: 'Thumbs up' }, { emoji: '❤️', label: 'Heart' },
  { emoji: '✅', label: 'Check mark' }, { emoji: '👀', label: 'Eyes' },
]

function Thread({ chat, self, selfName, peerName, hints, blocked, onReport, inform, onTask, taskPanel }: {
  chat: Chat; self: string; selfName:string; peerName:string; hints: EventTarget; blocked: boolean
  onReport: (message: Message,file?:ChatFile) => void; inform: (notice: string) => void
  onTask:(id:string)=>void;taskPanel:React.ReactNode
}) {
  const [messages, setMessages] = useState<Message[]>([])
  const [draft, setDraft] = useState('')
  const [loaded, setLoaded] = useState(false)
  const [activity, setActivity] = useState<ChatActivity | null>(null)
  const [reactions, setReactions] = useState<Reaction[]>([])
  const [pin, setPin] = useState<Message | null>(null)
  const [showSearch, setShowSearch] = useState(false)
  const [results, setResults] = useState<Message[] | null>(null)
  const [editing, setEditing] = useState<Message | null>(null)
  const [removing,setRemoving]=useState<{message:Message;action:'hide'|'revoke'}|null>(null)
  const [hidden,setHidden]=useState<string[]>([])
  const [files,setFiles]=useState<Record<string,ChatFile>>({})
  const [attachment,setAttachment]=useState<{file:File;id:string}|null>(null)
  const [emoji,setEmoji]=useState(false)
  const [reacting,setReacting]=useState<string|null>(null)
  const filePicker=useRef<HTMLInputElement>(null)
  const composerInput=useRef<HTMLTextAreaElement>(null)
  const cursor=useRef<{start:number;end:number}|null>(null)
  const [replying, setReplying] = useState<Message | null>(null)
  const [quotes,setQuotes]=useState<Record<string,Pick<Message,'id'|'sender'|'body'>>>({})
  const [history, setHistory] = useState<{ id: number; body: string; created_at: string }[] | null>(null)
  const [clock, setClock] = useState(0)
  const typingLast = useRef(0)
  const readLast = useRef('')
  const [older, setOlder] = useState(false)
  const [busy, setBusy] = useState(false)
  const feed = useRef<HTMLDivElement>(null)
  const nearBottom = useRef(true)
  const pending = useRef<{ id: string; body: string; reply: string | null } | null>(null)
  const pendingSchedule=useRef<{id:string;body:string;at:string}|null>(null)
  const [scheduleOpen,setScheduleOpen]=useState(false)
  const revoked=useRef(new Map<string,Message>())
  const [loadingOlder, setLoadingOlder] = useState(false)
  const merge = useCallback((rows: Message[]) => {
    for(const row of rows)if(row.revoked_at)revoked.current.set(row.id,row)
    const current=rows.map(row=>revoked.current.get(row.id)||row)
    setMessages(previous => [...new Map([...previous, ...current].map(row => [row.id, row])).values()]
      .sort((a, b) => a.created_at.localeCompare(b.created_at) || a.id.localeCompare(b.id)))
    const updates=new Map(current.map(row=>[row.id,row]))
    setResults(previous=>previous?.map(row=>updates.get(row.id)||row)??null)
    setReplying(previous=>previous&&(updates.get(previous.id)?.revoked_at?null:previous))
    setEditing(previous=>previous&&(updates.get(previous.id)?.revoked_at?null:previous))
  }, [])

  const loadQuotes=useCallback(async(rows:Message[])=>{
    const ids=[...new Set(rows.flatMap(row=>row.reply_to?[row.reply_to]:[]))]
    if(!ids.length)return
    const {data,error}=await db!.rpc('st_v6_reply_quotes',{p_chat:chat.id,p_ids:ids})
    setQuotes(previous=>{
      const next={...previous}
      for(const id of ids)delete next[id]
      if(!error)for(const row of data)if(!revoked.current.has(row.id))next[row.id]=row
      return next
    })
  },[chat.id])

  const load = useCallback(async (before?: Message) => {
    let query = db!.from('st_messages').select('*').eq('chat_id', chat.id)
    if (before) query = query.or('created_at.lt.' + before.created_at + ',and(created_at.eq.' + before.created_at + ',id.lt.' + before.id + ')')
    const { data, error } = await query.order('created_at', { ascending: false }).order('id', { ascending: false }).limit(51)
    if (error) { inform('Could not sync messages.'); return }
    if (before || !loaded) setOlder(data.length > 50)
    const page=data.slice(0,50) as Message[]
    const ids=page.map(row=>row.id)
    if(ids.length){
      const [removed,attachments]=await Promise.all([
        db!.from('st_v5_hidden_messages').select('message_id').in('message_id',ids),
        db!.from('st_v5_files').select('id,message_id,filename,size_bytes').in('message_id',ids),
        loadQuotes(page),
      ])
      if(removed.data) setHidden(previous=>[...new Set([...previous,...removed.data.map(row=>row.message_id)])])
      if(attachments.data) setFiles(previous=>({...previous,...Object.fromEntries(attachments.data.map(file=>[file.message_id,file]))}))
    }
    merge(page)
    setLoaded(true)
  }, [chat.id, inform, loaded, loadQuotes, merge])

  const loadLatest = useRef(load)
  useEffect(() => { loadLatest.current = load }, [load])
  const loadActivity = useCallback(async () => {
    const [status, reactions, pinned] = await Promise.all([
      db!.rpc('st_v2_chat_status', { p_chat: chat.id }),
      db!.from('st_v2_reactions').select('message_id,user_id,reaction').eq('chat_id', chat.id).limit(1000),
      db!.from('st_v2_pins').select('message_id').eq('chat_id', chat.id).maybeSingle(),
    ])
    if (!status.error) setActivity(status.data)
    if (!reactions.error) setReactions(reactions.data)
    if (pinned.error) return
    if (pinned.data) {
      const { data } = await db!.from('st_messages').select('*').eq('id', pinned.data.message_id).maybeSingle()
      setPin(data as Message | null)
    } else setPin(null)
  }, [chat.id])
  useEffect(() => {
    void loadLatest.current()
    const sync = () => { void loadLatest.current(); void loadActivity() }
    const onHint = (event: Event) => { if ((event as MessageEvent).data === chat.id) sync() }
    const onActivity = (event: Event) => { if ((event as MessageEvent).data === chat.id) sync() }
    const channel = liveChannel('thread:' + chat.id, sync)
      .on('postgres_changes', { event: '*', schema: 'public', table: 'st_messages', filter: 'chat_id=eq.' + chat.id }, payload => {
        if (payload.eventType !== 'DELETE'){
          const message=payload.new as Message
          merge([message])
          if(message.reply_to)void loadQuotes([message])
          if(payload.eventType==='UPDATE')setQuotes(current=>current[message.id]?
            {...current,[message.id]:{id:message.id,sender:message.sender,body:message.body.slice(0,240)}}:current)
        }
      })
      .subscribe(status => { if (status === 'SUBSCRIBED') void loadLatest.current() })
    const timer = window.setInterval(sync, 3500)
    const removeReconnect = onReconnect(sync)
    hints.addEventListener('inbox', onHint)
    hints.addEventListener('ready', sync)
    hints.addEventListener('chat_activity', onActivity)
    return () => {
      hints.removeEventListener('inbox', onHint)
      hints.removeEventListener('ready', sync)
      hints.removeEventListener('chat_activity', onActivity)
      removeReconnect()
      window.clearInterval(timer)
      void db!.removeChannel(channel)
    }
  }, [chat.id, hints, merge, loadActivity, loadQuotes])
  useEffect(() => {
    if (!activity?.typing_until) return
    setClock(Date.now())
    const timer = window.setTimeout(() => setClock(Date.now()), Math.max(0, Date.parse(activity.typing_until) - Date.now()) + 30)
    return () => window.clearTimeout(timer)
  }, [activity?.typing_until])
  const latestInbound = messages.findLast(message => message.sender !== self)?.id
  const viewingTasks=Boolean(taskPanel)
  const markRead = useCallback(() => {
    if (blocked || viewingTasks || !latestInbound || document.visibilityState !== 'visible' || !nearBottom.current ||
      readLast.current === latestInbound || results !== null) return
    readLast.current = latestInbound
    void db!.rpc('st_v2_read', { p_chat: chat.id, p_message: latestInbound }).then(({ error }) => {
      if (error && readLast.current === latestInbound) readLast.current = ''
      if (!error) hints.dispatchEvent(new Event('read_local'))
    })
  }, [blocked, chat.id, hints, latestInbound, results, viewingTasks])
  useEffect(() => {
    markRead()
    return onReconnect(markRead)
  }, [markRead])
  useEffect(() => {
    const node = feed.current
    if (node && nearBottom.current) node.scrollTop = node.scrollHeight
  }, [messages])

  async function update(name: string, input: Record<string, unknown>) {
    const { error } = await db!.rpc(name, input)
    if (error) { inform(formatError(error, 'Could not update the conversation.')); return false }
    await Promise.all([load(), loadActivity()])
    if (name === 'st_v2_mute') hints.dispatchEvent(new Event('read_local'))
    return true
  }

  function changeDraft(value: string) {
    setDraft(value)
    const now = Date.now()
    if (!blocked && value.trim() && now - typingLast.current > 2200) {
      typingLast.current = now
      void db!.rpc('st_v2_typing', { p_chat: chat.id, p_active: true })
    }
  }

  async function send(event: FormEvent) {
    event.preventDefault()
    const body = draft.trim()
    if ((!body&&!attachment) || busy || blocked) return
    if(attachment){
      setBusy(true)
      try{
        await sendChatFile(chat.id,attachment.id,attachment.file,body)
        nearBottom.current=true
        setAttachment(null)
        setDraft(previous=>previous.trim()===body?'':previous)
        await load()
      }catch(error){inform(formatError(error,'Could not send the attachment. Try again.'))}
      finally{setBusy(false)}
      return
    }
    const reply = replying?.id ?? null
    const id = pending.current?.body === body && pending.current.reply === reply ? pending.current.id : crypto.randomUUID()
    pending.current = { id, body, reply }
    setBusy(true)
    const { error } = await db!.rpc(reply ? 'st_v2_send_reply' : 'st_send', { p_chat: chat.id, p_id: id, p_body: body, ...(reply ? { p_reply: reply } : {}) })
    if (error) inform(formatError(error, 'Could not send. Your draft is still here.'))
    else {
      pending.current = null
      setReplying(current => current?.id === reply ? null : current)
      nearBottom.current = true
      setDraft(previous => previous.trim() === body ? '' : previous)
      void db!.rpc('st_v2_typing', { p_chat: chat.id, p_active: false })
      void load()
    }
    setBusy(false)
  }

  function pickEmoji(value:string) {
    const range=cursor.current??{start:draft.length,end:draft.length}
    const text=draft.slice(0,range.start)+value+draft.slice(range.end)
    if(text.length>4000){inform('The message exceeds the character limit.');return}
    changeDraft(text);setEmoji(false)
    requestAnimationFrame(()=>{
      composerInput.current?.focus()
      composerInput.current?.setSelectionRange(range.start+value.length,range.start+value.length)
    })
  }

  async function schedule(at:string) {
    const body=draft.trim()
    if(blocked||!body||replying||attachment)throw new Error('Only a plain text draft can be scheduled.')
    const previous=pendingSchedule.current
    const id=previous?.body===body&&previous.at===at?previous.id:crypto.randomUUID()
    pendingSchedule.current={id,body,at}
    const {data,error}=await db!.rpc('st_v6_schedule_message',{p_chat:chat.id,p_id:id,p_body:body,p_send_at:at})
    if(error)throw error
    if(data==='failed'||data==='cancelled')throw new Error('This attempt has closed. Choose a new date and time.')
    pendingSchedule.current=null
    setDraft(previous=>previous.trim()===body?'':previous)
    void db!.rpc('st_v2_typing',{p_chat:chat.id,p_active:false})
  }

  async function download(file:ChatFile) {
    try{ await downloadChatFile(file) }
    catch(error){inform(formatError(error,'Could not download the attachment.'))}
  }
  async function react(messageId:string,value:string) {
    const enabled=!reactions.some(row=>row.message_id===messageId&&row.user_id===self&&row.reaction===value)
    if(await update('st_v2_react',{p_message:messageId,p_reaction:value,p_enabled:enabled})) setReacting(null)
  }

  if(taskPanel)return taskPanel
  return <>
    <div className="thread-toolbar">
      <button type="button" className="secondary" aria-expanded={showSearch} onClick={() => { setShowSearch(!showSearch); setResults(null) }}><Search size={15}/> Search messages</button>
      <button type="button" className="secondary" aria-pressed={Boolean(activity?.muted)}
        onClick={() => void update('st_v2_mute', { p_chat: chat.id, p_muted: !activity?.muted })}>
        {activity?.muted ? <BellOff size={15}/> : <Bell size={15}/>} {activity?.muted ? 'Muted' : 'Mute'}
      </button>
    </div>
    {showSearch && <form className="thread-toolbar" onSubmit={async event => {
      event.preventDefault()
      const query = String(new FormData(event.currentTarget).get('query')).trim()
      const { data, error } = await db!.rpc('st_v2_search_messages', { p_chat: chat.id, p_query: query })
      if (error) inform('Could not search this conversation.')
      else{
        const rows=(data as Message[]).filter(row=>!row.revoked_at&&!revoked.current.has(row.id))
        const removed=rows.length?await db!.from('st_v5_hidden_messages').select('message_id').in('message_id',rows.map(row=>row.id)):null
        if(removed?.error){inform('Could not search this conversation.');return}
        const hiddenIds=new Set(removed?.data?.map(row=>row.message_id))
        const permitted=rows.filter(row=>!hiddenIds.has(row.id)).reverse()
        await loadQuotes(permitted)
        setResults(permitted)
      }
    }}><input name="query" aria-label="Search term" placeholder="Search within this chat" required minLength={2} maxLength={150}/>
      <button className="primary">Search</button>{results && <button className="secondary" type="button" onClick={() => setResults(null)}>Clear</button>}</form>}
    {pin&&!pin.revoked_at&&!hidden.includes(pin.id) && <div className="thread-pin"><Pin size={16}/><span><EmojiText value={pin.body}/></span>{!blocked && <button type="button" className="text-button" onClick={() => void update('st_v2_pin', { p_chat: chat.id, p_message: null })}>Unpin</button>}</div>}
    <div ref={feed} className="feed" role="log" aria-label="Messages" onScroll={() => {
      const node = feed.current
      if (node) nearBottom.current = node.scrollHeight - node.scrollTop - node.clientHeight < 100
      markRead()
    }}>
      {results === null && older && <button type="button" className="secondary older" disabled={loadingOlder} onClick={async () => {
        setLoadingOlder(true)
        nearBottom.current = false
        await load(messages[0])
        setLoadingOlder(false)
      }}>Load earlier messages</button>}
      {results?.length === 0 && <p>No messages match that search.</p>}
      {results === null && loaded && !messages.length && <div className="empty-thread"><div className="card-icon"><MessageCircle size={24}/></div><h2>Say hello</h2><p>This is the start of your conversation.</p></div>}
      {(results ?? messages).filter(message=>!hidden.includes(message.id)).map(message => {
        const own = message.sender === self
        const file=message.revoked_at?undefined:files[message.id]
        const quote=message.reply_to&&!hidden.includes(message.reply_to)&&!revoked.current.has(message.reply_to)
          ? quotes[message.reply_to]:null
        const read = own && activity?.read_at && (message.created_at < activity.read_at || message.created_at === activity.read_at && message.id <= (activity.read_id ?? ''))
        const selectedReactions = reactions.filter(reaction => reaction.message_id === message.id)
        return <div className={'message ' + (own ? 'own' : '')} key={message.id}>
          <div className="message-reaction-header"><strong className="message-sender">{own?selfName+' (you)':peerName}</strong>
            {!blocked&&!message.revoked_at&&<button className="small-icon add-reaction" type="button" title="Add reaction" aria-label="Add reaction"
              onClick={()=>setReacting(message.id)}><Smile size={16}/></button>}
          </div>
          {!message.revoked_at&&selectedReactions.length>0&&<div className="reaction-row">
            {[...new Set(selectedReactions.map(row=>row.reaction))].map(value=>{
              const active=selectedReactions.some(row=>row.reaction===value&&row.user_id===self)
              const count=selectedReactions.filter(row=>row.reaction===value).length
              return <button className="pill" type="button" key={value} aria-pressed={active} disabled={blocked}
                title={active?'Remove your reaction':'Add this reaction'} onClick={()=>void react(message.id,value)}>
                <EmojiText value={value}/> {count}
              </button>
            })}
          </div>}
          {message.reply_to&&!message.revoked_at && <blockquote className="reply-preview">
            {quote?<><strong>{quote.sender===self?selfName:peerName}</strong>{' · '}<EmojiText value={quote.body}/></>:'Original message unavailable'}
          </blockquote>}
          <div className={'bubble'+(message.revoked_at?' revoked-message':'')}>
            {(!file||message.body!=='Attachment: '+file.filename)&&<EmojiText value={message.body}/>}
            {file&&<button className="attachment-file" type="button" onClick={()=>void download(file)}>
              <Download size={16}/><span>{file.filename}<small>{Math.ceil(file.size_bytes/1024)} KiB</small></span>
            </button>}
          </div>
          {!own&&!message.revoked_at && riskIndicators(message.body).map(flag => <p key={flag} className="risk"><ShieldAlert size={14} />{flag}</p>)}
          <div className="message-meta"><time dateTime={message.created_at}>{formatTime(message.created_at)}</time>
            {message.edited_at&&!message.revoked_at && <button type="button" className="text-button" onClick={async () => {
              const { data, error } = await db!.from('st_v2_message_edits').select('id,body,created_at').eq('message_id', message.id).order('id', { ascending: false }).limit(25)
              if (error) inform('Could not load edit history.')
              else setHistory(data)
            }}>Edited</button>}
            {!message.revoked_at && (own ? read ? <CheckCheck size={15} aria-label="Read" /> : <Check size={13} aria-label="Sent" /> :
              <button className="small-icon" title="Report message" aria-label="Report message" onClick={() => onReport(message,file)}><Flag size={13} /></button>)}
            <details className="message-menu">
              <summary className="small-icon" aria-label="Message actions" title="Message actions"><MoreHorizontal size={17}/></summary>
              <div className="message-menu-panel">
                {!blocked&&!message.revoked_at&&<><div className="reaction-row">{reactionOptions.map(option => {
                  const active = selectedReactions.some(row => row.user_id === self && row.reaction === option.emoji)
                  return <button type="button" className="small-icon" key={option.emoji} aria-label={option.label} aria-pressed={active}
                    onClick={() => void react(message.id,option.emoji)}>{option.emoji}</button>
                })}</div>
                <button type="button" className="text-button" onClick={()=>setReacting(message.id)}>More reactions</button>
                <button type="button" className="text-button" onClick={() => void update('st_v2_pin', { p_chat: chat.id, p_message: message.id })}>Pin message</button>
                <button type="button" className="text-button" onClick={() => setReplying(message)}>Reply</button>
                {own&&!file&&Date.now()-Date.parse(message.created_at)<86400000&&<button type="button" className="text-button" onClick={()=>setEditing(message)}>Edit message</button>}</>}
                {file&&<button type="button" className="text-button" onClick={()=>void download(file)}>Download attachment</button>}
                {!message.revoked_at&&<button type="button" className="text-button" onClick={async()=>{
                  const result=await setSavedMessage(message.id,true)
                  inform(result.error?'Could not save this message.':'Message saved. Find it in Inbox → Saved messages.')
                }}>Save message</button>}
                {!blocked&&!message.revoked_at&&<button type="button" className="text-button" onClick={()=>onTask(message.id)}>Create task from message</button>}
                {!own&&!message.revoked_at&&<button type="button" className="text-button" onClick={()=>onReport(message,file)}>Report message</button>}
                <button type="button" className="text-button" onClick={()=>setRemoving({message,action:'hide'})}>Delete for me</button>
                {own&&!message.revoked_at&&<button type="button" className="text-button remove-text" onClick={()=>setRemoving({message,action:'revoke'})}>Revoke for everyone</button>}
              </div>
            </details>
          </div>
        </div>
      })}
    </div>
    {activity?.typing_until && Date.parse(activity.typing_until) > clock && <p className="thread-typing" role="status">Contact is typing…</p>}
    {removing&&<Dialog title={removing.action==='hide'?'Delete for me?':'Revoke for everyone?'} close={()=>setRemoving(null)}>
      <p>{removing.action==='hide'?'This message will be hidden in your SecTalk chat.':'SecTalk will replace this message with a removal notice. Copies already saved and evidence already reported can remain.'}</p>
      <button type="button" className="danger" disabled={busy} onClick={async()=>{
        setBusy(true)
        try{
          if(await update('st_v5_message_action',{p_message:removing.message.id,p_action:removing.action})){
            if(removing.action==='hide') setHidden(previous=>[...new Set([...previous,removing.message.id])])
            else {
              const {data}=await db!.from('st_messages').select('*').eq('id',removing.message.id).maybeSingle()
              if(data)merge([data as Message])
            }
            setHistory(null);setRemoving(null)
          }
        }finally{setBusy(false)}
      }}>{removing.action==='hide'?'Delete for me':'Revoke message'}</button>
    </Dialog>}
    {editing && <Dialog title="Edit message" close={() => setEditing(null)}><form onSubmit={async event => {
      event.preventDefault()
      const body = new FormData(event.currentTarget).get('body')
      if (await update('st_v2_edit_message', { p_message: editing.id, p_body: body })) { setEditing(null); setResults(null) }
    }}><label>Message<textarea name="body" required maxLength={4000} defaultValue={editing.body}/></label><button className="primary">Save changes</button></form></Dialog>}
    {history && <Dialog title="Edit history" close={() => setHistory(null)}>{history.map(edit => <article className="release-board-item" key={edit.id}><time dateTime={edit.created_at}>{new Date(edit.created_at).toLocaleString()}</time><p>{edit.body}</p></article>)}</Dialog>}
    {replying && <div className="thread-pin"><span>Replying to <EmojiText value={replying.body}/></span><button type="button" className="icon" aria-label="Cancel reply" onClick={() => setReplying(null)}><X size={16}/></button></div>}
    {attachment&&<div className="thread-pin"><Paperclip size={16}/><span>{attachment.file.name}</span>
      <button type="button" className="icon" disabled={busy} aria-label="Remove attachment" onClick={()=>setAttachment(null)}><X size={16}/></button>
    </div>}
    {emoji&&<Dialog title="Add emoji" close={()=>setEmoji(false)}><ChatEmoji onPick={pickEmoji}/></Dialog>}
    {reacting&&<Dialog title="Add a reaction" close={()=>setReacting(null)}><ChatEmoji onPick={value=>void react(reacting,value)}/></Dialog>}
    {scheduleOpen&&<Dialog title="Scheduled messages" close={()=>setScheduleOpen(false)}>
      <ScheduledMessages chat={chat.id} draft={draft.trim()} schedule={schedule} canSchedule={!blocked&&Boolean(draft.trim())&&!replying&&!attachment}/>
    </Dialog>}
    <form className="composer" onSubmit={send}>
      <input ref={filePicker} hidden type="file" accept={extensions} onChange={event=>{
        const file=event.target.files?.[0]
        event.target.value=''
        if(!file)return
        if(!supportedFile(file)){inform('Choose an image, PDF or text file up to 4 MiB.');return}
        setReplying(null);setAttachment({file,id:crypto.randomUUID()})
      }}/>
      <button type="button" className="icon" title="Attach file" aria-label="Attach file" disabled={blocked||busy} onClick={()=>filePicker.current?.click()}><Paperclip size={19}/></button>
      <button type="button" className="icon" title="Add emoji" aria-label="Add emoji" disabled={blocked||busy} onClick={()=>{
        if(composerInput.current)cursor.current={start:composerInput.current.selectionStart,end:composerInput.current.selectionEnd}
        setEmoji(true)
      }}><Smile size={20}/></button>
      <textarea ref={composerInput} aria-label="Write a message" placeholder={blocked ? 'Contact blocked' : 'Write a message…'} disabled={blocked} rows={1} maxLength={4000} value={draft} onChange={e => changeDraft(e.target.value)} onKeyDown={event => {
        if (event.key === 'Enter' && !event.shiftKey && !event.nativeEvent.isComposing) { event.preventDefault(); event.currentTarget.form?.requestSubmit() }
      }} />
      <button type="button" className="icon" title="Scheduled messages" aria-label="Scheduled messages" onClick={()=>setScheduleOpen(true)}><CalendarClock size={19}/></button>
      <button className="primary square" title="Send message" aria-label="Send message" disabled={busy||(!draft.trim()&&!attachment)||blocked}><Send size={19} /></button>
    </form>
  </>
}
