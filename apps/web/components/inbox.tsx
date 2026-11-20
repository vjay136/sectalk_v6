'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import {
  ArrowLeft, Ban, Bell, BellOff, CalendarDays, Check, CheckCheck, ChevronRight, CircleHelp, Copy, CreditCard, Flag, Inbox as InboxIcon, LockKeyhole, LogOut, ShieldAlert,
  MessageCircle, Phone, Pin, Plus, Search, Send, Shield, ShieldCheck, UserRound, Users, Video, X,
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
import { Vault } from './vault'
import { GlobalSearch, Notifications } from './discover'
import { SectionTabs } from './section-tabs'

export function Avatar({ name, tint = 'green' }: { name: string; tint?: string }) {
  const initials = name.trim().split(/\s+/).slice(0, 2).map(word => [...word][0]).join('').toUpperCase()
  return <span className={'avatar ' + tint} aria-hidden="true">{initials || '?'}</span>
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
  const [tab, setTab] = useState<'inbox' | 'calls' | 'safety' | 'profile' | 'workspaces' | 'billing' | 'meetings' | 'vault' | 'search' | 'notifications'>(() =>
    typeof window !== 'undefined' && new URLSearchParams(window.location.search).has('billing') ? 'billing' : 'inbox')
  const [mode, setMode] = useState<'chats' | 'requests'>('chats')
  const [profileTab, setProfileTab] = useState<'account' | 'availability'>('account')
  const [search, setSearch] = useState('')
  const [notice, setNotice] = useState('')
  const [newContact, setNewContact] = useState(false)
  const [report, setReport] = useState<{ chat: string; message: Message | null } | null>(null)
  const [blockCheck, setBlockCheck] = useState(false)
  const [online, setOnline] = useState(false)
  const [broadcastOnline, setBroadcastOnline] = useState(false)
  const [working, setWorking] = useState(false)
  const [requestedMeeting,setRequestedMeeting] = useState<string|null>(null)
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
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase()==='k' && !document.querySelector('dialog[open]')) {
        event.preventDefault()
        setTab('search')
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
  const blocked = chat ? blocks.includes(peerId(chat, user)) : false
  const requests = chats.filter(item => item.status === 'pending' && item.requester !== user && !blocks.includes(peerId(item, user)))
  const visible = chats.filter(item => (mode === 'requests' ? item.status === 'pending' : item.status === 'accepted') &&
    (!search || [profiles[peerId(item, user)]?.name, profiles[peerId(item, user)]?.handle]
      .some(value => value?.toLowerCase().includes(search.toLowerCase().trim()))))
  const callerId = call.call ? (call.call.caller === user ? call.call.callee : call.call.caller) : ''

  function select(id: string | null) {
    setSelected(id)
    setBlockCheck(false)
    setTab('inbox')
  }
  function openMeeting(id:string) {
    setRequestedMeeting(id)
    setTab('meetings')
  }

  async function run(name: string, input: Record<string, unknown>, success: () => void = () => {}) {
    if (working) return
    setWorking(true)
    try {
      const { data, error } = await db!.rpc(name, input)
      if (error) throw error
      if (name === 'st_request' && !data) throw new Error('This contact is unavailable.')
      success()
      await refresh()
      if (name === 'st_request') select(data)
    } catch (error) {
      setNotice(formatError(error, 'Please try again.'))
    } finally {
      setWorking(false)
    }
  }

  if (profile === undefined) return <main className="center-page"><Brand /><p role="status">{notice || 'Loading your workspace…'}</p>{notice && <button className="secondary" onClick={refresh}>Try again</button>}<button className="text-button" onClick={() => void db!.auth.signOut({ scope: 'local' })}>Sign out</button></main>
  if (!profile) return <main className="center-page"><Brand /><ProfileForm profile={null} onSave={refresh} /><button className="text-button" onClick={() => void db!.auth.signOut({ scope: 'local' })}>Sign out</button></main>

  return <main className={'workspace ' + (selected && tab === 'inbox' ? 'thread-open' : '') + (tab !== 'inbox' ? ' full-panel' : '')}>
    <nav className="rail" aria-label="SecTalk features">
      <Brand compact />
      <button className={tab === 'inbox' ? 'active' : ''} aria-current={tab === 'inbox' ? 'page' : undefined} onClick={() => setTab('inbox')}><MessageCircle size={20} /><span>Inbox</span></button>
      <button className={tab === 'calls' ? 'active' : ''} aria-current={tab === 'calls' ? 'page' : undefined} onClick={() => setTab('calls')}><Phone size={19} /><span>Calls</span></button>
      <button className={tab === 'workspaces' ? 'active' : ''} aria-current={tab === 'workspaces' ? 'page' : undefined} onClick={() => setTab('workspaces')}><Users size={19} /><span>Workspaces</span></button>
      <button className={tab==='meetings'?'active':''} aria-current={tab==='meetings'?'page':undefined} onClick={()=>{setRequestedMeeting(null);setTab('meetings')}}><CalendarDays size={19}/><span>Meetings</span></button>
      <button className={tab==='vault'?'active':''} aria-current={tab==='vault'?'page':undefined} onClick={()=>setTab('vault')}><LockKeyhole size={19}/><span>Vault</span></button>
      <button className={tab==='search'?'active':''} aria-current={tab==='search'?'page':undefined} title="Search (Ctrl or Command + K)" onClick={()=>setTab('search')}><Search size={19}/><span>Search</span></button>
      <button className={tab==='notifications'?'active':''} aria-current={tab==='notifications'?'page':undefined} onClick={()=>setTab('notifications')}><Bell size={19}/><span>Notifications</span></button>
      <button className={tab === 'safety' ? 'active' : ''} aria-current={tab === 'safety' ? 'page' : undefined} onClick={() => setTab('safety')}><Shield size={20} /><span>Safety</span></button>
      <div className="rail-end"><button className={tab === 'billing' ? 'active' : ''} aria-current={tab === 'billing' ? 'page' : undefined} onClick={() => setTab('billing')}><CreditCard size={19} /><span>Billing</span></button><button className={tab === 'profile' ? 'active' : ''} aria-current={tab === 'profile' ? 'page' : undefined} onClick={() => setTab('profile')}><UserRound size={20} /><span>Profile</span></button>
        <button onClick={async () => { await call.end(); void db!.auth.signOut({ scope: 'local' }) }}><LogOut size={19} /><span>Sign out</span></button></div>
    </nav>
    <aside className="inbox-list">
      <header><Brand /><div className="inbox-heading"><h1>Inbox</h1><button className="primary square" onClick={() => setNewContact(true)} title="New contact" aria-label="New contact"><Plus size={21} /></button></div>
        <div className="input-icon search"><Search size={17} /><input aria-label="Search contacts" placeholder="Search contacts" value={search} onChange={e => setSearch(e.target.value)} /></div>
      </header>
      <div className="tabs" aria-label="Conversation filters">
        <button aria-pressed={mode === 'chats'} className={mode === 'chats' ? 'active' : ''} onClick={() => setMode('chats')}>Chats</button>
        <button aria-pressed={mode === 'requests'} className={mode === 'requests' ? 'active' : ''} onClick={() => setMode('requests')}>Requests {requests.length > 0 && <span>{requests.length}</span>}</button>
      </div>
      <div className="chat-list">
        {visible.length === 0 && <div className="list-empty"><InboxIcon size={22} /><strong>{search ? 'No matching contacts' : mode === 'requests' ? 'No pending requests' : 'No conversations yet'}</strong><p>{!search && mode === 'chats' ? 'Send a request to someone you know.' : ''}</p></div>}
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
      <div className="list-footer"><Avatar name={profile.name} /><div><strong>{profile.name}</strong><small>@{profile.handle}</small></div><span className={'status-dot ' + (online || broadcastOnline ? '' : 'offline')} title={online || broadcastOnline ? 'Live updates connected' : 'Syncing'} /></div>
    </aside>
    {tab === 'profile' ? <section className="content-page"><h1>Profile</h1>
      <SectionTabs label="Profile sections" value={profileTab} onChange={setProfileTab} options={ [['account', 'Account'], ['availability', 'Availability']] }/>
      {profileTab === 'account' ? <><div className="profile-handle"><code>@{profile.handle}</code><button className="secondary" onClick={async () => {
        try { await navigator.clipboard.writeText(profile.handle); setNotice('Handle copied.') }
        catch { setNotice('Could not copy your handle. Select and copy it from your profile.') }
      }}><Copy size={15} /> Copy handle</button></div>
      <ProfileForm profile={profile} onSave={refresh} /></> :
      <div className="panel release-panel"><label>Availability for approved contacts
        <select value={presence[user]?.state||'offline'} disabled={working} onChange={event=>void run('st_v3_set_presence',{p_state:event.target.value})}>
          <option value="offline">Hidden</option><option value="online">Online</option><option value="away">Away</option><option value="busy">Busy</option>
        </select></label><p>Availability expires while you are away from SecTalk.</p></div>}
      </section> :
      tab === 'safety' ? <Safety staff={staff} refresh={refresh} /> :
      tab === 'workspaces' ? <Workspaces user={user} /> :
      tab === 'billing' ? <Billing user={user} /> :
      tab === 'meetings' ? <Meetings key={requestedMeeting||'all'} requested={requestedMeeting} user={user}/> :
      tab === 'vault' ? <Vault user={user}/> :
      tab === 'search' ? <GlobalSearch openChat={select} openMeeting={openMeeting}/> :
      tab === 'notifications' ? <Notifications user={user} openMeeting={openMeeting}/> :
      tab === 'calls' ? <Calls user={user} chats={chats} profiles={profiles} blocks={blocks} state={call} openChat={select} openInbox={() => setTab('inbox')} /> :
      chat ? <section className="thread">
        <header className="thread-header"><button className="icon mobile-back" aria-label="Back to inbox" onClick={() => select(null)}><ArrowLeft size={20} /></button><Avatar name={peer?.name || 'Contact'} />
          <div><h2>{peer?.name || 'Contact'}</h2><p>{blocked ? 'Blocked' : peerState ? peerState[0].toUpperCase()+peerState.slice(1) : chat.status === 'accepted' ? 'Accepted contact' : 'Contact request'}</p></div>
          <div className="thread-actions">
            {chat.status === 'accepted' && !blocked && <>
              <button className="icon" disabled={call.busy || !!call.call} aria-label="Start audio call" title="Start audio call" onClick={() => void call.start(chat.id, false)}><Phone size={18} /></button>
              <button className="icon" disabled={call.busy || !!call.call} aria-label="Start video call" title="Start video call" onClick={() => void call.start(chat.id, true)}><Video size={20} /></button>
            </>}
            <button className="icon" title="Report contact" aria-label="Report contact" onClick={() => setReport({ chat: chat.id, message: null })}><Flag size={18} /></button>
            <button className="icon" title={blocked ? 'Unblock contact' : 'Block contact'} aria-label={blocked ? 'Unblock contact' : 'Block contact'} onClick={() => setBlockCheck(true)}><Ban size={18} /></button>
          </div>
        </header>
        {blockCheck && <div className="inline-warning"><span>{blocked ? 'Allow this contact to reach you again?' : 'Block new messages and calls from this contact?'}</span><button className="danger" disabled={working} onClick={() => void run('st_set_block', { p_chat: chat.id, p_block: !blocked }, () => { setBlockCheck(false); setNotice(blocked ? 'Contact unblocked.' : 'Contact blocked.') })}>{blocked ? 'Unblock' : 'Block'}</button><button className="secondary" onClick={() => setBlockCheck(false)}>Cancel</button></div>}
        {chat.status === 'accepted' ? <Thread key={chat.id} chat={chat} self={user} hints={hints} blocked={blocked} inform={setNotice} onReport={message => setReport({ chat: chat.id, message })} /> :
          <div className="empty-thread"><div className="card-icon"><ShieldCheck size={26} /></div>
            <h2>{chat.status === 'declined' ? 'Request declined' : chat.requester === user ? 'Request sent' : 'New contact request'}</h2>
            <p>{chat.status === 'declined' ? 'This conversation is closed.' : chat.requester === user ? 'You can chat and call once this contact accepts.' : 'Accept to allow this person to message or call you.'}</p>
            {chat.status === 'pending' && chat.requester !== user && !blocked && <div className="action-row">
              <button className="primary" disabled={working} onClick={() => void run('st_respond', { p_chat: chat.id, p_accept: true }, () => setMode('chats'))}><Check size={17} /> Accept</button>
              <button className="secondary" disabled={working} onClick={() => void run('st_respond', { p_chat: chat.id, p_accept: false })}>Decline</button>
            </div>}
          </div>}
      </section> : <section className="thread"><header className="thread-header default-header"><h2>Messages</h2><span className="pill"><span className={'status-dot ' + (online || broadcastOnline ? '' : 'offline')} />{online || broadcastOnline ? 'Live updates' : 'Syncing'}</span></header>
        <div className="empty-thread welcome-thread"><div className="card-icon"><MessageCircle size={27}/></div><h2>Your conversations</h2><p>Choose a chat or add a contact to start talking.</p><button className="primary" onClick={() => setNewContact(true)}><Plus size={17} /> New contact</button></div>
      </section>}
    {notice && <div className="toast" role="status"><CircleHelp size={18} /><span>{notice}</span><button className="icon" aria-label="Dismiss notice" onClick={() => setNotice('')}><X size={17}/></button></div>}
    {newContact && <Dialog title="New contact" close={() => setNewContact(false)}><form onSubmit={event => {
      event.preventDefault()
      const value = new FormData(event.currentTarget).get('handle')
      void run('st_request', { p_handle: value }, () => { setNewContact(false); setMode('requests') })
    }}><p>Send a request using the contact’s exact SecTalk handle.</p><label>SecTalk handle<input name="handle" required maxLength={24} pattern="[a-zA-Z0-9_]{3,24}" placeholder="e.g. avery_m" /></label><button className="primary" disabled={working}>Send request <Send size={16}/></button></form></Dialog>}
    {report && <ReportDialog chat={report.chat} message={report.message} close={() => setReport(null)} inform={setNotice} />}
    {call.call && <CallPanel key={call.call.id} state={call} self={user} name={profiles[callerId]?.name || 'Contact'} />}
  </main>
}

function Calls({ user, chats, profiles, blocks, state, openChat, openInbox }: {
  user: string; chats: Chat[]; profiles: Record<string, Profile>; blocks: string[];
  state: ReturnType<typeof useCalling>; openChat: (id: string) => void; openInbox: () => void
}) {
  const [rows, setRows] = useState<Call[] | null>(null)
  const [filter, setFilter] = useState<'all' | 'audio' | 'video'>('all')
  const [error, setError] = useState(false)
  const reload = useCallback(async () => {
    const { data, error } = await db!.from('st_calls').select('*')
      .or('caller.eq.' + user + ',callee.eq.' + user).order('created_at', { ascending: false }).limit(40)
    setError(!!error)
    if (data) setRows(data as Call[])
  }, [user])
  useEffect(() => { void reload() }, [reload, state.historyVersion])
  const visibleCalls = rows?.filter(row => filter === 'all' || row.video === (filter === 'video'))

  return <section className="content-page">
    <header className="content-title"><div className="card-icon"><Phone size={22} /></div><div><h1>Calls</h1><p>Start a call from an approved conversation or return a recent call.</p></div></header>
    <SectionTabs label="Call history" value={filter} onChange={setFilter} options={ [['all', 'All calls'], ['audio', 'Audio'], ['video', 'Video']] }/>
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
        const status = row.status === 'active' && Date.parse(row.expires_at) > Date.now() ? 'In progress'
          : row.status === 'ringing' ? Date.parse(row.expires_at) > Date.now() ? 'Ringing' : incoming ? 'Missed' : 'No answer' : 'Ended'
        return <div className="report-row" key={row.id}>
          <Avatar name={name} />
          <div><strong>{name}</strong><small>{incoming ? 'Incoming' : 'Outgoing'} {row.video ? 'video' : 'audio'} · {new Date(row.created_at).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}</small><span className="call-state">{status}</span></div>
          {reachable && <span className="call-history-controls">
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

function Thread({ chat, self, hints, blocked, onReport, inform }: {
  chat: Chat; self: string; hints: EventTarget; blocked: boolean; onReport: (message: Message) => void; inform: (notice: string) => void
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
  const [replying, setReplying] = useState<Message | null>(null)
  const [history, setHistory] = useState<{ id: number; body: string; created_at: string }[] | null>(null)
  const [clock, setClock] = useState(0)
  const typingLast = useRef(0)
  const readLast = useRef('')
  const [older, setOlder] = useState(false)
  const [busy, setBusy] = useState(false)
  const feed = useRef<HTMLDivElement>(null)
  const nearBottom = useRef(true)
  const pending = useRef<{ id: string; body: string; reply: string | null } | null>(null)
  const [loadingOlder, setLoadingOlder] = useState(false)
  const merge = useCallback((rows: Message[]) => {
    setMessages(previous => [...new Map([...previous, ...rows].map(row => [row.id, row])).values()]
      .sort((a, b) => a.created_at.localeCompare(b.created_at) || a.id.localeCompare(b.id)))
  }, [])

  const load = useCallback(async (before?: Message) => {
    let query = db!.from('st_messages').select('*').eq('chat_id', chat.id)
    if (before) query = query.or('created_at.lt.' + before.created_at + ',and(created_at.eq.' + before.created_at + ',id.lt.' + before.id + ')')
    const { data, error } = await query.order('created_at', { ascending: false }).order('id', { ascending: false }).limit(51)
    if (error) { inform('Could not sync messages.'); return }
    if (before || !loaded) setOlder(data.length > 50)
    merge(data.slice(0, 50))
    setLoaded(true)
  }, [chat.id, inform, loaded, merge])

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
        if (payload.eventType !== 'DELETE') merge([payload.new as Message])
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
  }, [chat.id, hints, merge, loadActivity])
  useEffect(() => {
    if (!activity?.typing_until) return
    setClock(Date.now())
    const timer = window.setTimeout(() => setClock(Date.now()), Math.max(0, Date.parse(activity.typing_until) - Date.now()) + 30)
    return () => window.clearTimeout(timer)
  }, [activity?.typing_until])
  const latestInbound = messages.findLast(message => message.sender !== self)?.id
  const markRead = useCallback(() => {
    if (blocked || !latestInbound || document.visibilityState !== 'visible' || !nearBottom.current ||
      readLast.current === latestInbound || results !== null) return
    readLast.current = latestInbound
    void db!.rpc('st_v2_read', { p_chat: chat.id, p_message: latestInbound }).then(({ error }) => {
      if (error && readLast.current === latestInbound) readLast.current = ''
      if (!error) hints.dispatchEvent(new Event('read_local'))
    })
  }, [blocked, chat.id, hints, latestInbound, results])
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
    if (!body || busy || blocked) return
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
      else setResults((data as Message[]).reverse())
    }}><input name="query" aria-label="Search term" placeholder="Search within this chat" required minLength={2} maxLength={150}/>
      <button className="primary">Search</button>{results && <button className="secondary" type="button" onClick={() => setResults(null)}>Clear</button>}</form>}
    {pin && <div className="thread-pin"><Pin size={16}/><span title={pin.body}>{pin.body}</span>{!blocked && <button type="button" className="text-button" onClick={() => void update('st_v2_pin', { p_chat: chat.id, p_message: null })}>Unpin</button>}</div>}
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
      {(results ?? messages).map(message => {
        const own = message.sender === self
        const read = own && activity?.read_at && (message.created_at < activity.read_at || message.created_at === activity.read_at && message.id <= (activity.read_id ?? ''))
        const selectedReactions = reactions.filter(reaction => reaction.message_id === message.id)
        return <div className={'message ' + (own ? 'own' : '')} key={message.id}>
          {message.reply_to && <blockquote className="reply-preview">{messages.find(row => row.id === message.reply_to)?.body || 'Reply to an earlier message'}</blockquote>}
          <div className="bubble">{message.body}</div>
          {!own && riskIndicators(message.body).map(flag => <p key={flag} className="risk"><ShieldAlert size={14} />{flag}</p>)}
          {selectedReactions.length > 0 && <div className="reaction-row">{reactionOptions.filter(option => selectedReactions.some(row => row.reaction === option.emoji)).map(option => <span className="pill" key={option.emoji}>{option.emoji} {selectedReactions.filter(row => row.reaction === option.emoji).length}</span>)}</div>}
          <div className="message-meta"><time dateTime={message.created_at}>{formatTime(message.created_at)}</time>
            {message.edited_at && <button type="button" className="text-button" onClick={async () => {
              const { data, error } = await db!.from('st_v2_message_edits').select('id,body,created_at').eq('message_id', message.id).order('id', { ascending: false }).limit(25)
              if (error) inform('Could not load edit history.')
              else setHistory(data)
            }}>Edited</button>}
            {own ? read ? <CheckCheck size={15} aria-label="Read" /> : <Check size={13} aria-label="Sent" /> :
              <button className="small-icon" title="Report message" aria-label="Report message" onClick={() => onReport(message)}><Flag size={13} /></button>}
            {!blocked && <details className="message-menu">
              <summary aria-label="Message actions">•••</summary>
              <div className="message-menu-panel">
                <div className="reaction-row">{reactionOptions.map(option => {
                  const active = selectedReactions.some(row => row.user_id === self && row.reaction === option.emoji)
                  return <button type="button" className="small-icon" key={option.emoji} aria-label={option.label} aria-pressed={active}
                    onClick={() => void update('st_v2_react', { p_message: message.id, p_reaction: option.emoji, p_enabled: !active })}>{option.emoji}</button>
                })}</div>
                <button type="button" className="text-button" onClick={() => void update('st_v2_pin', { p_chat: chat.id, p_message: message.id })}>Pin message</button>
                <button type="button" className="text-button" onClick={() => setReplying(message)}>Reply</button>
                {own && Date.now() - Date.parse(message.created_at) < 86400000 && <button type="button" className="text-button" onClick={() => setEditing(message)}>Edit message</button>}
              </div>
            </details>}
          </div>
        </div>
      })}
    </div>
    {activity?.typing_until && Date.parse(activity.typing_until) > clock && <p className="thread-typing" role="status">Contact is typing…</p>}
    {editing && <Dialog title="Edit message" close={() => setEditing(null)}><form onSubmit={async event => {
      event.preventDefault()
      const body = new FormData(event.currentTarget).get('body')
      if (await update('st_v2_edit_message', { p_message: editing.id, p_body: body })) { setEditing(null); setResults(null) }
    }}><label>Message<textarea name="body" required maxLength={4000} defaultValue={editing.body}/></label><button className="primary">Save changes</button></form></Dialog>}
    {history && <Dialog title="Edit history" close={() => setHistory(null)}>{history.map(edit => <article className="release-board-item" key={edit.id}><time dateTime={edit.created_at}>{new Date(edit.created_at).toLocaleString()}</time><p>{edit.body}</p></article>)}</Dialog>}
    {replying && <div className="thread-pin"><span>Replying to {replying.body}</span><button type="button" className="icon" aria-label="Cancel reply" onClick={() => setReplying(null)}><X size={16}/></button></div>}
    <form className="composer" onSubmit={send}>
      <textarea aria-label="Write a message" placeholder={blocked ? 'Contact blocked' : 'Write a message…'} disabled={blocked} required rows={1} maxLength={4000} value={draft} onChange={e => changeDraft(e.target.value)} onKeyDown={event => {
        if (event.key === 'Enter' && !event.shiftKey && !event.nativeEvent.isComposing) { event.preventDefault(); event.currentTarget.form?.requestSubmit() }
      }} />
      <button className="primary square" title="Send message" aria-label="Send message" disabled={busy || !draft.trim() || blocked}><Send size={19} /></button>
    </form>
  </>
}
