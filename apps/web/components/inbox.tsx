'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import {
  ArrowLeft, Ban, Check, ChevronRight, CircleHelp, Copy, Flag, Inbox as InboxIcon, LogOut, ShieldAlert,
  MessageCircle, Phone, Plus, Search, Send, Shield, ShieldCheck, UserRound, Video, X,
} from 'lucide-react'
import { db, formatError, formatTime, liveChannel, onReconnect, peerId, type Call, type Chat, type Message, type Profile } from '../lib/data'
import { useCalling } from '../lib/calling'
import { riskIndicators } from '../lib/safety.mjs'
import { CallPanel } from './call-panel'
import { Brand } from './entry'
import { ReportDialog, Safety } from './safety'

export function Avatar({ name, tint = 'green' }: { name: string; tint?: string }) {
  const initials = name.trim().split(/\s+/).slice(0, 2).map(word => [...word][0]).join('').toUpperCase()
  return <span className={'avatar ' + tint} aria-hidden="true">{initials || '?'}</span>
}

export function Inbox({ user }: { user: string }) {
  const [profile, setProfile] = useState<Profile | null | undefined>()
  const [profiles, setProfiles] = useState<Record<string, Profile>>({})
  const [chats, setChats] = useState<Chat[]>([])
  const [blocks, setBlocks] = useState<string[]>([])
  const [staff, setStaff] = useState('none')
  const [selected, setSelected] = useState<string | null>(null)
  const [tab, setTab] = useState<'inbox' | 'calls' | 'safety' | 'profile'>('inbox')
  const [mode, setMode] = useState<'chats' | 'requests'>('chats')
  const [search, setSearch] = useState('')
  const [notice, setNotice] = useState('')
  const [newContact, setNewContact] = useState(false)
  const [report, setReport] = useState<{ chat: string; message: Message | null } | null>(null)
  const [blockCheck, setBlockCheck] = useState(false)
  const [online, setOnline] = useState(false)
  const [broadcastOnline, setBroadcastOnline] = useState(false)
  const [working, setWorking] = useState(false)
  const readVersion = useRef(0)
  const [hints] = useState(() => new EventTarget())
  const call = useCalling(user, setNotice, hints)

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
    if (!ids.length) return
    const { data } = await db!.from('st_profiles').select('*').in('id', ids)
    if (version === readVersion.current && data) setProfiles(Object.fromEntries(data.map(person => [person.id, person])))
  }, [user])

  useEffect(() => {
    void refresh()
    const account = db!.channel('st:account:' + user, { config: { private: true } })
      .on('broadcast', { event: 'inbox' }, ({ payload }) => {
        if (typeof payload?.chat_id === 'string') {
          hints.dispatchEvent(new MessageEvent('inbox', { data: payload.chat_id }))
          void refresh()
        }
      })
      .on('broadcast', { event: 'call' }, () => hints.dispatchEvent(new Event('call')))
      .on('broadcast', { event: 'signal' }, ({ payload }) => {
        if (typeof payload?.call_id === 'string') hints.dispatchEvent(new MessageEvent('signal', { data: payload.call_id }))
      })
      .subscribe(status => {
        setBroadcastOnline(status === 'SUBSCRIBED')
        if (status === 'SUBSCRIBED') {
          hints.dispatchEvent(new Event('ready'))
          void refresh()
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
      removeReconnect()
      window.clearInterval(timer)
      subscription.data.subscription.unsubscribe()
      void db!.removeChannel(account)
      void db!.removeChannel(channel)
    }
  }, [user, refresh, hints])

  const chat = chats.find(item => item.id === selected)
  const peer = chat ? profiles[peerId(chat, user)] : undefined
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
    <nav className="rail" aria-label="Workspace">
      <Brand compact />
      <button className={tab === 'inbox' ? 'active' : ''} aria-current={tab === 'inbox' ? 'page' : undefined} onClick={() => setTab('inbox')}><MessageCircle size={20} /><span>Inbox</span></button>
      <button className={tab === 'calls' ? 'active' : ''} aria-current={tab === 'calls' ? 'page' : undefined} onClick={() => setTab('calls')}><Phone size={19} /><span>Calls</span></button>
      <button className={tab === 'safety' ? 'active' : ''} aria-current={tab === 'safety' ? 'page' : undefined} onClick={() => setTab('safety')}><Shield size={20} /><span>Safety</span></button>
      <div className="rail-end"><button className={tab === 'profile' ? 'active' : ''} aria-current={tab === 'profile' ? 'page' : undefined} onClick={() => setTab('profile')}><UserRound size={20} /><span>Profile</span></button>
        <button onClick={async () => { await call.end(); void db!.auth.signOut({ scope: 'local' }) }}><LogOut size={19} /><span>Sign out</span></button></div>
    </nav>
    <aside className="inbox-list">
      <header><Brand /><div className="inbox-heading"><h1>Inbox</h1><button className="primary square" onClick={() => setNewContact(true)} title="New contact" aria-label="New contact"><Plus size={21} /></button></div>
        <div className="input-icon search"><Search size={17} /><input aria-label="Search contacts" placeholder="Search contacts" value={search} onChange={e => setSearch(e.target.value)} /></div>
      </header>
      <div className="tabs" aria-label="Conversation filters">
        <button className={mode === 'chats' ? 'active' : ''} onClick={() => setMode('chats')}>Chats</button>
        <button className={mode === 'requests' ? 'active' : ''} onClick={() => setMode('requests')}>Requests {requests.length > 0 && <span>{requests.length}</span>}</button>
      </div>
      <div className="chat-list">
        {visible.length === 0 && <div className="list-empty"><InboxIcon size={22} /><strong>{search ? 'No matching contacts' : mode === 'requests' ? 'No pending requests' : 'No conversations yet'}</strong><p>{!search && mode === 'chats' ? 'Send a request to someone you know.' : ''}</p></div>}
        {visible.map(item => {
          const person = profiles[peerId(item, user)]
          return <button key={item.id} className={'chat-item ' + (item.id === selected ? 'selected' : '')} onClick={() => select(item.id)}>
            <Avatar name={person?.name || 'Contact'} tint={item.status === 'pending' ? 'peach' : 'green'} />
            <span><strong>{person?.name || 'Contact'}</strong><small>{blocks.includes(peerId(item, user)) ? 'Blocked' : person ? '@' + person.handle : 'Contact'}</small></span><ChevronRight size={15} />
          </button>
        })}
      </div>
      <div className="list-footer"><Avatar name={profile.name} /><div><strong>{profile.name}</strong><small>@{profile.handle}</small></div><span className={'status-dot ' + (online || broadcastOnline ? '' : 'offline')} title={online || broadcastOnline ? 'Live updates connected' : 'Syncing'} /></div>
    </aside>
    {tab === 'profile' ? <section className="content-page"><h1>Profile</h1>
      <div className="profile-handle"><code>@{profile.handle}</code><button className="secondary" onClick={async () => {
        try { await navigator.clipboard.writeText(profile.handle); setNotice('Handle copied.') }
        catch { setNotice('Could not copy your handle. Select and copy it from your profile.') }
      }}><Copy size={15} /> Copy handle</button></div><ProfileForm profile={profile} onSave={refresh} /></section> :
      tab === 'safety' ? <Safety staff={staff} refresh={refresh} /> :
      tab === 'calls' ? <Calls user={user} chats={chats} profiles={profiles} blocks={blocks} state={call} openChat={select} openInbox={() => setTab('inbox')} /> :
      chat ? <section className="thread">
        <header className="thread-header"><button className="icon mobile-back" aria-label="Back to inbox" onClick={() => select(null)}><ArrowLeft size={20} /></button><Avatar name={peer?.name || 'Contact'} />
          <div><h2>{peer?.name || 'Contact'}</h2><p>{blocked ? 'Blocked' : chat.status === 'accepted' ? 'Accepted contact' : 'Contact request'}</p></div>
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
  const [error, setError] = useState(false)
  const reload = useCallback(async () => {
    const { data, error } = await db!.from('st_calls').select('*')
      .or('caller.eq.' + user + ',callee.eq.' + user).order('created_at', { ascending: false }).limit(40)
    setError(!!error)
    if (data) setRows(data as Call[])
  }, [user])
  useEffect(() => { void reload() }, [reload, state.historyVersion])

  return <section className="content-page">
    <header className="content-title"><div className="card-icon"><Phone size={22} /></div><div><h1>Calls</h1><p>Start a call from an approved conversation or return a recent call.</p></div></header>
    <div className="panel">
      <div className="panel-header"><h2>Recent calls</h2><button className="secondary" onClick={openInbox}>Open inbox <ChevronRight size={16} /></button></div>
      {error && <div className="list-empty"><p role="alert">Could not load call history.</p><button className="secondary" onClick={reload}>Try again</button></div>}
      {!error && rows === null && <div className="list-empty" role="status">Loading calls…</div>}
      {!error && rows?.length === 0 && <div className="list-empty"><Phone size={22} /><strong>No calls yet</strong><p>Open a chat and choose Audio or Video.</p></div>}
      {rows?.map(row => {
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

function Thread({ chat, self, hints, blocked, onReport, inform }: {
  chat: Chat; self: string; hints: EventTarget; blocked: boolean; onReport: (message: Message) => void; inform: (notice: string) => void
}) {
  const [messages, setMessages] = useState<Message[]>([])
  const [draft, setDraft] = useState('')
  const [loaded, setLoaded] = useState(false)
  const [older, setOlder] = useState(false)
  const [busy, setBusy] = useState(false)
  const feed = useRef<HTMLDivElement>(null)
  const nearBottom = useRef(true)
  const pending = useRef<{ id: string; body: string } | null>(null)
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
  useEffect(() => {
    void loadLatest.current()
    const sync = () => void loadLatest.current()
    const onHint = (event: Event) => { if ((event as MessageEvent).data === chat.id) sync() }
    const channel = liveChannel('thread:' + chat.id, sync)
      .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'st_messages', filter: 'chat_id=eq.' + chat.id }, payload => merge([payload.new as Message]))
      .subscribe(status => { if (status === 'SUBSCRIBED') void loadLatest.current() })
    const timer = window.setInterval(sync, 3500)
    const removeReconnect = onReconnect(sync)
    hints.addEventListener('inbox', onHint)
    hints.addEventListener('ready', sync)
    return () => {
      hints.removeEventListener('inbox', onHint)
      hints.removeEventListener('ready', sync)
      removeReconnect()
      window.clearInterval(timer)
      void db!.removeChannel(channel)
    }
  }, [chat.id, hints, merge])
  useEffect(() => {
    const node = feed.current
    if (node && nearBottom.current) node.scrollTop = node.scrollHeight
  }, [messages])

  async function send(event: FormEvent) {
    event.preventDefault()
    const body = draft.trim()
    if (!body || busy || blocked) return
    const id = pending.current?.body === body ? pending.current.id : crypto.randomUUID()
    pending.current = { id, body }
    setBusy(true)
    const { error } = await db!.rpc('st_send', { p_chat: chat.id, p_id: id, p_body: body })
    if (error) inform(formatError(error, 'Could not send. Your draft is still here.'))
    else {
      pending.current = null
      nearBottom.current = true
      setDraft(previous => previous.trim() === body ? '' : previous)
      void load()
    }
    setBusy(false)
  }

  return <>
    <div ref={feed} className="feed" role="log" aria-label="Messages" onScroll={() => {
      const node = feed.current
      if (node) nearBottom.current = node.scrollHeight - node.scrollTop - node.clientHeight < 100
    }}>
      {older && <button type="button" className="secondary older" disabled={loadingOlder} onClick={async () => {
        setLoadingOlder(true)
        nearBottom.current = false
        await load(messages[0])
        setLoadingOlder(false)
      }}>Load earlier messages</button>}
      {loaded && !messages.length && <div className="empty-thread"><div className="card-icon"><MessageCircle size={24}/></div><h2>Say hello</h2><p>This is the start of your conversation.</p></div>}
      {messages.map(message => {
        const own = message.sender === self
        return <div className={'message ' + (own ? 'own' : '')} key={message.id}>
          <div className="bubble">{message.body}</div>
          {!own && riskIndicators(message.body).map(flag => <p key={flag} className="risk"><ShieldAlert size={14} />{flag}</p>)}
          <div className="message-meta"><time dateTime={message.created_at}>{formatTime(message.created_at)}</time>{own ? <Check size={13} aria-label="Sent" /> :
            <button className="small-icon" title="Report message" aria-label="Report message" onClick={() => onReport(message)}><Flag size={13} /></button>}</div>
        </div>
      })}
    </div>
    <form className="composer" onSubmit={send}>
      <textarea aria-label="Write a message" placeholder={blocked ? 'Contact blocked' : 'Write a message…'} disabled={blocked} required rows={1} maxLength={4000} value={draft} onChange={e => setDraft(e.target.value)} onKeyDown={event => {
        if (event.key === 'Enter' && !event.shiftKey && !event.nativeEvent.isComposing) { event.preventDefault(); event.currentTarget.form?.requestSubmit() }
      }} />
      <button className="primary square" title="Send message" aria-label="Send message" disabled={busy || !draft.trim() || blocked}><Send size={19} /></button>
    </form>
  </>
}
