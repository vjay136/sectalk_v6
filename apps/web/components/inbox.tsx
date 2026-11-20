'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import dynamic from 'next/dynamic'
import {
  ArrowLeft, Ban, Bell, BellOff, Bookmark, CalendarClock, CalendarDays, Check, ChevronRight, CircleHelp, Copy, CreditCard, Flag, Folder, Inbox as InboxIcon, LogOut,
  Download, Hash, ListChecks, MessageCircle, MoreHorizontal, Paperclip, Phone, Pin, Search, Send, Shield, ShieldCheck, Smile, UserPlus, UserRound, Users, Video, X,
} from 'lucide-react'
import { db, formatError, formatTime, liveChannel, onReconnect, peerId, type Call, type Chat, type Message, type Profile } from '../lib/data'
import { useCalling } from '../lib/calling'
import { MessageSafetyWarning } from './message-safety-warning'
import { CallPanel } from './call-panel'
import { Brand } from './entry'
import { ReportDialog, Safety } from './safety'
import { Workspaces } from './workspaces'
import { Billing } from './billing'
import { Meetings } from './meetings'
import { FilesLibrary } from './files-library'
import { GlobalSearch, Notifications } from './discover'
import { InProductHelp } from './in-product-help'
import { ForwardMessageDialog, type ForwardDestination } from './forward-message'
import { useLocale } from './locale-provider'
import { meetingFromQuery } from '../lib/meeting-calendar'
import { useWorkspaceContext } from './workspace-context'
import { ScopedTasks } from './scoped-tasks'
import { SectionTabs } from './section-tabs'
import { NetworkDiagnostics } from './network-diagnostics'
import { GroupCalls } from './group-calls'
import { ContactKeyVerification } from './contact-key-verification'
import { VoiceNotePlayer, VoiceNoteRecorder } from './voice-note'
import { CommandPalette, type Command } from './command-palette'
import { ScheduledMessages } from './scheduled-messages'
import { useOfflineMessages } from '../lib/use-offline-messages'
import { downloadChatFile, extensions, formatChatFileBytes, getChatFileCapacity, sendChatFile, supportedFile,
  type ChatFile, type ChatFileCapacity } from '../lib/chat-files'
import { EmojiText } from './emoji-text'
import { SavedMessages, setSavedMessage } from './saved-messages'
import { ProfileActivity, ProfileAppearance, useProfileExtras } from './profile-settings'
import { AccountMfa } from './account-mfa'
import { DeviceSessions } from './device-sessions'
import { DeviceRegistry } from './device-registry'
import { DraftStatus, notifyDraftChange, useSyncedDraft } from './synced-draft'
import { pendingWorkspaceInvite } from '../lib/workspace-invite'
import { QuietHoursSettings, useEffectiveAvailability, useQuietIncoming } from './quiet-hours'

const ChatEmoji=dynamic(()=>import('./chat-emoji'))
const Friends=dynamic(()=>import('./friends').then(module=>module.Friends))
const DiscoverySettings=dynamic(()=>import('./friends').then(module=>module.DiscoverySettings))

export function Avatar({ name, tint = 'green', photo }: { name:string; tint?:string; photo?:string }) {
  const initials = name.trim().split(/\s+/).slice(0, 2).map(word => [...word][0]).join('').toUpperCase()
  return <span className={'avatar ' + tint} aria-hidden="true">{photo?<img src={photo} alt="" width={42} height={42}/>:initials||'?'}</span>
}

type InboxStatus = { chat_id: string; muted: boolean; unread: boolean; latest_id: string | null; latest_at: string | null }
type Presence = { user_id:string; state:'online'|'away'|'busy'|'offline'|'invisible'; expires_at:string }
type PresenceSettings = { required: boolean; sharing: boolean }

export function Inbox({ user }: { user: string }) {
  const { t } = useLocale()
  const {reload:reloadWorkspaces,select:selectWorkspace}=useWorkspaceContext()
  const [profile, setProfile] = useState<Profile | null | undefined>()
  const [profiles, setProfiles] = useState<Record<string, Profile>>({})
  const [chats, setChats] = useState<Chat[]>([])
  const [blocks, setBlocks] = useState<string[]>([])
  const [staff, setStaff] = useState('none')
  const [selected, setSelected] = useState<string | null>(null)
  const [requestedMeeting,setRequestedMeeting] = useState<string|null>(()=>typeof window==='undefined'?null:meetingFromQuery(window.location.search))
  const [requestedRoom,setRequestedRoom] = useState<{workspace:string;id:string}|null>(null)
  const [tab, setTab] = useState<'inbox' | 'calls' | 'safety' | 'profile' | 'workspaces' | 'billing' | 'meetings' | 'vault' | 'search' | 'notifications' | 'rooms' | 'tasks' | 'calendar' | 'friends' | 'saved'>(() =>
    requestedMeeting?'meetings':pendingWorkspaceInvite()?'workspaces':
      typeof window !== 'undefined' && new URLSearchParams(window.location.search).has('billing') ? 'billing' : 'inbox')
  const [mode, setMode] = useState<'chats' | 'requests' | 'sent'>('chats')
  const [taskSection,setTaskSection]=useState<'scoped'|'workspace'>('scoped')
  const [paletteOpen,setPaletteOpen]=useState(false)
  const [paletteSearch,setPaletteSearch]=useState({query:'',sequence:0})
  const [chatTasks,setChatTasks]=useState(false)
  const [sourceTask,setSourceTask]=useState<string|null>(null)
  const [profileTab, setProfileTab] = useState<'account' | 'security' | 'sessions' | 'availability' | 'discovery' | 'activity' | 'blocked' | 'help'>('account')
  const [managedBlock,setManagedBlock]=useState<Chat|null>(null)
  const [search, setSearch] = useState('')
  const [notice, setNotice] = useState('')
  const [priorityNotice, setPriorityNotice] = useState<{message: string; priority: 'high' | 'critical'} | null>(null)
  const [onboarding,setOnboarding]=useState(false)
  const [report, setReport] = useState<{ chat: string; message: Message | null; file?:ChatFile } | null>(null)
  const [lastSeen,setLastSeen]=useState<{chat:string;at:string}|null>(null)
  const [blockCheck, setBlockCheck] = useState(false)
  const [online, setOnline] = useState(false)
  const [broadcastOnline, setBroadcastOnline] = useState(false)
  const [working, setWorking] = useState(false)
  const [presence,setPresence] = useState<Record<string,Presence>>({})
  const [presenceSettings,setPresenceSettings] = useState<PresenceSettings | null>(null)
  const [inboxStatus, setInboxStatus] = useState<Record<string, InboxStatus>>({})
  const activeChat = useRef<string | null>(null)
  const announced = useRef(new Map<string, string>())
  const readVersion = useRef(0)
  const [hints] = useState(() => new EventTarget())
  const announceAlert = useCallback((message: string, priority: unknown) => {
    if (priority === 'high' || priority === 'critical') {
      setPriorityNotice(current => current?.priority === 'critical' && priority === 'high' ? current : {message, priority})
    } else setNotice(message)
  }, [])
  const acknowledgeAdminAlert = useCallback(async (receipt: unknown) => {
    if (typeof receipt === 'string') await db!.rpc('st_v6_ack_admin_notification', {p_receipt: receipt})
  }, [])
  const offlineMessages=useOfflineMessages(user,hints)
  const call = useCalling(user, setNotice, hints)
  useEffect(() => { activeChat.current = tab === 'inbox' ? selected : null }, [tab, selected])
  const refreshInboxStatus = useCallback(async (changedChat?: string) => {
    const [{ data, error }, quiet] = await Promise.all([
      db!.rpc('st_v2_inbox_status'),
      changedChat ? db!.rpc('st_v6_direct_alert_quiet', { p_chat: changedChat, p_category: 'dm' }) : null,
    ])
    if (error) return
    setInboxStatus(Object.fromEntries((data as InboxStatus[]).map(row => [row.chat_id,row])))
    if (changedChat) {
      const row = (data as InboxStatus[]).find(item => item.chat_id === changedChat)
      if (quiet?.data === false && row?.unread && !row.muted && row.latest_id && row.latest_at && activeChat.current !== changedChat
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
    const [people,state,settings] = await Promise.all([
      ids.length ? db!.from('st_profiles').select('*').in('id', ids) : Promise.resolve({data:[]}),
      db!.from('st_v3_presence').select('user_id,state,expires_at').in('user_id',[user,...ids]),
      db!.rpc('st_v6_presence_settings'),
    ])
    if (version !== readVersion.current) return
    if (people.data) setProfiles(Object.fromEntries(people.data.map(person => [person.id, person])))
    setPresence(Object.fromEntries(((state.data??[]) as Presence[]).map(row=>[row.user_id,row])))
    setPresenceSettings(settings.data as PresenceSettings | null)
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
      .on('broadcast', { event: 'presence' }, () => { hints.dispatchEvent(new Event('presence')); void refresh() })
      .on('broadcast', { event: 'availability' }, () => hints.dispatchEvent(new Event('availability')))
      .on('broadcast', { event: 'draft_change' }, ({payload}) => notifyDraftChange(payload||{}))
      .on('broadcast', { event: 'room_activity' }, ({ payload }) => {
        if (typeof payload?.room_id === 'string') {
          announceAlert(payload.mention_kind==='mention.user'?'You were mentioned directly in a room.':
            typeof payload.mention_kind==='string'?'You received a room mention.':'New activity in one of your rooms.',
            payload.priority)
          void acknowledgeAdminAlert(payload.receipt_id)
        }
      })
      .on('broadcast', { event: 'channel_activity' }, ({ payload }) => {
        if (typeof payload?.channel_id === 'string') setNotice('New activity in one of your workspace channels.')
      })
      .on('broadcast', { event: 'category_alert' }, ({ payload }) => {
        void acknowledgeAdminAlert(payload?.receipt_id)
        switch (payload?.kind) {
          case 'thread.reply': announceAlert('New reply in a thread you follow.',payload.priority); break
          case 'task.completed': announceAlert('A task you follow was completed.',payload.priority); break
          case 'task.due': announceAlert('A task is due soon.',payload.priority); break
          case 'security.report': announceAlert('One of your Safety reports has an update.',payload.priority); break
          case 'security.account': announceAlert('There is a new account notice in your Safety center.',payload.priority); break
          case 'billing.subscription': announceAlert('Your subscription has an update.',payload.priority); break
          case 'admin.room': announceAlert('New activity in a workspace admin room.',payload.priority); break
        }
      })
      .on('broadcast', { event: 'case_collaboration' }, () => {
        void db!.rpc('st_v6_case_collaboration_alerts', { p_unread_only: true }).then(({ data, error }) => {
          if (!error && Array.isArray(data) && data.length) setNotice('You have a new staff case mention.')
        })
      })
      .on('broadcast', { event: 'case_escalation' }, () => {
        void db!.rpc('st_v6_case_escalation_assignments').then(({ data, error }) => {
          if (!error && Array.isArray(data) && data.length) setNotice('You have a new on-call case assignment.')
        })
      })
      .on('broadcast', { event: 'workspace_room_report' }, () => {
        void db!.rpc('st_v6_room_report_queue', { p_scope: 'workspace' }).then(({ data, error }) => {
          if (!error && Array.isArray(data) && data.length) setNotice('You have a new workspace room report to review.')
        })
      })
      .on('broadcast', { event: 'room_report_routed' }, () => {
        void db!.rpc('st_v6_room_report_queue', { p_scope: 'platform' }).then(({ data, error }) => {
          if (!error && Array.isArray(data) && data.some(row => row.assigned_to_you)) {
            setNotice('You have a new on-call room report assignment.')
          }
        })
      })
      .on('broadcast', { event: 'account_security_lifecycle' }, () => {
        hints.dispatchEvent(new Event('account_security_lifecycle'))
        announceAlert('There is new activity in your account security settings.', 'critical')
      })
      .on('broadcast', { event: 'emergency_customer_notice' }, () => {
        hints.dispatchEvent(new Event('emergency_customer_notice'))
        announceAlert('Review the new workspace emergency access notice in Safety.', 'critical')
      })
      .on('broadcast', { event: 'contact_key_changed' }, () => hints.dispatchEvent(new Event('contact_key_changed')))
      .on('broadcast', { event: 'session_lifecycle' }, () => {
        hints.dispatchEvent(new Event('session_lifecycle'))
        window.dispatchEvent(new Event('sectalk-device-command'))
        void db!.rpc('st_v7_current_session_valid').then(({data,error}) => {
          if (!error && data === false) void db!.auth.signOut({scope:'local'})
        })
      })
      .on('broadcast', { event: 'login_anomaly' }, () => {
        hints.dispatchEvent(new Event('login_anomaly'))
        void db!.rpc('st_v7_list_login_anomalies').then(({data,error})=>{
          if (!error&&Array.isArray(data)&&data.some(row=>row.state==='pending'))
            announceAlert('Review an unusual sign-in in your account security settings.', 'critical')
        })
      })
      .on('broadcast', { event: 'device_registry' }, () => hints.dispatchEvent(new Event('device_registry')))
      .on('broadcast', { event: 'workspace_memberships' }, () => { void reloadWorkspaces(); void refresh() })
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
  }, [user, refresh, hints, refreshInboxStatus, reloadWorkspaces, announceAlert, acknowledgeAdminAlert])

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
    const ping=async()=>{if(document.visibilityState==='visible') await db!.rpc('st_v3_ping')}
    ping()
    const timer=window.setInterval(ping,45000)
    const disconnect=onReconnect(ping)
    return ()=>{disconnect();window.clearInterval(timer)}
  },[profile?.id])

  const chat = chats.find(item => item.id === selected)
  const peer = chat ? profiles[peerId(chat, user)] : undefined
  const peerPresence = peer ? presence[peer.id] : undefined
  const rawPeerState = peerPresence && Date.parse(peerPresence.expires_at)>Date.now()
    && peerPresence.state!=='offline' && peerPresence.state!=='invisible' ? peerPresence.state : null
  const ownPresence = presence[user]?.state ?? 'offline'
  const mustResumeSharing = presenceSettings?.required && (!presenceSettings.sharing || ownPresence==='invisible')
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
  const peerExtras=useProfileExtras(acceptedChat?peer?.id:undefined,true)
  const effectiveAvailability=useEffectiveAvailability(acceptedChat && tab==='inbox' ? peer?.id : undefined,hints)
  const peerState=rawPeerState && effectiveAvailability?.busy ? 'busy' : rawPeerState
  const statusMessage=effectiveAvailability?.status
  const incoming=call.call?.status==='ringing' && call.call.callee===user ? call.call : null
  const quietIncoming=useQuietIncoming(incoming,hints)
  useEffect(()=>{
    if(!acceptedChat) return
    let active=true
    let sequence=0
    const check=async()=>{
      const request=++sequence
      const {data,error}=await db!.rpc('st_v5_last_seen',{p_chat:acceptedChat})
      if(active&&request===sequence) setLastSeen(!error&&typeof data==='string'?{chat:acceptedChat,at:data}:null)
    }
    void check()
    hints.addEventListener('presence',check)
    const timer=window.setInterval(check,12000)
    return ()=>{active=false;hints.removeEventListener('presence',check);window.clearInterval(timer)}
  },[acceptedChat,hints])
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
  function openRoom(workspace:string,id:string) {
    selectWorkspace(workspace)
    setRequestedRoom({workspace,id})
    setTab('rooms')
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
    <nav className="rail" aria-label={t('features')}>
      <Brand compact />
      <button className={tab === 'inbox' || tab === 'saved' ? 'active' : ''} aria-current={tab === 'inbox' || tab === 'saved' ? 'page' : undefined} onClick={() => setTab('inbox')}><MessageCircle size={20} /><span>{t('inbox')}</span></button>
      <button className={tab==='friends'?'active':''} aria-current={tab==='friends'?'page':undefined} onClick={()=>setTab('friends')}><UserPlus size={19}/><span>{t('friends')}</span></button>
      <button className={tab === 'calls' ? 'active' : ''} aria-current={tab === 'calls' ? 'page' : undefined} onClick={() => setTab('calls')}><Phone size={19} /><span>{t('calls')}</span></button>
      <button className={tab === 'workspaces' ? 'active' : ''} aria-current={tab === 'workspaces' ? 'page' : undefined} onClick={() => setTab('workspaces')}><Users size={19} /><span>{t('workspaces')}</span></button>
      <button className={tab==='rooms'?'active':''} aria-current={tab==='rooms'?'page':undefined} onClick={()=>{setRequestedRoom(null);setTab('rooms')}}><Hash size={19}/><span>{t('rooms')}</span></button>
      <button className={tab==='tasks'?'active':''} aria-current={tab==='tasks'?'page':undefined} onClick={()=>setTab('tasks')}><ListChecks size={19}/><span>{t('tasks')}</span></button>
      <button className={tab==='calendar'?'active':''} aria-current={tab==='calendar'?'page':undefined} onClick={()=>setTab('calendar')}><CalendarDays size={19}/><span>{t('calendar')}</span></button>
      <button className={tab==='meetings'?'active':''} aria-current={tab==='meetings'?'page':undefined} onClick={()=>{setRequestedMeeting(null);setTab('meetings')}}><CalendarDays size={19}/><span>{t('meetings')}</span></button>
      <button className={tab==='vault'?'active':''} aria-current={tab==='vault'?'page':undefined} onClick={()=>setTab('vault')}><Folder size={19}/><span>{t('files')}</span></button>
      <button className={tab==='search'?'active':''} aria-current={tab==='search'?'page':undefined} onClick={()=>showSearch()}><Search size={19}/><span>{t('search')}</span></button>
      <button className={tab==='notifications'?'active':''} aria-current={tab==='notifications'?'page':undefined} onClick={()=>setTab('notifications')}><Bell size={19}/><span>{t('notifications')}</span></button>
      <button className={tab === 'safety' ? 'active' : ''} aria-current={tab === 'safety' ? 'page' : undefined} onClick={() => setTab('safety')}><Shield size={20} /><span>{t('safety')}</span></button>
      <div className="rail-end"><button className={tab === 'billing' ? 'active' : ''} aria-current={tab === 'billing' ? 'page' : undefined} onClick={() => setTab('billing')}><CreditCard size={19} /><span>{t('billing')}</span></button><button className={tab === 'profile' ? 'active' : ''} aria-current={tab === 'profile' ? 'page' : undefined} onClick={() => setTab('profile')}><UserRound size={20} /><span>{t('profile')}</span></button>
        <button onClick={async () => { await call.end(); void db!.auth.signOut({ scope: 'local' }) }}><LogOut size={19} /><span>{t('signOut')}</span></button></div>
    </nav>
    <aside className="inbox-list">
      <header><Brand /><div className="inbox-heading"><h1>{t('inbox')}</h1><button className="primary" onClick={()=>setTab('friends')}><UserPlus size={17}/> {t('findFriends')}</button></div>
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
    {tab === 'profile' ? <section className="content-page"><h1>{t('profile')}</h1>
      <SectionTabs label={t('profileSections')} value={profileTab} onChange={setProfileTab} options={ [['account',t('account')],['security',t('accountSecurity')],['sessions','Devices and sessions'],['availability',t('availability')],['discovery',t('discovery')],['activity',t('activityReports')],['blocked',t('blockedContacts')],['help',t('help')]] }/>
      {profileTab === 'account' ? <><div className="profile-handle"><code>@{profile.handle}</code><button className="secondary" onClick={async () => {
        try { await navigator.clipboard.writeText(profile.handle); setNotice('Handle copied.') }
        catch { setNotice('Could not copy your handle. Select and copy it from your profile.') }
      }}><Copy size={15} /> Copy handle</button></div>
      <ProfileForm profile={profile} onSave={refresh} /><ProfileAppearance user={user} profile={myExtras}/></> :
      profileTab==='security'?<AccountMfa hints={hints}/>:
      profileTab==='sessions'?<><DeviceSessions hints={hints}/><DeviceRegistry hints={hints}/></>:
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
        <select value={mustResumeSharing?'':ownPresence} disabled={working||!presenceSettings} onChange={event=>void run('st_v3_set_presence',{p_state:event.target.value})}>
          {mustResumeSharing&&<option value="" disabled>Choose an availability state</option>}
          <option value="offline">Offline (hidden)</option><option value="online">Online</option><option value="away">Away</option><option value="busy">Busy</option>
          {presenceSettings&&!presenceSettings.required&&<option value="invisible">Invisible</option>}
        </select></label>
        {presenceSettings?.required
          ? <p className="muted">{mustResumeSharing
            ? 'A workspace requires availability sharing. Your availability stays private until you choose a state.'
            : 'A workspace requires availability sharing.'}</p>
          : <label className="task-check"><input type="checkbox" checked={presenceSettings?.sharing??false} disabled={working||!presenceSettings}
            onChange={event=>void run('st_v6_set_presence_privacy',{p_share:event.target.checked})}/> Share availability and status with approved contacts</label>}
        <label className="task-check"><input type="checkbox" checked={myExtras.details?.share_last_seen||false} disabled={working||!presenceSettings?.sharing||ownPresence==='invisible'}
          onChange={event=>void run('st_v5_set_last_seen',{p_enabled:event.target.checked},()=>void myExtras.refresh())}/> Share last seen</label>
        <p>Accepted contacts can see your last activity for up to seven days when both availability and last seen are shared.</p>
        <QuietHoursSettings chat={null} hints={hints}/></div>}
      </section> :
      tab==='friends'?<Friends user={user} pending={requests.length} working={working} send={sendRequest} openRequests={openRequests}/>:
      tab==='saved'?<SavedMessages openChat={select}/>:
      tab === 'safety' ? <Safety staff={staff} refresh={refresh} hints={hints} /> :
      tab==='workspaces'||tab==='rooms'||tab==='calendar' ? <Workspaces key={tab} user={user} view={tab} requestedRoom={tab==='rooms'?requestedRoom:null} /> :
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
      tab === 'search' ? <GlobalSearch key={paletteSearch.sequence} initialQuery={paletteSearch.query} openChat={select} openMeeting={openMeeting}
        openRoom={openRoom} openPalette={()=>setPaletteOpen(true)}/> :
      tab === 'notifications' ? <Notifications user={user} hints={hints} openMeeting={openMeeting} openRoom={openRoom} openChat={select}/> :
      tab === 'calls' ? <Calls user={user} chats={chats} profiles={profiles} blocks={blocks} state={call} openChat={select} openInbox={() => setTab('inbox')} /> :
      chat ? <section className="thread">
        <header className="thread-header"><button className="icon mobile-back" aria-label="Back to inbox" onClick={() => select(null)}><ArrowLeft size={20} /></button><Avatar name={peer?.name || 'Contact'} photo={peerExtras.photo}/>
          <div><h2>{peer?.name || 'Contact'}</h2><p aria-label="Contact availability">{blocked ? 'Blocked' : peerState ? peerState[0].toUpperCase()+peerState.slice(1) : chat.status==='accepted' ? ['Offline',lastSeenLabel].filter(Boolean).join(' · ') : 'Contact request'}</p>
            {statusMessage&&<p className="thread-profile-status" title={statusMessage}>{statusMessage}</p>}</div>
          <div className="thread-actions">
            {chat.status === 'accepted' && !blocked && <>
              <button className="icon" aria-pressed={chatTasks} aria-label="Chat tasks" title="Chat tasks" onClick={()=>{
                setChatTasks(!chatTasks);setSourceTask(null)
              }}><ListChecks size={18}/></button>
              <button className="icon" disabled={call.busy || !!call.call} aria-label="Start audio call" title="Start audio call" onClick={() => void call.start(chat.id, false)}><Phone size={18} /></button>
              <button className="icon" disabled={call.busy || !!call.call} aria-label="Start video call" title="Start video call" onClick={() => void call.start(chat.id, true)}><Video size={20} /></button>
              <ContactKeyVerification key={peerId(chat,user)} owner={user} peer={peerId(chat,user)} name={peer?.name || 'your contact'} hints={hints}/>
              <details className="call-menu">
                <summary className="icon" aria-label="Protected call options" title="Protected calls"><ShieldCheck size={18}/></summary>
                <div className="message-menu-panel" style={{top:'100%',right:0,bottom:'auto'}}>
                  <button type="button" className="text-button" disabled={call.busy || !!call.call}
                    onClick={()=>void call.start(chat.id,false,true)}>Start protected audio call</button>
                  <button type="button" className="text-button" disabled={call.busy || !!call.call}
                    onClick={()=>void call.start(chat.id,true,true)}>Start protected video call</button>
                </div>
              </details>
            </>}
            <button className="icon" title="Report contact" aria-label="Report contact" onClick={() => setReport({ chat: chat.id, message: null })}><Flag size={18} /></button>
            <button className="icon" title={blocked ? 'Unblock contact' : 'Block contact'} aria-label={blocked ? 'Unblock contact' : 'Block contact'} onClick={() => setBlockCheck(true)}><Ban size={18} /></button>
          </div>
        </header>
        {blockCheck && <div className="inline-warning"><span>{blocked ? 'Allow this contact to reach you again?' : 'Block new messages and calls from this contact?'}</span><button className="danger" disabled={working} onClick={() => void run('st_set_block', { p_chat: chat.id, p_block: !blocked }, () => { setBlockCheck(false); setNotice(blocked ? 'Contact unblocked.' : 'Contact blocked.') })}>{blocked ? 'Unblock' : 'Block'}</button><button className="secondary" onClick={() => setBlockCheck(false)}>Cancel</button></div>}
        {chat.status === 'accepted' ? <Thread key={chat.id} chat={chat} self={user} selfName={profile.name} peerName={peer?.name||'Contact'} hints={hints} offlineMessages={offlineMessages}
          forwardDestinations={chats.flatMap(conversation => {
            const contact = profiles[peerId(conversation, user)]
            if (conversation.id === chat.id || conversation.status !== 'accepted' || !contact || blocks.includes(contact.id)) return []
            return [{ id: conversation.id, name: contact.name + ' (@' + contact.handle + ')' }]
          })}
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
        <div className="empty-thread welcome-thread"><div className="card-icon"><MessageCircle size={27}/></div><h2>{t('yourConversations')}</h2><p>{t('conversationWelcome')}</p><button className="primary" onClick={()=>setTab('friends')}><UserPlus size={17}/> {t('findFriends')}</button><button className="secondary" onClick={showHelp}>{t('gettingStarted')}</button></div>
      </section>}
    {(priorityNotice || notice) && <div className="toast" role={priorityNotice?.priority === 'critical' ? 'alert' : 'status'}>
      <CircleHelp size={18} aria-hidden="true" />
      <div>{priorityNotice && <><strong>{priorityNotice.priority === 'critical' ? 'Critical security notice' : 'High-priority alert'}</strong><br/></>}
        <span>{priorityNotice?.message ?? notice}</span></div>
      <button className="icon" aria-label="Dismiss notice" onClick={() => priorityNotice ? setPriorityNotice(null) : setNotice('')}><X size={17}/></button>
    </div>}
    {managedBlock&&<Dialog title={blocks.includes(peerId(managedBlock,user))?'Unblock contact?':'Block contact?'} close={()=>setManagedBlock(null)}>
      <p>{blocks.includes(peerId(managedBlock,user))?'Allow new messages and calls from this contact.':'Stop new messages and calls from this contact.'}</p>
      <button className="danger" type="button" disabled={working} onClick={()=>{
        const block=!blocks.includes(peerId(managedBlock,user))
        void run('st_set_block',{p_chat:managedBlock.id,p_block:block},()=>{setManagedBlock(null);setNotice(block?'Contact blocked.':'Contact unblocked.')})
      }}>{blocks.includes(peerId(managedBlock,user))?'Unblock':'Block'}</button>
    </Dialog>}
    {paletteOpen&&<CommandPalette commands={commands} onClose={()=>setPaletteOpen(false)} onSearch={showSearch}/>}
    {report && <ReportDialog chat={report.chat} message={report.message} file={report.file} close={() => setReport(null)} inform={setNotice} />}
    {call.call && !quietIncoming && <CallPanel key={call.call.id} state={call} self={user} name={profiles[callerId]?.name || 'Contact'}
      openChat={select} reportContact={chatId => setReport({chat:chatId,message:null})} />}
  </main>
}

function Calls({ user, chats, profiles, blocks, state, openChat, openInbox }: {
  user: string; chats: Chat[]; profiles: Record<string, Profile>; blocks: string[];
  state: ReturnType<typeof useCalling>; openChat: (id: string) => void; openInbox: () => void
}) {
  const [rows, setRows] = useState<Call[] | null>(null)
  const [filter, setFilter] = useState<'all' | 'missed' | 'audio' | 'video' | 'diagnostics' | 'groups'>('all')
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
    <SectionTabs label="Call history" value={filter} onChange={setFilter} options={ [['all', 'All calls'], ['missed','Missed'], ['audio', 'Audio'], ['video', 'Video'], ['groups','Groups'], ['diagnostics', 'Network diagnostics']] }/>
    {filter==='diagnostics' ? <NetworkDiagnostics inCall={Boolean(state.call)}/> : filter==='groups' ?
      <GroupCalls user={user} inDirectCall={Boolean(state.call)} contacts={chats.filter(chat=>chat.status==='accepted'&&!blocks.includes(peerId(chat,user)))
        .map(chat=>({id:peerId(chat,user),name:profiles[peerId(chat,user)]?.name || 'Contact'}))}/> : <div className="panel">
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
          row.end_reason==='declined'?'Declined':row.end_reason==='cancelled'?'Cancelled':row.end_reason==='busy'?'Busy':
          row.status==='active'&&Date.parse(row.expires_at)>now?'In progress':row.status==='ringing'?'Ringing':'Ended'
        return <div className="report-row" key={row.id}>
          <Avatar name={name} />
          <div><strong>{name}</strong><small>{incoming ? 'Incoming' : 'Outgoing'} {row.media_protection===1?'protected ':''}{row.video ? 'video' : 'audio'} · {new Date(row.created_at).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}</small><span className="call-state">{status}</span></div>
          {reachable && <span className="call-history-controls">
            {incoming&&missed(row)&&<button className="secondary" aria-label={'Call back '+name}
              disabled={state.busy||!!state.call} onClick={()=>void state.start(row.chat_id,row.video,row.media_protection===1)}>Call back</button>}
            <button className="icon" aria-label={'Open conversation with ' + name} title="Open conversation" onClick={() => openChat(row.chat_id)}><MessageCircle size={17} /></button>
            <button className="icon" aria-label={'Start '+(row.media_protection===1?'protected ':'')+'audio call with '+name} title={row.media_protection===1?'Protected audio call':'Audio call'} disabled={state.busy || !!state.call} onClick={() => void state.start(row.chat_id,false,row.media_protection===1)}><Phone size={17} /></button>
            <button className="icon" aria-label={'Start '+(row.media_protection===1?'protected ':'')+'video call with '+name} title={row.media_protection===1?'Protected video call':'Video call'} disabled={state.busy || !!state.call} onClick={() => void state.start(row.chat_id,true,row.media_protection===1)}><Video size={17} /></button>
          </span>}
        </div>
      })}
    </div>}
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
type ChatActivity = {
  muted:boolean;read_sequence:number|null;read_since_sequence:number|null;typing_until:string|null
  share_own_typing:boolean
  share_own_read_receipts:boolean
  share_own_edit_history:boolean;share_peer_edit_history:boolean
}
type EditHistory={message:string;own:boolean;revisions:{id:number;body:string;created_at:string}[]}
type DirectMessage = Message & { sequence:number; delivered_at?:string|null }
type OutboxMessage = {
  id:string; body:string; reply:string|null; file:File|null; at:string; state:'queued'|'sent'|'failed'|'damaged'
}
function mergeDelivery(before:DirectMessage|undefined,row:DirectMessage){
  if(!before)return row
  const body=row.revoked_at?row:before.revoked_at||before.edited_at&&before.edited_at>(row.edited_at||'')?before:row
  return {...body,delivered_at:row.delivered_at||before.delivered_at}
}
const reactionOptions = [
  { emoji: '👍', label: 'Thumbs up' }, { emoji: '❤️', label: 'Heart' },
  { emoji: '✅', label: 'Check mark' }, { emoji: '👀', label: 'Eyes' },
]

function Thread({ chat, self, selfName, peerName, hints, blocked, onReport, inform, onTask, taskPanel, offlineMessages, forwardDestinations }: {
  chat: Chat; self: string; selfName:string; peerName:string; hints: EventTarget; blocked: boolean
  onReport: (message: Message,file?:ChatFile) => void; inform: (notice: string) => void
  onTask:(id:string)=>void;taskPanel:React.ReactNode
  offlineMessages:ReturnType<typeof useOfflineMessages>
  forwardDestinations:ForwardDestination[]
}) {
  const [messages, setMessages] = useState<DirectMessage[]>([])
  const syncedDraft=useSyncedDraft(self,'chat',chat.id,null,!blocked)
  const draft=syncedDraft.body
  const [loaded, setLoaded] = useState(false)
  const [activity, setActivity] = useState<ChatActivity | null>(null)
  const [reactions, setReactions] = useState<Reaction[]>([])
  const [pin, setPin] = useState<Message | null>(null)
  const [showSearch, setShowSearch] = useState(false)
  const [quietSettings, setQuietSettings] = useState(false)
  const [results, setResults] = useState<DirectMessage[] | null>(null)
  const [editing, setEditing] = useState<Message | null>(null)
  const [forwarding, setForwarding] = useState<string | null>(null)
  const [removing,setRemoving]=useState<{message:Message;action:'hide'|'revoke'}|null>(null)
  const [hidden,setHidden]=useState<string[]>([])
  const [files,setFiles]=useState<Record<string,ChatFile>>({})
  const [attachment,setAttachment]=useState<{file:File;id:string}|null>(null)
  const [fileCapacity, setFileCapacity] = useState<ChatFileCapacity | null>(null)
  const refreshFileCapacity = useCallback(async () => {
    const capacity = await getChatFileCapacity()
    if (capacity) setFileCapacity(capacity)
  }, [])
  useEffect(() => { if (!blocked) void refreshFileCapacity() }, [blocked, refreshFileCapacity])
  const [emoji,setEmoji]=useState(false)
  const [reacting,setReacting]=useState<string|null>(null)
  const filePicker=useRef<HTMLInputElement>(null)
  const composerInput=useRef<HTMLTextAreaElement>(null)
  const cursor=useRef<{start:number;end:number}|null>(null)
  const [replying, setReplying] = useState<Message | null>(null)
  const [quotes,setQuotes]=useState<Record<string,Pick<Message,'id'|'sender'|'body'|'expires_at'>>>({})
  const [expireAfter, setExpireAfter] = useState(0)
  const pendingExpiry = useRef<{id:string;body:string;seconds:number;reply:string|null}|null>(null)
  const [expiryClock, setExpiryClock] = useState(Date.now)
  const [history,setHistory]=useState<EditHistory|null>(null)
  const [historySettings,setHistorySettings]=useState(false)
  const [clock, setClock] = useState(0)
  const typingPulse = useRef({ sentAt: 0, stopped: true })
  const [typingPolicyBusy, setTypingPolicyBusy] = useState(false)
  const [receiptPolicyBusy, setReceiptPolicyBusy] = useState(false)
  const readLast = useRef('')
  const [older, setOlder] = useState(false)
  const [busy, setBusy] = useState(false)
  const feed = useRef<HTMLDivElement>(null)
  const nearBottom = useRef(true)
  const [outbox,setOutbox]=useState<OutboxMessage[]>([])
  const pendingText:OutboxMessage[]=offlineMessages.entries.filter(item=>item.chat===chat.id&&!messages.some(row=>row.id===item.id))
    .map(item=>({...item,file:null,state:item.state==='retry'?'failed':item.state}))
  const sending=useRef(false)
  const acknowledged=useRef(new Set<string>())
  const pendingSchedule=useRef<{id:string;body:string;at:string}|null>(null)
  const [scheduleOpen,setScheduleOpen]=useState(false)
  const revoked=useRef(new Map<string,DirectMessage>())
  const [loadingOlder, setLoadingOlder] = useState(false)
  const lifecycle=useRef<AbortController|null>(null)
  const frontier=useRef<number|null>(null)
  const inFlight=useRef<Promise<void>|null>(null)
  const runAgain=useRef(false)
  const refreshWindow=useRef(false)
  const activityVersion=useRef(0)
  useEffect(() => {
    const expiring=[...messages,...Object.values(quotes),replying,removing?.message]
      .flatMap(message=>message?.expires_at?[Date.parse(message.expires_at)]:[])
    const alive = (message: Pick<Message, 'expires_at'>, now: number) =>
      !message.expires_at || Date.parse(message.expires_at)>now
    let timer: number | undefined
    function advance() {
      window.clearTimeout(timer)
      const now = Date.now()
      setExpiryClock(now)
      if (expiring.some(time=>time<=now)) {
        setMessages(rows=>rows.some(row=>!alive(row,now))?rows.filter(row=>alive(row,now)):rows)
        setQuotes(rows=>Object.values(rows).some(row=>!alive(row,now))?
          Object.fromEntries(Object.entries(rows).filter(([,row])=>alive(row,now))):rows)
        setReplying(row=>row&&!alive(row,now)?null:row)
        setRemoving(row=>row&&!alive(row.message,now)?null:row)
      }
      const next = Math.min(...expiring.filter(time=>time>now))
      if (Number.isFinite(next)) timer=window.setTimeout(advance,next-now)
    }
    advance()
    document.addEventListener('visibilitychange',advance)
    return () => {
      window.clearTimeout(timer)
      document.removeEventListener('visibilitychange',advance)
    }
  }, [messages,quotes,replying,removing])
  const merge = useCallback((rows: DirectMessage[], existingOnly=false) => {
    for(const row of rows)if(row.revoked_at)revoked.current.set(row.id,row)
    const current=rows.map(row=>revoked.current.get(row.id)||row)
    setMessages(previous => {
      const byId=new Map(previous.map(row=>[row.id,row]))
      for(const row of current){
        if(!existingOnly||byId.has(row.id))byId.set(row.id,mergeDelivery(byId.get(row.id),row))
      }
      return [...byId.values()].sort((a,b)=>a.sequence-b.sequence)
    })
    const updates=new Map(current.map(row=>[row.id,row]))
    setResults(previous=>previous?.map(row=>{
      const update=updates.get(row.id)
      return update?mergeDelivery(row,update):row
    })??null)
    setOutbox(previous=>previous.some(item=>updates.has(item.id))?previous.filter(item=>!updates.has(item.id)):previous)
    setReplying(previous=>previous&&(updates.get(previous.id)?.revoked_at?null:previous))
    setEditing(previous=>previous&&(updates.get(previous.id)?.revoked_at?null:previous))
    setHistory(previous=>previous&&(updates.get(previous.message)?.revoked_at?null:previous))
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

  const hydrate=useCallback(async(page:DirectMessage[],signal:AbortSignal)=>{
    const ids=page.map(row=>row.id)
    if(ids.length){
      const [removed,attachments]=await Promise.all([
        db!.from('st_v5_hidden_messages').select('message_id').in('message_id',ids).abortSignal(signal),
        db!.from('st_v5_files').select('id,message_id,filename,size_bytes').in('message_id',ids).abortSignal(signal),
        loadQuotes(page),
      ])
      if(signal.aborted)return
      if(removed.error||attachments.error)throw new Error('Message metadata unavailable')
      if(removed.data.length)setHidden(previous=>[...new Set([...previous,...removed.data.map(row=>row.message_id)])])
      setFiles(previous=>{
        const next={...previous}
        for(const id of ids)delete next[id]
        for(const file of attachments.data)next[file.message_id]=file
        return next
      })
    }
    if(!signal.aborted)merge(page)
  },[loadQuotes,merge])

  const load = useCallback(async(before?:DirectMessage, refreshRecent=true)=>{
    const signal=lifecycle.current?.signal
    if(!signal||signal.aborted)return
    const query=()=>db!.from('st_messages').select('*').eq('chat_id',chat.id).abortSignal(signal)
    if(before){
      try{
        const {data,error}=await query().lt('sequence',before.sequence).order('sequence',{ascending:false}).limit(51)
        if(error)throw error
        await hydrate(data.slice(0,50) as DirectMessage[],signal)
        if(!signal.aborted)setOlder(data.length>50)
      }catch{if(!signal.aborted)inform('Could not sync messages.')}
      return
    }
    refreshWindow.current ||= refreshRecent
    if(inFlight.current){
      runAgain.current=true
      return inFlight.current
    }
    const sync=(async()=>{
      let passes=0
      try{
        do{
          runAgain.current=false
          const recent=refreshWindow.current
          refreshWindow.current=false
          if(frontier.current===null){
            const {data,error}=await query().order('sequence',{ascending:false}).limit(51)
            if(error)throw error
            await hydrate(data.slice(0,50) as DirectMessage[],signal)
            if(signal.aborted)return
            frontier.current=data[0]?.sequence??0
            setOlder(data.length>50)
            setLoaded(true)
          }else{
            // Advance only from pages read in sequence order. A live event can point
            // beyond messages missed while disconnected and must not skip them.
            for(let page=0;page<6&&!signal.aborted;page++){
              const {data,error}=await query().gt('sequence',frontier.current).order('sequence').limit(50)
              if(error)throw error
              if(!data.length)break
              await hydrate(data as DirectMessage[],signal)
              if(signal.aborted)return
              frontier.current=data[data.length-1].sequence
              if(data.length<50)break
            }
            if(recent&&!signal.aborted){
              const {data,error}=await query().lte('sequence',frontier.current).order('sequence',{ascending:false}).limit(50)
              if(error)throw error
              await hydrate(data as DirectMessage[],signal)
            }
          }
        }while(runAgain.current&&!signal.aborted&&++passes<3)
      }catch{if(!signal.aborted)inform('Could not sync messages.')}
    })()
    inFlight.current=sync
    try{await sync}finally{if(inFlight.current===sync)inFlight.current=null}
  },[chat.id,hydrate,inform])

  const loadLatest = useRef(load)
  useEffect(() => { loadLatest.current = load }, [load])
  const loadActivity = useCallback(async () => {
    const version=++activityVersion.current
    const [status, reactions, pinned] = await Promise.all([
      db!.rpc('st_v2_chat_status', { p_chat: chat.id }),
      db!.from('st_v2_reactions').select('message_id,user_id,reaction').eq('chat_id', chat.id).limit(1000),
      db!.from('st_v2_pins').select('message_id').eq('chat_id', chat.id).maybeSingle(),
    ])
    if(version!==activityVersion.current)return
    if (!status.error) setActivity(status.data)
    if (!reactions.error) setReactions(reactions.data)
    if (pinned.error) return
    if (pinned.data) {
      const { data } = await db!.from('st_messages').select('*').eq('id', pinned.data.message_id).maybeSingle()
      if(version===activityVersion.current)setPin(data as Message | null)
    } else setPin(null)
  }, [chat.id])
  useEffect(() => {
    const controller=new AbortController()
    lifecycle.current=controller
    void loadLatest.current()
    const sync = () => { void loadLatest.current(); void loadActivity() }
    const onHint = (event: Event) => { if ((event as MessageEvent).data === chat.id) sync() }
    const onActivity = (event: Event) => { if ((event as MessageEvent).data === chat.id) sync() }
    const channel = liveChannel('thread:' + chat.id, sync)
      .on('postgres_changes', { event: '*', schema: 'public', table: 'st_messages', filter: 'chat_id=eq.' + chat.id }, payload => {
        if (payload.eventType !== 'DELETE'){
          const message=payload.new as DirectMessage
          const next=frontier.current
          if(next===null||message.sequence>next){
            // This also fills a gap when the announcement is more than one sequence ahead.
            void loadLatest.current(undefined,false)
          }else if(payload.eventType==='UPDATE')merge([message],true)
          if(payload.eventType==='UPDATE')setQuotes(current=>current[message.id]?
            {...current,[message.id]:{id:message.id,sender:message.sender,body:message.body.slice(0,240),expires_at:message.expires_at}}:current)
        }
      })
      .subscribe(status => { if (status === 'SUBSCRIBED') void loadLatest.current() })
    const timer = window.setInterval(sync, 3500)
    const removeReconnect = onReconnect(sync)
    hints.addEventListener('inbox', onHint)
    hints.addEventListener('ready', sync)
    hints.addEventListener('chat_activity', onActivity)
    return () => {
      controller.abort()
      ++activityVersion.current
      lifecycle.current=null
      inFlight.current=null
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
  const historyAllowed=history&&!blocked&&!hidden.includes(history.message)&&
    (history.own||activity?.share_peer_edit_history)
  useEffect(()=>{
    if(history&&!historyAllowed)setHistory(null)
  },[history,historyAllowed])
  useEffect(()=>{
    if(blocked)return
    const unavailable=new Set(hidden)
    const ids=messages.filter(message=>message.sender!==self&&!message.delivered_at&&!message.revoked_at&&
      !unavailable.has(message.id)&&!acknowledged.current.has(message.id)).slice(-100).map(message=>message.id)
    if(!ids.length)return
    for(const id of ids)acknowledged.current.add(id)
    void db!.rpc('st_v6_ack_message_delivery',{p_chat:chat.id,p_messages:ids}).then(({data})=>{
      const updated=new Set(data||[])
      for(const id of ids)if(!updated.has(id))acknowledged.current.delete(id)
    })
  },[blocked,chat.id,hidden,messages,self])
  const latestInbound = messages.findLast(message => message.sender !== self&&!message.revoked_at&&!hidden.includes(message.id))?.id
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
  }, [messages,outbox.length,pendingText.length])

  async function update(name: string, input: Record<string, unknown>) {
    const { error } = await db!.rpc(name, input)
    if (error) { inform(formatError(error, 'Could not update the conversation.')); return false }
    await Promise.all([load(), loadActivity()])
    if (name === 'st_v6_set_quiet_mute') hints.dispatchEvent(new Event('read_local'))
    return true
  }

  async function changeDraft(value: string) {
    syncedDraft.change(value)
    if (blocked || !activity?.share_own_typing || typingPolicyBusy || !navigator.onLine) return
    if (!value.trim()) {
      await stopTyping()
      return
    }
    const now = Date.now()
    if (now - typingPulse.current.sentAt > 2200) {
      typingPulse.current = { sentAt: now, stopped: false }
      await db!.rpc('st_v2_typing', { p_chat: chat.id, p_active: true })
    }
  }

  async function stopTyping() {
    const pulse = typingPulse.current
    if (!activity?.share_own_typing || !navigator.onLine || pulse.stopped || Date.now() - pulse.sentAt >= 5000) return
    pulse.stopped = true
    await db!.rpc('st_v2_typing', { p_chat: chat.id, p_active: false })
  }

  async function changeTypingPolicy() {
    setTypingPolicyBusy(true)
    try {
      const { error } = await db!.rpc('st_v6_set_typing_policy', {
        p_chat: chat.id, p_share: !activity?.share_own_typing,
      })
      if (error) inform(formatError(error, 'Could not update typing privacy.'))
      else await loadActivity()
    } finally {
      setTypingPolicyBusy(false)
    }
  }

  async function transmit(item:OutboxMessage) {
    if(sending.current||busy||blocked||!item.file)return
    sending.current=true
    setBusy(true)
    nearBottom.current=true
    const queued:OutboxMessage={...item,state:'queued'}
    setOutbox(previous=>previous.some(entry=>entry.id===item.id)
      ?previous.map(entry=>entry.id===item.id?queued:entry):[...previous,queued])
    try{
      const {duplicate}=await sendChatFile(chat.id,item.id,item.file,item.body)
      if(duplicate)inform('Attachment sent. You previously shared the same file contents in this chat.')
      setOutbox(previous=>previous.map(entry=>entry.id===item.id?{...entry,state:'sent'}:entry))
      void load()
    }catch(error){
      setOutbox(previous=>previous.map(entry=>entry.id===item.id?{...entry,state:'failed'}:entry))
      inform(formatError(error,'The attachment could not be sent.'))
    }finally{
      void refreshFileCapacity()
      sending.current=false
      setBusy(false)
    }
  }

  async function send(event: FormEvent) {
    event.preventDefault()
    const body=draft.trim()
    if((!body&&!attachment)||sending.current||busy||blocked)return
    const reply=replying?.id??null
    const at=new Date().toISOString()
    if(expireAfter){
      if(!navigator.onLine||attachment){inform('Reconnect to send a disappearing text message.');return}
      if(pendingExpiry.current?.body!==body||pendingExpiry.current.seconds!==expireAfter||pendingExpiry.current.reply!==reply)
        pendingExpiry.current={id:crypto.randomUUID(),body,seconds:expireAfter,reply}
      sending.current=true
      setBusy(true)
      try{
        const result=await db!.rpc('st_v6_send_disappearing_message',{
          p_chat:chat.id,p_id:pendingExpiry.current.id,p_body:body,p_seconds:expireAfter,p_reply:reply,
        })
        if(result.error)throw result.error
        pendingExpiry.current=null
        setExpireAfter(0)
        nearBottom.current=true
        void load()
      }catch(error){
        inform(formatError(error,'Could not send the disappearing message. Your draft is still here.'))
        return
      }finally{
        sending.current=false
        setBusy(false)
      }
    }else if(attachment){
      if(!navigator.onLine){inform('Reconnect to send attachments.');return}
      void transmit({id:attachment.id,body,reply,file:attachment.file,at,state:'queued'})
      setAttachment(null)
    }else{
      sending.current=true
      setBusy(true)
      try{
        await offlineMessages.enqueue({id:crypto.randomUUID(),chat:chat.id,body,reply,at})
        nearBottom.current=true
      }catch{
        inform('Could not save the outgoing message. Your draft is still here.')
        return
      }finally{
        sending.current=false
        setBusy(false)
      }
    }
    syncedDraft.clear(body)
    setReplying(current=>current?.id===reply?null:current)
    void stopTyping()
  }

  function pickEmoji(value:string) {
    const range=cursor.current??{start:draft.length,end:draft.length}
    const text=draft.slice(0,range.start)+value+draft.slice(range.end)
    if(text.length>4000){inform('The message exceeds the character limit.');return}
    void changeDraft(text);setEmoji(false)
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
    syncedDraft.clear(body)
    void stopTyping()
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
      <button type="button" className="secondary" aria-pressed={Boolean(activity?.muted)} disabled={blocked||!activity}
        onClick={() => void update('st_v6_set_quiet_mute', { p_chat: chat.id, p_muted: !activity?.muted })}>
        {activity?.muted ? <BellOff size={15}/> : <Bell size={15}/>} {activity?.muted ? 'Muted' : 'Mute'}
      </button>
      <button type="button" className="secondary" disabled={blocked} onClick={()=>setQuietSettings(true)}>Chat quiet hours</button>
      <button type="button" className="secondary" disabled={blocked||!activity}
        onClick={()=>setHistorySettings(true)}>Edit history settings</button>
      <button type="button" className="secondary" disabled={blocked||!activity||typingPolicyBusy}
        aria-pressed={Boolean(activity?.share_own_typing)} onClick={()=>void changeTypingPolicy()}>
        Share my typing
      </button>
      <button type="button" className="secondary" disabled={!activity||receiptPolicyBusy}
        aria-pressed={Boolean(activity?.share_own_read_receipts)}
        title="Applies to your direct chats and eligible rooms"
        onClick={async()=>{
          setReceiptPolicyBusy(true)
          try { await update('st_v6_set_read_receipt_policy',{p_enabled:!activity?.share_own_read_receipts}) }
          finally { setReceiptPolicyBusy(false) }
        }}>
        Share my read receipts
      </button>
    </div>
    {quietSettings && !blocked && <Dialog title="Chat quiet hours" close={()=>{setQuietSettings(false);void loadActivity()}}>
      <QuietHoursSettings chat={chat.id} hints={hints}/>
    </Dialog>}
    {showSearch && <form className="thread-toolbar" onSubmit={async event => {
      event.preventDefault()
      const query = String(new FormData(event.currentTarget).get('query')).trim()
      const { data, error } = await db!.rpc('st_v2_search_messages', { p_chat: chat.id, p_query: query })
      if (error) inform('Could not search this conversation.')
      else{
        const rows=(data as DirectMessage[]).filter(row=>!row.revoked_at&&!revoked.current.has(row.id))
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
      {(results ?? messages).filter(message=>!hidden.includes(message.id)&&
        (!message.expires_at||Date.parse(message.expires_at)>expiryClock)).map(message => {
        const own = message.sender === self
        const file=message.revoked_at?undefined:files[message.id]
        const sourceQuote=message.reply_to?quotes[message.reply_to]:null
        const quote=message.reply_to&&!hidden.includes(message.reply_to)&&!revoked.current.has(message.reply_to)
          &&(!sourceQuote?.expires_at||Date.parse(sourceQuote.expires_at)>expiryClock)
          ? quotes[message.reply_to]:null
        const read=own&&typeof activity?.read_sequence==='number'&&message.sequence<=activity.read_sequence
          &&message.sequence>=(activity.read_since_sequence??0)
        const selectedReactions = reactions.filter(reaction => reaction.message_id === message.id)
        return <div className={'message ' + (own ? 'own' : '')} key={message.id} data-sequence={message.sequence}>
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
            {message.voice_note&&!message.revoked_at ?
              <VoiceNotePlayer chat={chat.id} message={message.id} blocked={blocked} revision={Boolean(message.voice_transcript)}/> :
              (!file||message.body!=='Attachment: '+file.filename)&&<EmojiText value={message.body}/>}
            {file&&<button className="attachment-file" type="button" onClick={()=>void download(file)}>
              <Download size={16}/><span>{file.filename}<small>{Math.ceil(file.size_bytes/1024)} KiB</small></span>
            </button>}
          </div>
          {!own&&!message.revoked_at&&<MessageSafetyWarning key={message.id+':'+(message.edited_at||message.created_at)}
            account={self} message={message.id} revision={message.edited_at||message.created_at} body={message.body} sender={message.sender}
            onReport={()=>onReport(message,file)}/>}
          <div className="message-meta"><time dateTime={message.created_at}>{formatTime(message.created_at)}</time>
            {message.expires_at&&!message.revoked_at&&<span>Disappears at {formatTime(message.expires_at)}</span>}
            {message.forwarded&&!message.revoked_at&&<span>Forwarded</span>}
            {message.edited_at&&!message.revoked_at && (!blocked&&(own||activity?.share_peer_edit_history)?
              <button type="button" className="text-button" aria-label="View edit history" onClick={async () => {
              const { data, error } = await db!.from('st_v2_message_edits').select('id,body,created_at').eq('message_id', message.id).order('id', { ascending: false }).limit(25)
              if (error) inform('Could not load edit history.')
              else if(data.length&&!revoked.current.has(message.id))setHistory({message:message.id,own,revisions:data})
              else inform('Edit history is unavailable.')
            }}>Edited</button>:<span>Edited</span>)}
            {!message.revoked_at && (own ? <span>{read?'Read':message.delivered_at?'Delivered':'Sent'}</span> :
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
                {!message.expires_at&&<button type="button" className="text-button" onClick={() => void update('st_v2_pin', { p_chat: chat.id, p_message: message.id })}>Pin message</button>}
                <button type="button" className="text-button" onClick={() => setReplying(message)}>Reply</button>
                {!file&&!message.voice_note&&!message.expires_at&&<button type="button" className="text-button" onClick={()=>setForwarding(message.id)}>Forward message</button>}
                {own&&!file&&!message.voice_note&&!message.expires_at&&Date.now()-Date.parse(message.created_at)<86400000&&<button type="button" className="text-button" onClick={()=>setEditing(message)}>Edit message</button>}</>}
                {file&&<button type="button" className="text-button" onClick={()=>void download(file)}>Download attachment</button>}
                {!message.revoked_at&&!message.expires_at&&<button type="button" className="text-button" onClick={async()=>{
                  const result=await setSavedMessage(message.id,true)
                  inform(result.error?'Could not save this message.':'Message saved. Find it in Inbox → Saved messages.')
                }}>Save message</button>}
                {!blocked&&!message.revoked_at&&!message.expires_at&&<button type="button" className="text-button" onClick={()=>onTask(message.id)}>Create task from message</button>}
                {!own&&!message.revoked_at&&<button type="button" className="text-button" onClick={()=>onReport(message,file)}>Report message</button>}
                <button type="button" className="text-button" onClick={()=>setRemoving({message,action:'hide'})}>Delete for me</button>
                {own&&!message.revoked_at&&<button type="button" className="text-button remove-text" onClick={()=>setRemoving({message,action:'revoke'})}>Revoke for everyone</button>}
              </div>
            </details>
          </div>
        </div>
      })}
      {results===null&&[...outbox,...pendingText].map(item=><div className="message own" key={item.id}>
        <div className="message-reaction-header"><strong className="message-sender">{selfName} (you)</strong></div>
        <div className="bubble">{item.body&&<EmojiText value={item.body}/>}
          {item.file&&<span className="attachment-file"><Paperclip size={16}/>{item.file.name}</span>}
        </div>
        <div className="message-meta">
          <time dateTime={item.at}>{formatTime(item.at)}</time>
          <span role="status">{item.state==='queued'?'Queued':item.state==='sent'?'Sent':item.state==='damaged'?'Could not recover':'Failed to send'}</span>
          {item.state==='failed'&&
            <button type="button" className="text-button" disabled={busy||blocked} onClick={()=>{
              if(item.file)void transmit(item)
              else void offlineMessages.retry(item.id).catch(()=>inform('Could not retry the queued message.'))
            }}>Retry message</button>}
          {(item.state==='failed'||item.state==='damaged')&&
            <button type="button" className="text-button" onClick={()=>{
              if(item.file)setOutbox(previous=>previous.filter(entry=>entry.id!==item.id))
              else void offlineMessages.dismiss(item.id).catch(()=>inform('Could not dismiss the queued message.'))
            }}>Dismiss</button>}
        </div>
      </div>)}
    </div>
    {!blocked && activity?.typing_until && Date.parse(activity.typing_until) > clock && <p className="thread-typing" role="status">Contact is typing…</p>}
    {forwarding&&<ForwardMessageDialog key={forwarding}
      source={{kind:'direct',conversation:chat.id,message:forwarding,destinations:forwardDestinations}}
      close={()=>setForwarding(null)} onSent={()=>inform('Message forwarded.')}/>}
    {removing&&<Dialog title={removing.action==='hide'?'Delete for me?':'Revoke for everyone?'} close={()=>setRemoving(null)}>
      <p>{removing.action==='hide'?'This message will be hidden in your SecTalk chat.':'SecTalk will replace this message with a removal notice. Copies already saved and evidence already reported can remain.'}</p>
      <button type="button" className="danger" disabled={busy} onClick={async()=>{
        setBusy(true)
        try{
          if(await update('st_v5_message_action',{p_message:removing.message.id,p_action:removing.action})){
            if(removing.action==='hide') setHidden(previous=>[...new Set([...previous,removing.message.id])])
            else {
              const {data}=await db!.from('st_messages').select('*').eq('id',removing.message.id).maybeSingle()
              if(data)merge([data as DirectMessage])
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
    {history&&historyAllowed&&<Dialog title="Edit history" close={()=>setHistory(null)}>
      {history.revisions.map(edit=><article className="release-board-item" key={edit.id}><time dateTime={edit.created_at}>{new Date(edit.created_at).toLocaleString()}</time><p>{edit.body}</p></article>)}
    </Dialog>}
    {historySettings&&<Dialog title="Edit history settings" close={()=>setHistorySettings(false)}>
      <form onSubmit={async event=>{
        event.preventDefault()
        const share=new FormData(event.currentTarget).get('audience')==='shared'
        if(await update('st_v6_set_edit_history',{p_chat:chat.id,p_share:share}))setHistorySettings(false)
      }}>
        <p>This applies to earlier versions of your messages in this chat, including edits you already made.</p>
        <label>Who can see my edit history?
          <select name="audience" defaultValue={activity?.share_own_edit_history===false?'private':'shared'}>
            <option value="shared">Both contacts</option>
            <option value="private">Only me</option>
          </select>
        </label>
        <button className="primary" disabled={blocked}>Save history setting</button>
      </form>
    </Dialog>}
    {replying && (!replying.expires_at||Date.parse(replying.expires_at)>expiryClock) && <div className="thread-pin"><span>Replying to <EmojiText value={replying.body}/></span><button type="button" className="icon" aria-label="Cancel reply" onClick={() => setReplying(null)}><X size={16}/></button></div>}
    {attachment&&<div className="thread-pin"><Paperclip size={16}/><span>{attachment.file.name}</span>
      <button type="button" className="icon" disabled={busy} aria-label="Remove attachment" onClick={()=>setAttachment(null)}><X size={16}/></button>
    </div>}
    {emoji&&<Dialog title="Add emoji" close={()=>setEmoji(false)}><ChatEmoji onPick={pickEmoji}/></Dialog>}
    {reacting&&<Dialog title="Add a reaction" close={()=>setReacting(null)}><ChatEmoji onPick={value=>void react(reacting,value)}/></Dialog>}
    {scheduleOpen&&<Dialog title="Scheduled messages" close={()=>setScheduleOpen(false)}>
      <ScheduledMessages chat={chat.id} draft={draft.trim()} schedule={schedule} canSchedule={!blocked&&Boolean(draft.trim())&&!replying&&!attachment&&!expireAfter}/>
    </Dialog>}
    <DraftStatus draft={syncedDraft}/>
    {!blocked && fileCapacity && <p id="attachment-capacity" className="attachment-capacity muted">
      {formatChatFileBytes(fileCapacity.max_file_bytes)} per attachment · {formatChatFileBytes(Math.max(0,
        fileCapacity.max_storage_bytes - fileCapacity.stored_bytes - fileCapacity.reserved_bytes))} storage available
    </p>}
    <label className="attachment-capacity">Message timer<select value={expireAfter} disabled={blocked||busy||Boolean(attachment)}
      onChange={event=>setExpireAfter(Number(event.target.value))}>
      <option value={0}>Off</option><option value={60}>1 minute</option><option value={3600}>1 hour</option>
      <option value={86400}>1 day</option><option value={604800}>7 days</option>
    </select></label>
    <VoiceNoteRecorder key={chat.id} chat={chat.id} blocked={blocked} timer={expireAfter}
      disabled={busy||Boolean(attachment)||Boolean(replying)} onSent={()=>void load()}/>
    <form className="composer" onSubmit={send}>
      <input ref={filePicker} hidden type="file" accept={extensions} onChange={event=>{
        const file=event.target.files?.[0]
        event.target.value=''
        if(!file)return
        if(fileCapacity && file.size>fileCapacity.max_file_bytes){
          inform('Your limit is '+formatChatFileBytes(fileCapacity.max_file_bytes)+' per attachment.');return
        }
        if(!supportedFile(file)){inform('Choose an image, PDF, text or supported Office file up to 4 MiB.');return}
        setReplying(null);setAttachment({file,id:crypto.randomUUID()})
      }}/>
      <button type="button" className="icon" title="Attach file" aria-label="Attach file"
        aria-describedby={!blocked&&fileCapacity?'attachment-capacity':undefined}
        disabled={blocked||busy||Boolean(expireAfter)} onClick={()=>filePicker.current?.click()}><Paperclip size={19}/></button>
      <button type="button" className="icon" title="Add emoji" aria-label="Add emoji" disabled={blocked||busy} onClick={()=>{
        if(composerInput.current)cursor.current={start:composerInput.current.selectionStart,end:composerInput.current.selectionEnd}
        setEmoji(true)
      }}><Smile size={20}/></button>
      <textarea ref={composerInput} aria-label="Write a message" placeholder={blocked ? 'Contact blocked' : 'Write a message…'} disabled={blocked} rows={1} maxLength={4000} value={draft} onChange={e => void changeDraft(e.target.value)} onBlur={syncedDraft.flush} onKeyDown={event => {
        if (event.key === 'Enter' && !event.shiftKey && !event.nativeEvent.isComposing) { event.preventDefault(); event.currentTarget.form?.requestSubmit() }
      }} />
      <button type="button" className="icon" title="Scheduled messages" aria-label="Scheduled messages" onClick={()=>setScheduleOpen(true)}><CalendarClock size={19}/></button>
      <button className="primary square" title="Send message" aria-label="Send message" disabled={busy||(!draft.trim()&&!attachment)||blocked}><Send size={19} /></button>
    </form>
  </>
}
