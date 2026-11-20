'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { Users } from 'lucide-react'
import type { ManifestEntry } from '../lib/contact-key-verification'
import { db } from '../lib/data'
import { encryptedMessageWarning } from '../lib/encrypted-message-warning'
import { GroupMessageReport } from './group-message-report'
import { GroupFileDownload } from './group-file-download'
import { GroupHistoryTransfer } from './group-history-transfer'
import { MessageFormatting, RichMessage } from './rich-message'
import { EncryptedGroupSearch } from './encrypted-group-search'
import { clearGroupIndex, pruneGroupIndex, rememberGroupMessages } from '../lib/encrypted-group-search'
import { decryptGroupMessage, encryptGroupMessage, groupLocalDevice, openGroupKey, rotateGroupKey,
  type GroupCiphertext, type GroupEnvelope } from '../lib/group-chat-crypto'
import {maxGroupFileBytes,readGroupFileDescriptor,sealGroupFile,type GroupFileDescriptor} from '../lib/group-file-crypto'

type Group = { id: string; owner: string; name: string; epoch: number; member_cap: number }
type Member = { id: string; name: string }
type RenderMessage = (GroupCiphertext & { quarantined?: false }) |
  (Pick<GroupCiphertext,'id' | 'actor' | 'epoch' | 'sent'> & { quarantined: true })
type Snapshot = { group: Group; device: string; members: Member[]; envelopes: GroupEnvelope[]; messages: RenderMessage[] }
type Preview = { epoch: number; devices: ManifestEntry[]; plan_cap: number }
type PendingFile={file:File;group:string;epoch:number;id:string;ciphertext:Uint8Array<ArrayBuffer>;
  encrypted:Awaited<ReturnType<typeof encryptGroupMessage>>;uploaded:boolean}

async function groupAction<T>(action: string, group?: string, values?: object) {
  const result = await db!.rpc('st_group_chat', { p_action: action, p_group: group, p_data: values })
  if (result.error) throw Object.assign(new Error(result.error.message), { code: result.error.code })
  return result.data as T
}

export function GroupChat({user,contacts,openDeviceSettings,hints}:{user:string;contacts:Member[];openDeviceSettings:()=>void;hints:EventTarget}) {
  const [groups, setGroups] = useState<Group[]>([])
  const [selected, setSelected] = useState('')
  const [view, setView] = useState<Snapshot>()
  const [messages, setMessages] = useState<Array<RenderMessage & {text:string|null;file:GroupFileDescriptor|null}>>([])
  const [draft, setDraft] = useState('')
  const [attachment,setAttachment]=useState<File|null>(null)
  const pendingFile=useRef<PendingFile|null>(null)
  const [editor, setEditor] = useState<{ name: string; cap: number; members: string[]; previous_epoch: number }>()
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [revision, setRevision] = useState(0)
  const [ready, setReady] = useState(false)
  const nameFor = (id: string) => id === user ? 'You' : (view?.members.find(member => member.id === id)?.name || contacts.find(contact => contact.id === id)?.name || 'Group member')

  const refresh = useCallback(() => setRevision(current => current + 1), [])
  useEffect(()=>{
    const receive=(event:Event)=>{if((event as MessageEvent<string>).data===selected)refresh()}
    hints.addEventListener('group_file_published',receive)
    hints.addEventListener('group_history_transferred',receive)
    return ()=>{
      hints.removeEventListener('group_file_published',receive)
      hints.removeEventListener('group_history_transferred',receive)
    }
  },[hints,selected,refresh])
  useEffect(() => {
    let current = true
    let pending = false
    async function viewingAccount() {
      if (!current) return false
      const { data } = await db!.auth.getSession()
      return current && data.session?.user.id === user
    }
    async function update() {
      if (pending) return
      pending = true
      let listAuthorized = false
      try {
        const listed = await groupAction<Group[]>('list')
        listAuthorized = true
        if (!await viewingAccount()) return
        await pruneGroupIndex(user, new Set(listed.map(group => group.id))).catch(() => {})
        if (!current) return
        setGroups(listed)
        if (selected && !listed.some(group => group.id === selected)) {
          setSelected('')
          setView(undefined)
          setMessages([])
          setReady(false)
          return
        }
        if (!selected) return
        const snapshot = await groupAction<Snapshot>('read', selected)
        const device = await groupLocalDevice(user, snapshot.device)
        const keys = new Map(await Promise.all(snapshot.envelopes.map(async envelope =>
          [envelope.epoch, await openGroupKey(selected, device, envelope)] as const)))
        const opened = await Promise.all(snapshot.messages.map(async message => {
          const key = keys.get(message.epoch)
          let text: string | null = null
          let file:GroupFileDescriptor|null=null
          if (key && !message.quarantined) {
            try {
              const decrypted=await decryptGroupMessage(selected,key,message)
              file=readGroupFileDescriptor(decrypted)
              text=file?'Encrypted attachment: '+file.name:decrypted
            } catch { /* A failed signature stays unreadable. */ }
          }
          return {...message,text,file}
        }))
        if (!await viewingAccount()) return
        await rememberGroupMessages(device, selected, opened.flatMap(message => message.text === null ? [] : [{
          id: message.id, sent: message.sent, epoch: message.epoch, text: message.text,
        }])).catch(() => {})
        if (!current) return
        setView(snapshot)
        setMessages(opened)
        setReady(keys.has(snapshot.group.epoch))
      } catch (cause) {
        if (!await viewingAccount()) return
        if (cause instanceof Error && 'code' in cause && cause.code === '42501') {
          const purge = listAuthorized && selected ? clearGroupIndex(user, selected) : pruneGroupIndex(user, new Set())
          await purge.catch(() => {})
        }
        if (!current) return
        setView(undefined)
        setMessages([])
        setReady(false)
        if (cause instanceof Error) setError(cause.message)
      } finally {
        pending = false
      }
    }
    void update()
    const poll = window.setInterval(() => void update(), 4000)
    return () => { current = false; window.clearInterval(poll) }
  }, [user, selected, revision])

  function choose(id: string) {
    setSelected(id)
    setView(undefined)
    setMessages([])
    setReady(false)
    setEditor(undefined)
    setDraft('')
    setAttachment(null)
    pendingFile.current=null
    setError('')
  }

  async function saveGroup() {
    if (!editor || busy) return
    setBusy(true)
    setError('')
    try {
      const group = selected || crypto.randomUUID()
      const preview = await groupAction<Preview>('preview', group, editor)
      const envelopes = await rotateGroupKey(group, preview.epoch, preview.devices)
      await groupAction('rotate', group, { ...editor, epoch: preview.epoch, envelopes })
      choose(group)
      refresh()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not update group.')
    } finally {
      setBusy(false)
    }
  }

  async function send() {
    if (!view || busy || !ready) return
    const envelope = view.envelopes.find(candidate => candidate.epoch === view.group.epoch)
    if (!envelope) return
    setBusy(true)
    setError('')
    try {
      const device = await groupLocalDevice(user, view.device)
      const key = await openGroupKey(view.group.id, device, envelope)
      await groupAction('send', view.group.id, await encryptGroupMessage(view.group.id, view.group.epoch, device, key, draft))
      setDraft('')
      refresh()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not send group message.')
      refresh()
    } finally {
      setBusy(false)
    }
  }

  async function sendAttachment(){
    if(!attachment||!view||!ready||busy)return
    const {group,device:localDevice,envelopes}=view
    const envelope=envelopes.find(entry=>entry.epoch===group.epoch)
    if(!envelope)return
    setBusy(true);setError('')
    try{
      let work=pendingFile.current
      if(!work||work.file!==attachment||work.group!==group.id||work.epoch!==group.epoch){
        const id=crypto.randomUUID()
        const device=await groupLocalDevice(user,localDevice)
        const key=await openGroupKey(group.id,device,envelope)
        const sealed=await sealGroupFile(group.id,group.epoch,id,attachment)
        const encrypted=await encryptGroupMessage(group.id,group.epoch,device,key,sealed.message)
        work={file:attachment,group:group.id,epoch:group.epoch,id,ciphertext:sealed.ciphertext,encrypted,uploaded:false}
        pendingFile.current=work
      }
      const {data}=await db!.auth.getSession()
      if(data.session?.user.id!==user)throw new Error('Sign in on the authorized browser to send this attachment.')
      if(!work.uploaded){
        const staged=await db!.rpc('st_v7_stage_group_file',{p_group:group.id,p_file:work.id,p_epoch:group.epoch,p_cipher_bytes:work.ciphertext.byteLength})
        if(staged.error)throw new Error(staged.error.message)
        const uploaded=await fetch('/api/group-files?file='+work.id,{method:'POST',headers:{
          'Content-Type':'application/octet-stream',Authorization:'Bearer '+data.session.access_token,
        },body:work.ciphertext})
        if(!uploaded.ok){const status=await uploaded.json().catch(()=>null);throw new Error(status?.error||'Could not store this encrypted attachment.')}
        work.uploaded=true
      }
      const current=await db!.auth.getSession()
      if(current.data.session?.user.id!==user)return
      const sent=await db!.rpc('st_v7_publish_group_file',{p_file:work.id,p_encrypted:work.encrypted})
      if(sent.error)throw new Error(sent.error.message)
      setAttachment(null)
      pendingFile.current=null
      refresh()
    }catch(cause){setError(cause instanceof Error?cause.message:'Could not send the encrypted attachment.');refresh()}
    finally{setBusy(false)}
  }

  const choices = editor ? [...contacts, ...editor.members.filter(id => !contacts.some(contact => contact.id === id))
    .map(id => ({ id, name: nameFor(id) }))] : []

  return <section className="content-panel">
    <header className="content-title"><div className="card-icon"><Users size={22} /></div>
      <div><h1>Group chats</h1><p>Group messages are encrypted on approved browser devices.</p></div></header>
    <div className="settings-card">
      <label>Open group<select value={selected} onChange={event => choose(event.target.value)} disabled={busy}>
        <option value="">Choose a group</option>{groups.map(group => <option key={group.id} value={group.id}>{group.name}</option>)}
      </select></label>
      <button className="secondary" disabled={busy} onClick={() => { choose(''); setEditor({ name: '', cap: 4, members: [], previous_epoch: 0 }) }}>New group</button>
      <button className="text-button" onClick={openDeviceSettings}>Manage approved devices</button>
      {error && <p role="alert">{error}</p>}
      {view && <div><h2>{view.group.name}</h2><p>{view.members.map(member => nameFor(member.id)).join(', ')}</p>
        {view.group.owner === user && <button className="secondary" disabled={busy} onClick={() => setEditor({
          name: view.group.name, cap: view.group.member_cap, previous_epoch: view.group.epoch, members: view.members.map(member => member.id).filter(id => id !== user),
        })}>Manage members and encryption</button>}
        {!ready && <p role="status">Ask the group owner to refresh keys for this approved device.</p>}
        <GroupHistoryTransfer key={view.group.id+':'+view.device} actor={user} group={view.group.id} source={view.device}/>
      </div>}
      {editor && <form onSubmit={event => { event.preventDefault(); void saveGroup() }}>
        <label>Group name<input value={editor.name} maxLength={64} required onChange={event => setEditor({ ...editor, name: event.target.value })} /></label>
        <label>Member limit including you<input value={editor.cap} type="number" min={2} max={32} required
          onChange={event => setEditor({ ...editor, cap: Number(event.target.value) })} /></label>
        <fieldset><legend>Group members</legend>{choices.map(contact => <label key={contact.id}>
          <input type="checkbox" checked={editor.members.includes(contact.id)} onChange={event => setEditor({
            ...editor, members: event.target.checked ? [...editor.members, contact.id] : editor.members.filter(id => id !== contact.id),
          })} /> {contact.name}</label>)}</fieldset>
        <button className="primary" disabled={busy}>{selected ? 'Save members and rotate keys' : 'Create encrypted group'}</button>
        <button className="text-button" disabled={busy} type="button" onClick={() => setEditor(undefined)}>Cancel</button>
      </form>}
      {view && <><EncryptedGroupSearch key={view.group.id + ':' + view.group.epoch + ':' + view.device + ':' +
          messages.filter(message => message.quarantined).map(message => message.id).join(',')}
        owner={user} group={view.group.id} device={view.device} /><ol aria-label="Group messages">{messages.map(message => {
        const received = message.actor !== user && message.text !== null
        const warning = received && message.text ? encryptedMessageWarning(message.text) : null
        return <li key={message.id}><strong>{nameFor(message.actor)}</strong>
          {message.file?<GroupFileDownload actor={user} group={view.group.id} epoch={message.epoch} message={message.id} file={message.file}/>:
            <p>{message.quarantined ? 'Message quarantined by Safety review.' : message.text === null ? 'Encrypted message could not be verified.' :
              <RichMessage value={message.text} account={user} mode='encrypted' allowLinks={!warning}/>}</p>}
          {warning && <p className="warning">{warning} Checked on this device.</p>}
          {received && message.text && <GroupMessageReport group={view.group.id} message={message.id} text={message.text} />}
        </li>
      })}</ol>
      <MessageFormatting account={user} mode="encrypted"/>
      <form onSubmit={event => { event.preventDefault(); void send() }}><label>Group message
        <textarea value={draft} maxLength={4000} disabled={!ready || busy} onChange={event => setDraft(event.target.value)} />
      </label><button className="primary" disabled={!ready || busy || !draft.trim()}>Send encrypted message</button></form>
      <div className="release-form">
        <label>Encrypted group attachment<input type="file" aria-label="Encrypted group attachment" disabled={!ready||busy}
          onChange={event=>{
            const file=event.currentTarget.files?.[0]
            event.currentTarget.value=''
            if(!file)return
            if(file.size<1||file.size>maxGroupFileBytes){setError('Choose a file up to 4 MiB containing data.');return}
            pendingFile.current=null;setAttachment(file);setError('')
          }}/></label>
        {attachment&&<div className="actions"><p>{attachment.name}</p>
          <button className="text-button" type="button" disabled={busy} onClick={()=>{pendingFile.current=null;setAttachment(null);setError('')}}>Remove attachment</button>
        </div>}
        <button className="secondary" type="button" onClick={()=>void sendAttachment()} disabled={!ready||busy||!attachment}>
          Send encrypted attachment
        </button>
      </div></>}
    </div>
  </section>
}
