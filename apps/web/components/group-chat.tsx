'use client'

import { useCallback, useEffect, useState } from 'react'
import { Users } from 'lucide-react'
import type { ManifestEntry } from '../lib/contact-key-verification'
import { db } from '../lib/data'
import { encryptedMessageWarning } from '../lib/encrypted-message-warning'
import { GroupMessageReport } from './group-message-report'
import { EncryptedGroupSearch } from './encrypted-group-search'
import { clearGroupIndex, pruneGroupIndex, rememberGroupMessages } from '../lib/encrypted-group-search'
import { decryptGroupMessage, encryptGroupMessage, groupLocalDevice, openGroupKey, rotateGroupKey,
  type GroupCiphertext, type GroupEnvelope } from '../lib/group-chat-crypto'

type Group = { id: string; owner: string; name: string; epoch: number; member_cap: number }
type Member = { id: string; name: string }
type Snapshot = { group: Group; device: string; members: Member[]; envelopes: GroupEnvelope[]; messages: GroupCiphertext[] }
type Preview = { epoch: number; devices: ManifestEntry[]; plan_cap: number }

async function groupAction<T>(action: string, group?: string, values?: object) {
  const result = await db!.rpc('st_group_chat', { p_action: action, p_group: group, p_data: values })
  if (result.error) throw Object.assign(new Error(result.error.message), { code: result.error.code })
  return result.data as T
}

export function GroupChat({ user, contacts, openDeviceSettings }: { user: string; contacts: Member[]; openDeviceSettings: () => void }) {
  const [groups, setGroups] = useState<Group[]>([])
  const [selected, setSelected] = useState('')
  const [view, setView] = useState<Snapshot>()
  const [messages, setMessages] = useState<Array<GroupCiphertext & { text: string | null }>>([])
  const [draft, setDraft] = useState('')
  const [editor, setEditor] = useState<{ name: string; cap: number; members: string[]; previous_epoch: number }>()
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [revision, setRevision] = useState(0)
  const [ready, setReady] = useState(false)
  const nameFor = (id: string) => id === user ? 'You' : (view?.members.find(member => member.id === id)?.name || contacts.find(contact => contact.id === id)?.name || 'Group member')

  const refresh = useCallback(() => setRevision(current => current + 1), [])
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
          if (key) {
            try { text = await decryptGroupMessage(selected, key, message) } catch { /* A failed signature stays unreadable. */ }
          }
          return { ...message, text }
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
      {view && <><EncryptedGroupSearch key={view.group.id + ':' + view.group.epoch + ':' + view.device}
        owner={user} group={view.group.id} device={view.device} /><ol aria-label="Group messages">{messages.map(message => {
        const received = message.actor !== user && message.text !== null
        const warning = received && message.text ? encryptedMessageWarning(message.text) : null
        return <li key={message.id}><strong>{nameFor(message.actor)}</strong>
          <p style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{message.text ?? 'Encrypted message could not be verified.'}</p>
          {warning && <p className="warning">{warning} Checked on this device.</p>}
          {received && message.text && <GroupMessageReport group={view.group.id} message={message.id} text={message.text} />}
        </li>
      })}</ol>
      <form onSubmit={event => { event.preventDefault(); void send() }}><label>Group message
        <textarea value={draft} maxLength={4000} disabled={!ready || busy} onChange={event => setDraft(event.target.value)} />
      </label><button className="primary" disabled={!ready || busy || !draft.trim()}>Send encrypted message</button></form></>}
    </div>
  </section>
}
