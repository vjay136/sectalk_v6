'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'

const actions = [
  ['post', 'Post messages and replies'],
  ['react', 'Add reactions'],
  ['upload', 'Upload files'],
  ['mention_all', 'Mention the room or online members'],
  ['start_call', 'Start a room call'],
] as const
type Capability = typeof actions[number][0]
type Rules = Partial<Record<Capability, 'allow' | 'deny'>>
type Role = 'owner' | 'moderator' | 'member'
const roleLabels: Record<Role, string> = { owner: 'Owner', moderator: 'Moderator', member: 'Member' }
type State = {
  post: boolean; react: boolean; mention_all: boolean;
  editable: Partial<Record<Role, Rules>>
}

export function useRoomPermissions(room: string | null) {
  const [state, setState] = useState<State | null>(null)
  const refresh = useCallback(async (signal?: AbortSignal) => {
    if (!room) return
    const request = db!.rpc('st_v6_room_permission_state', { p_room: room })
    const result = await (signal ? request.abortSignal(signal) : request)
    if (!signal?.aborted) setState(result.error ? null : result.data as State | null)
  }, [room])
  useEffect(() => {
    if (!room) return
    const controller = new AbortController()
    void refresh(controller.signal)
    const timer = window.setInterval(() => void refresh(controller.signal), 5000)
    return () => {
      controller.abort()
      window.clearInterval(timer)
    }
  }, [refresh, room])
  return { state, refresh }
}

export function RoomPermissionSettings({ room, editable, refresh }: {
  room: string; editable: State['editable']; refresh: () => Promise<void>
}) {
  const available = (Object.keys(roleLabels) as Role[]).filter(role => editable[role] !== undefined)
  const [role, setRole] = useState<Role>('member')
  const selected = available.includes(role) ? role : available[0]
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  if (!selected) return null
  const rules = editable[selected] ?? {}

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    setBusy(true)
    setMessage('')
    setError('')
    const form = new FormData(event.currentTarget)
    const overrides = Object.fromEntries(actions.flatMap(([action]) => {
      const value = form.get(action)
      return value === 'allow' || value === 'deny' ? [[action, value]] : []
    }))
    try {
      const result = await db!.rpc('st_v6_set_room_role_overrides', { p_room: room, p_role: selected, p_rules: overrides })
      if (result.error) throw result.error
      await refresh()
      setMessage(roleLabels[selected] + ' permissions saved.')
    } catch (failure) {
      setError(formatError(failure, 'Could not save room permissions.'))
    } finally {
      setBusy(false)
    }
  }

  return <section className="release-section" aria-label="Room role permissions">
    <h3>Room role permissions</h3>
    <p>Room defaults, workspace policies and read-only protections still apply where required.</p>
    <label>Room role<select value={selected} disabled={busy} onChange={event => {
      setRole(event.target.value as Role)
      setMessage('')
      setError('')
    }}>{available.map(value => <option key={value} value={value}>{roleLabels[value]}</option>)}</select></label>
    <form className="release-form" key={selected + JSON.stringify(rules)} onSubmit={save}>
      {actions.map(([action, label]) => <label key={action}>{label}<select name={action} aria-label={label}
        defaultValue={rules[action] ?? 'inherit'} disabled={busy}>
        <option value="inherit">Room default</option><option value="allow">Allow</option><option value="deny">Block</option>
      </select></label>)}
      <button className="secondary" disabled={busy}>Save room permissions</button>
    </form>
    {message && <p role="status">{message}</p>}
    {error && <p className="error" role="alert">{error}</p>}
  </section>
}
