'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db } from '../lib/data'

type Action = 'revoke' | 'wipe' | 'cancel_wipe' | 'block_device' | 'mark_managed' | 'clear_managed'
type Device = {
  id: string; trust: 'known' | 'trusted' | 'managed' | 'blocked'; registered_at: string
  active_sessions: number; locked: boolean; wiped: boolean; operator_managed: boolean
  command_kind: 'revoke' | 'lock' | 'wipe' | null
  command_state: 'pending' | 'delivered' | 'acknowledged' | 'cancelled' | null
  operator_wipe: boolean
  audit: { action: Action; reason: string; occurred_at: string }[]
}
const actionLabels: Record<Action,string> = {
  revoke: 'Revoke device sessions', wipe: 'Wipe local device keys', cancel_wipe: 'Cancel pending wipe',
  block_device: 'Block registered device',
  mark_managed: 'Mark as managed', clear_managed: 'Clear managed flag',
}
const explanations: Record<Action,string> = {
  revoke: 'End the native sessions linked to this device. The user can sign in again.',
  wipe: 'End the linked sessions and ask this device to erase its local keys. An offline device can complete the wipe once it reconnects.',
  cancel_wipe: 'Cancel this operator wipe before the device receives it.',
  block_device: 'Permanently revoke this registered identity and end its linked sessions. The device keeps its local keys.',
  mark_managed: 'Mark this already trusted device as managed.',
  clear_managed: 'Remove the operator-managed flag and return this device to trusted.',
}

export function OperatorAccountDevices({ accountId, onAccessChanged }: {
  accountId: string; onAccessChanged: () => Promise<void>
}) {
  const [open, setOpen] = useState(false)
  const [devices, setDevices] = useState<Device[] | null>(null)
  const [selected, setSelected] = useState<{ device: string; action: Action } | null>(null)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const load = useCallback(async () => {
    const { data, error } = await db!.rpc('st_v7_operator_device_inventory', { p_owner: accountId })
    if (error) {
      setDevices(null)
      setError('Could not load registered devices.')
      if (error.code === '42501') await onAccessChanged()
      return
    }
    setDevices(data as Device[])
  }, [accountId, onAccessChanged])

  useEffect(() => {
    if (!open) return
    void load()
    const timer = window.setInterval(load, 4000)
    return () => window.clearInterval(timer)
  }, [open, load])

  async function confirm(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!selected || busy) return
    const fields = new FormData(event.currentTarget)
    setBusy(true)
    setError('')
    setMessage('')
    const { data, error } = await db!.rpc('st_v7_operator_device_action', {
      p_owner: accountId, p_device: selected.device, p_action: selected.action,
      p_reason: String(fields.get('reason') ?? '').trim(),
    })
    if (error || data !== true) {
      setError(error?.code === '22023' ? error.message : 'This action is unavailable for the current device state.')
      if (error?.code === '42501') await onAccessChanged()
    } else {
      setMessage('Device action recorded.')
      setSelected(null)
    }
    setBusy(false)
    await load()
  }

  function choose(device: string, action: Action) {
    setSelected({ device, action })
    setMessage('')
    setError('')
  }

  return <section className="release-section" aria-label="Operator device inventory">
    <details onToggle={event => setOpen(event.currentTarget.open)}>
      <summary>Registered devices</summary>
      <p>Review trust and session activity for this account’s registered devices.</p>
      <button className="secondary" type="button" onClick={() => void load()}>Refresh registered devices</button>
      {!devices && !error && <p role="status">Loading registered devices…</p>}
      {devices?.length === 0 && <p>No registered devices.</p>}
      {devices?.map(device => {
        const pending = device.command_state === 'pending' || device.command_state === 'delivered'
        return <article className="release-board-item" key={device.id}>
          <h4>Device {device.id.slice(0,8)}</h4>
          <p><span className="pill">{device.trust}</span> · {device.active_sessions} active {device.active_sessions === 1 ? 'session' : 'sessions'}</p>
          <p>Registered <time dateTime={device.registered_at}>{new Date(device.registered_at).toLocaleString()}</time>
            {device.wiped ? ' · Keys wiped' : device.locked ? ' · Locked' : ''}</p>
          {device.command_kind && <p>Latest command · {device.command_kind} · {device.command_state}</p>}
          {device.audit.length > 0 && <details>
            <summary>Recent operator actions</summary>
            <ul className="audit">{device.audit.map(event => <li key={event.action + event.occurred_at}>
              <strong>{actionLabels[event.action]}</strong> · <time dateTime={event.occurred_at}>{new Date(event.occurred_at).toLocaleString()}</time>
              <p>{event.reason}</p>
            </li>)}</ul>
          </details>}
          <div className="actions">
            {!device.wiped && device.trust !== 'blocked' && <button className="secondary" type="button" disabled={busy}
              onClick={() => choose(device.id, 'block_device')}>{actionLabels.block_device}</button>}
            {!device.wiped && !pending && <button className="secondary" type="button" disabled={busy || !device.active_sessions}
              onClick={() => choose(device.id, 'revoke')}>{actionLabels.revoke}</button>}
            {!device.wiped && !pending && <button className="secondary" type="button" disabled={busy}
              onClick={() => choose(device.id, 'wipe')}>{actionLabels.wipe}</button>}
            {device.operator_wipe && device.command_state === 'pending' && <button className="secondary" type="button" disabled={busy}
              onClick={() => choose(device.id, 'cancel_wipe')}>{actionLabels.cancel_wipe}</button>}
            {!device.locked && !device.wiped && !pending && device.trust === 'trusted' && <button className="secondary" type="button" disabled={busy}
              onClick={() => choose(device.id, 'mark_managed')}>{actionLabels.mark_managed}</button>}
            {!device.locked && !device.wiped && !pending && device.trust === 'managed' && device.operator_managed &&
              <button className="secondary" type="button" disabled={busy} onClick={() => choose(device.id, 'clear_managed')}>{actionLabels.clear_managed}</button>}
          </div>
          {selected?.device === device.id && <form className="release-form" key={selected.action} onSubmit={confirm}>
            <h5>{actionLabels[selected.action]}</h5>
            <p>{explanations[selected.action]}</p>
            <label>Case reference and reason<textarea name="reason" required minLength={10} maxLength={240}/></label>
            <button className="primary" disabled={busy}>Confirm {actionLabels[selected.action].toLowerCase()}</button>
            <button className="secondary" disabled={busy} type="button" onClick={() => setSelected(null)}>Cancel</button>
          </form>}
        </article>
      })}
      {message && <p role="status">{message}</p>}
      {error && <p className="error" role="alert">{error}</p>}
    </details>
  </section>
}
