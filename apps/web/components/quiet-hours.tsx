'use client'

import { useEffect, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'

type EffectiveAvailability = { busy: boolean; status: string }
type QuietSettings = {
  muted: boolean
  snooze_until: string | null
  days: number[] | null
  starts_at: string | null
  ends_at: string | null
  zone: string | null
  scheduled_status: string | null
  active: boolean
}

export function useEffectiveAvailability(peer: string | undefined, hints: EventTarget) {
  const [current, setCurrent] = useState<{ peer: string; value: EffectiveAvailability } | null>(null)
  useEffect(() => {
    if (!peer) return
    let disconnected = false
    let sequence = 0
    const refresh = async () => {
      const request = ++sequence
      const result = await db!.rpc('st_v6_effective_availability', { p_user: peer })
      if (!disconnected && request === sequence) {
        setCurrent(result.data ? { peer, value: result.data as EffectiveAvailability } : null)
      }
    }
    void refresh()
    hints.addEventListener('availability', refresh)
    hints.addEventListener('presence', refresh)
    hints.addEventListener('ready', refresh)
    const timer = window.setInterval(refresh, 10000)
    return () => {
      disconnected = true
      hints.removeEventListener('availability', refresh)
      hints.removeEventListener('presence', refresh)
      hints.removeEventListener('ready', refresh)
      window.clearInterval(timer)
    }
  }, [peer, hints])
  return current?.peer === peer ? current?.value : undefined
}

export function useQuietIncoming(call: { id: string; chat_id: string } | null, hints: EventTarget) {
  const id = call?.id
  const chat = call?.chat_id
  const [decision, setDecision] = useState<{ id: string; quiet: boolean } | null>(null)
  useEffect(() => {
    if (!id || !chat) return
    let disconnected = false
    let sequence = 0
    const refresh = async () => {
      const request = ++sequence
      const { data } = await db!.rpc('st_v6_direct_alert_quiet', { p_chat: chat, p_category: 'call' })
      if (!disconnected && request === sequence) setDecision({ id, quiet: data !== false })
    }
    void refresh()
    hints.addEventListener('availability', refresh)
    hints.addEventListener('ready', refresh)
    const timer = window.setInterval(refresh, 5000)
    return () => {
      disconnected = true
      hints.removeEventListener('availability', refresh)
      hints.removeEventListener('ready', refresh)
      window.clearInterval(timer)
    }
  }, [id, chat, hints])
  return Boolean(id && (decision?.id !== id || decision.quiet))
}

const weekdays = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

function ScheduleForm({ settings, account, busy, save }: {
  settings: QuietSettings; account: boolean; busy: boolean
  save: (fields: Record<string, unknown>) => Promise<void>
}) {
  const [enabled, setEnabled] = useState(Boolean(settings.days))
  const [days, setDays] = useState(settings.days ?? [1, 2, 3, 4, 5, 6, 7])
  const [zone, setZone] = useState(settings.zone ?? Intl.DateTimeFormat().resolvedOptions().timeZone)
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const fields = new FormData(event.currentTarget)
    void save({
      p_days: enabled ? [...days].sort((a, b) => a - b) : null,
      p_start: enabled ? fields.get('start') : null,
      p_end: enabled ? fields.get('end') : null,
      p_zone: enabled ? zone.trim() : null,
      ...(account ? { p_status: enabled ? fields.get('status') : null } : {}),
    })
  }
  return <form onSubmit={submit}>
    <label className="task-check"><input type="checkbox" checked={enabled}
      onChange={event => setEnabled(event.target.checked)}/> Schedule quiet hours</label>
    {enabled && <>
      <fieldset><legend>Quiet days</legend>
        <div className="actions">{weekdays.map((day, index) => <label className="task-check" key={day}>
          <input type="checkbox" checked={days.includes(index + 1)}
            onChange={event => setDays(current => event.target.checked
              ? [...current, index + 1]
              : current.filter(value => value !== index + 1))}/> {day}
        </label>)}</div>
      </fieldset>
      <div className="actions">
        <label>Starts at<input name="start" type="time" required step={60} defaultValue={settings.starts_at?.slice(0, 5) ?? '22:00'}/></label>
        <label>Ends at<input name="end" type="time" required step={60} defaultValue={settings.ends_at?.slice(0, 5) ?? '07:00'}/></label>
      </div>
      <p>If the end time is earlier, quiet hours continue into the next day.</p>
      <label>Time zone<input value={zone} required maxLength={100} onChange={event => setZone(event.target.value)}/></label>
      <button type="button" className="text-button"
        onClick={() => setZone(Intl.DateTimeFormat().resolvedOptions().timeZone)}>Use device time zone</button>
      {account && <label>Status during quiet hours (optional)
        <input name="status" maxLength={140} defaultValue={settings.scheduled_status ?? ''}/>
      </label>}
    </>}
    <button type="submit" className="primary" disabled={busy || (enabled && !days.length)}>Save quiet hours</button>
  </form>
}

export function QuietHoursSettings({ chat = null, room, channel, hints }: {
  chat?: string | null; room?: string; channel?: string; hints?: EventTarget
}) {
  const account = !chat && !room && !channel
  const [settings, setSettings] = useState<QuietSettings | null>(null)
  const [feedback, setFeedback] = useState('')
  const [loadingError, setLoadingError] = useState(false)
  const [busy, setBusy] = useState(false)
  const [minutes, setMinutes] = useState(60)
  const [muteIntent, setMuteIntent] = useState<boolean | null>(null)
  useEffect(() => {
    let current = true
    let sequence = 0
    const refresh = async () => {
      const request = ++sequence
      const { data, error } = await readQuietSettings(chat, room, channel)
      if (!current || request !== sequence) return
      setLoadingError(Boolean(error))
      if (!error) setSettings(data as QuietSettings)
    }
    void refresh()
    hints?.addEventListener('availability', refresh)
    hints?.addEventListener('ready', refresh)
    const timer = window.setInterval(refresh, 15000)
    return () => {
      current = false
      hints?.removeEventListener('availability', refresh)
      hints?.removeEventListener('ready', refresh)
      window.clearInterval(timer)
    }
  }, [chat, hints, room, channel])

  async function update(action: 'mute' | 'snooze' | 'schedule', fields: Record<string, unknown>, success: string) {
    setBusy(true)
    setFeedback('')
    const { error } = room || channel
      ? await db!.rpc(room ? 'st_v6_set_room_quiet' : 'st_v6_set_channel_quiet',
        { ...(room ? { p_room: room } : { p_channel: channel }), p_action: action, ...fields })
      : await db!.rpc('st_v6_set_quiet_' + action, { p_chat: chat, ...fields, ...(action==='schedule'&&!account?{p_status:null}:{}) })
    if (error) {
      setBusy(false)
      setFeedback(formatError(error, 'Could not update notification settings.'))
      return false
    }
    hints?.dispatchEvent(new Event('availability'))
    hints?.dispatchEvent(new Event('read_local'))
    if (room || channel) {
      const result = await readQuietSettings(chat, room, channel)
      if (!result.error) setSettings(result.data as QuietSettings)
    }
    setBusy(false)
    setFeedback(success)
    return true
  }

  async function changeMute(muted: boolean) {
    setMuteIntent(muted)
    if (await update('mute', { p_muted: muted }, 'Mute setting saved.')) {
      setSettings(previous => previous && { ...previous, muted })
    }
    setMuteIntent(null)
  }

  if (!settings) return <p role="status">{loadingError ? 'Could not load notification settings.' : 'Loading notification settings…'}</p>
  const snoozed = settings.snooze_until && Date.parse(settings.snooze_until) > Date.now()
  const scheduleKey = JSON.stringify([settings.days, settings.starts_at, settings.ends_at, settings.zone, settings.scheduled_status])
  return <div className="quiet-hours">
    {account && <h3>Do not disturb</h3>}
    <p>{room || channel ? 'Silence alerts from this conversation.' : chat ? 'Silence direct message alerts and incoming calls from this contact.' : 'Silence conversation alerts and incoming calls. Your accepted contacts see Busy when you share availability.'}</p>
    <p role="status">{settings.active ? 'Notifications are quiet now.' : 'Notifications are enabled.'}</p>
    <label className="task-check"><input type="checkbox" checked={muteIntent ?? settings.muted} disabled={busy}
      onChange={event => void changeMute(event.target.checked)}/> Mute notifications</label>
    <div className="actions">
      <label>Snooze for<select value={minutes} disabled={busy} onChange={event => setMinutes(Number(event.target.value))}>
        <option value={30}>30 minutes</option><option value={60}>1 hour</option>
        <option value={480}>8 hours</option><option value={1440}>1 day</option>
        <option value={10080}>1 week</option>
      </select></label>
      <button className="secondary" type="button" disabled={busy}
        onClick={() => void update('snooze', { p_minutes: minutes }, 'Notifications snoozed.')}>Snooze notifications</button>
      {snoozed && <button className="secondary" type="button" disabled={busy}
        onClick={() => void update('snooze', { p_minutes: 0 }, 'Snooze ended.')}>End snooze</button>}
    </div>
    {snoozed && settings.snooze_until && <p>Snoozed until {new Date(settings.snooze_until).toLocaleString()}.</p>}
    <ScheduleForm key={scheduleKey} account={account} settings={settings} busy={busy}
      save={async fields => { await update('schedule', fields, 'Quiet hours saved.') }}/>
    {feedback && <p role="status">{feedback}</p>}
  </div>
}

function readQuietSettings(chat: string | null, room?: string, channel?: string) {
  if (room) return db!.rpc('st_v6_room_quiet_settings', { p_room: room })
  if (channel) return db!.rpc('st_v6_channel_quiet_settings', { p_channel: channel })
  return db!.rpc('st_v6_quiet_settings', { p_chat: chat })
}
