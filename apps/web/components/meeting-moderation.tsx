'use client'

import { useState } from 'react'
import { db, formatError } from '../lib/data'

type Action = 'lock' | 'chat' | 'screen' | 'mute' | 'mute_all' | 'remove' | 'cohost' | 'end'
type Moderate = (action: Action, target?: string, enabled?: boolean) => Promise<void>

export function useMeetingModeration(meeting: string, reload: () => Promise<unknown>) {
  const [running, setRunning] = useState(false)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')

  async function act(action: Action, target?: string, enabled?: boolean) {
    if (running) return
    setRunning(true)
    setNotice('')
    setError('')
    try {
      const { data } = await db!.auth.getSession()
      const response = await fetch('/api/meetings/moderate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + data.session?.access_token },
        body: JSON.stringify({ meetingId: meeting, action, target, enabled }),
      })
      const result = await response.json()
      if (!response.ok) throw new Error(result.error)
      if (action === 'mute' || action === 'mute_all') {
        const affected = result.affected as number
        setNotice(affected === 0 ? 'No eligible microphones were active.'
          : affected === 1 ? 'Muted one microphone.' : 'Muted ' + affected + ' microphones.')
      }
      if (action === 'remove') setNotice('Participant removed.')
      if (action === 'cohost') setNotice(enabled ? 'Co-host access granted.' : 'Co-host access removed.')
    } catch (failure) {
      setError(formatError(failure, 'The meeting action failed.'))
    } finally {
      await reload().catch(() => {})
      setRunning(false)
    }
  }

  return { act, running, notice, error }
}

export function MeetingModeratorActions({ locked, chatDisabled, shareDisabled, busy, moderate }: {
  locked: boolean; chatDisabled: boolean; shareDisabled: boolean; busy: boolean; moderate: Moderate
}) {
  return <section className="release-section" aria-label="Meeting moderation">
    <div className="release-row">
      <button type="button" className="secondary" disabled={busy} onClick={() => void moderate('mute_all')}>Mute all microphones</button>
      <button type="button" className="secondary" disabled={busy} onClick={() => void moderate('lock', undefined, !locked)}>
        {locked ? 'Unlock meeting' : 'Lock meeting'}
      </button>
      <button type="button" className="secondary" disabled={busy} onClick={() => void moderate('chat', undefined, chatDisabled)}>
        {chatDisabled ? 'Enable meeting chat' : 'Disable meeting chat'}
      </button>
      <button type="button" className="secondary" disabled={busy} onClick={() => void moderate('screen', undefined, shareDisabled)}>
        {shareDisabled ? 'Enable screen sharing' : 'Disable screen sharing'}
      </button>
    </div>
  </section>
}

export function MeetingParticipantModeration({ participant, name, cohost, organizer, busy, moderate }: {
  participant: string; name: string; cohost: boolean; organizer: boolean; busy: boolean; moderate: Moderate
}) {
  return <>
    <button type="button" className="secondary" disabled={busy} aria-label={'Mute ' + name}
      onClick={() => void moderate('mute', participant)}>Mute</button>
    {organizer && <button type="button" className="secondary" disabled={busy}
      aria-label={(cohost ? 'Revoke co-host access from ' : 'Promote to co-host ') + name}
      onClick={() => void moderate('cohost', participant, !cohost)}>
      {cohost ? 'Revoke co-host access' : 'Promote to co-host'}
    </button>}
    <button type="button" className="secondary" disabled={busy} aria-label={'Remove ' + name}
      onClick={() => {
        if (window.confirm('Remove ' + name + ' from this meeting?')) void moderate('remove', participant)
      }}>Remove</button>
  </>
}
