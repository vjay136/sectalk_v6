'use client'

import { useRoomContext } from '@livekit/components-react'
import { ConnectionState, RoomEvent, Track, type LocalTrackPublication, type Participant } from 'livekit-client'
import { MonitorUp } from 'lucide-react'
import { useCallback, useEffect, useRef, useState } from 'react'
import { db } from '../lib/data'
import styles from './meeting-media.module.css'

type ScreenSession = {
  id: string
  tracks: MediaStreamTrack[]
  claim?: Promise<void>
  renewal?: number
  ended?: () => void
  publishing: boolean
}

async function updateShare(meeting: string, leaseId: string, action: 'claim' | 'renew' | 'release') {
  const { data } = await db!.auth.getSession()
  const response = await fetch('/api/meetings/screen-share', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + data.session?.access_token },
    body: JSON.stringify({ meetingId: meeting, leaseId, action }),
    keepalive: action === 'release',
    signal: AbortSignal.timeout(18_000),
  })
  if (response.ok) return
  const body = await response.json().catch(() => null)
  throw new Error(body?.error || 'Screen sharing is unavailable.')
}

export function MeetingScreenShare({ meeting, presenting, disabled }: { meeting: string; presenting: boolean; disabled: boolean }) {
  const room = useRoomContext()
  const participant = room.localParticipant
  const [audio, setAudio] = useState(false)
  const [phase, setPhase] = useState<'idle' | 'starting' | 'sharing' | 'stopping'>('idle')
  const [notice, setNotice] = useState('')
  const [connected, setConnected] = useState(room.state === ConnectionState.Connected)
  const active = useRef<ScreenSession | null>(null)
  const mounted = useRef(false)
  const supported = Boolean(navigator.mediaDevices?.getDisplayMedia)

  const stop = useCallback(async (reason: string) => {
    const session = active.current
    if (!session) return
    active.current = null
    window.clearInterval(session.renewal)
    for (const track of session.tracks) {
      if (session.ended) track.removeEventListener('ended', session.ended)
      track.stop()
    }
    if (mounted.current) {
      setPhase('stopping')
      setNotice(reason)
    }
    await Promise.allSettled(session.tracks.map(track => participant.unpublishTrack(track, true)))
    if (session.claim) {
      await session.claim.catch(() => {})
      await updateShare(meeting, session.id, 'release').catch(() => {})
    }
    if (mounted.current) setPhase('idle')
  }, [meeting, participant])

  useEffect(() => {
    mounted.current = true
    function stateChanged(state: ConnectionState) {
      setConnected(state === ConnectionState.Connected)
      if (state === ConnectionState.Disconnected) void stop('Screen sharing stopped when you disconnected.')
    }
    function permissionsChanged(_previous: unknown, changed: Participant) {
      const permission = participant.permissions
      if (changed === participant && active.current?.publishing &&
        (!permission?.canPublish || !permission.canPublishSources.includes(Track.sourceToProto(Track.Source.ScreenShare)))) {
        void stop('Screen sharing permission was lost.')
      }
    }
    function unpublished(publication: LocalTrackPublication) {
      if (publication.source === Track.Source.ScreenShare) void stop('Screen sharing ended.')
      if (publication.source === Track.Source.ScreenShareAudio && active.current?.publishing) {
        setNotice('Shared audio ended. The screen is still being shared.')
      }
    }
    room.on(RoomEvent.ConnectionStateChanged, stateChanged)
    room.on(RoomEvent.ParticipantPermissionsChanged, permissionsChanged)
    room.on(RoomEvent.LocalTrackUnpublished, unpublished)
    stateChanged(room.state)
    return () => {
      mounted.current = false
      room.off(RoomEvent.ConnectionStateChanged, stateChanged)
      room.off(RoomEvent.ParticipantPermissionsChanged, permissionsChanged)
      room.off(RoomEvent.LocalTrackUnpublished, unpublished)
      void stop('')
    }
  }, [room, participant, stop])

  useEffect(() => {
    if (disabled) void stop('Screen sharing stopped by a moderator.')
    else setNotice(previous => previous === 'Screen sharing stopped by a moderator.' ? '' : previous)
  }, [disabled, stop])

  async function share() {
    if (active.current || disabled || !supported || presenting || !connected) return
    const session: ScreenSession = { id: crypto.randomUUID(), tracks: [], publishing: false }
    active.current = session
    setPhase('starting')
    setNotice('')
    try {
      const stream = await navigator.mediaDevices.getDisplayMedia({ video: true, audio })
      session.tracks = stream.getTracks()
      if (active.current !== session) {
        session.tracks.forEach(track => track.stop())
        return
      }
      const [video] = stream.getVideoTracks()
      if (!video || video.readyState === 'ended') throw new Error('The screen capture has ended.')
      session.ended = () => { void stop('Screen sharing ended.') }
      video.addEventListener('ended', session.ended, { once: true })
      session.claim = updateShare(meeting, session.id, 'claim')
      await session.claim
      if (active.current !== session) return

      // The room can receive its permission update shortly after the HTTP acknowledgement.
      for (let attempt = 0; attempt < 40; attempt++) {
        if (active.current !== session) return
        if (participant.permissions?.canPublishSources.includes(Track.sourceToProto(Track.Source.ScreenShare))) break
        await new Promise<void>(resolve => window.setTimeout(resolve, 100))
      }
      if (active.current !== session) return
      session.publishing = true
      const [sound] = stream.getAudioTracks()
      await participant.publishTrack(video, { source: Track.Source.ScreenShare })
      if (active.current !== session) return
      if (audio && sound?.readyState === 'live') {
        try {
          await participant.publishTrack(sound, { source: Track.Source.ScreenShareAudio })
        } catch {
          sound.stop()
          if (active.current === session) setNotice('Shared audio could not start.')
        }
      } else {
        sound?.stop()
        if (audio) setNotice('This capture source did not provide audio.')
      }
      if (active.current !== session) return
      setPhase('sharing')
      session.renewal = window.setInterval(() => {
        void updateShare(meeting, session.id, 'renew').catch(() => {
          if (active.current === session) void stop('Screen sharing permission could not be renewed.')
        })
      }, 20_000)
    } catch (error) {
      if (active.current !== session) return
      const message = error instanceof DOMException && ['NotAllowedError', 'AbortError'].includes(error.name)
        ? 'Screen sharing was cancelled or blocked.'
        : error instanceof Error ? error.message : 'Could not start screen sharing.'
      await stop(message)
    }
  }

  return <div className={styles.screenShare}>
    <button className="secondary" type="button" disabled={disabled || phase === 'starting' || phase === 'stopping' ||
      (phase === 'idle' && (!supported || !connected || presenting))}
      onClick={() => phase === 'sharing' ? void stop('Screen sharing stopped.') : void share()}>
      <MonitorUp size={16} aria-hidden="true"/>
      {phase === 'sharing' ? 'Stop sharing screen' : phase === 'starting' ? 'Starting screen share…' : 'Share screen'}
    </button>
    {phase === 'idle' && supported && !presenting && !disabled && <label><input type="checkbox" checked={audio}
      onChange={event => setAudio(event.target.checked)}/> Share audio when available</label>}
    {phase === 'idle' && supported && !presenting && !disabled && <span>Choose a tab, window, or screen.</span>}
    <span role="status">{disabled ? 'Screen sharing is disabled for this meeting.' : presenting ? 'Someone is already presenting.'
      : notice || (!supported ? 'Screen sharing is unavailable in this browser.' : '')}</span>
  </div>
}
