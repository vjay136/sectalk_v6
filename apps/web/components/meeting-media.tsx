'use client'

import {
  CarouselLayout, ConnectionStateToast, ControlBar, FocusLayout, FocusLayoutContainer,
  GridLayout, LiveKitRoom, ParticipantTile, RoomAudioRenderer, useConnectionState, useLocalParticipant, useRoomContext, useTracks,
} from '@livekit/components-react'
import { ConnectionError, ConnectionState, DisconnectReason, RoomEvent, Track } from 'livekit-client'
import { MoreHorizontal, Signal, VideoOff } from 'lucide-react'
import { useEffect, useState } from 'react'
import '@livekit/components-styles'
import { createCallQos } from '../lib/call-qos'
import { parseMeetingMediaIdentity } from '../lib/meeting-media-identity'
import { useMeetingNetwork } from './meeting-network'
import { deviceConstraint, type MeetingChoices } from './meeting-prejoin'
import { MeetingScreenShare } from './meeting-screen-share'
import { MeetingCaptions } from './meeting-captions'
import styles from './meeting-media.module.css'

function MeetingQosObserver({ qos }: { qos: ReturnType<typeof createCallQos> }) {
  const room = useRoomContext()
  useEffect(() => {
    let active = true
    let attempts = 0
    let timer: number | undefined
    let mosAttempts = 0
    let mosTimer: number | undefined
    qos.started()
    async function readStats() {
      // The pinned LiveKit SDK uses these transports for its own WebRTC stats snapshots.
      const transports = room.engine?.pcManager
      const reads = [transports?.publisher, transports?.subscriber].map(async transport => transport?.getStats())
      const results = await Promise.allSettled(reads)
      return results.flatMap(result => result.status === 'fulfilled' ? [result.value] : [])
    }
    async function sampleRoute() {
      if (!active || attempts >= 3) return
      attempts++
      const stats = await readStats()
      if (!active) return
      if (!qos.route(...stats) && attempts < 3) timer = window.setTimeout(() => void sampleRoute(), 400)
    }
    async function sampleAudio() {
      if (!active || mosAttempts >= 3) return
      mosAttempts++
      const stats = await readStats()
      if (active && !qos.mos(...stats) && mosAttempts < 3) mosTimer = window.setTimeout(() => void sampleAudio(), 2500)
    }
    function subscribed(track: Track) {
      if (track.source === Track.Source.Microphone && mosTimer === undefined) {
        mosTimer = window.setTimeout(() => void sampleAudio(), 2500)
      }
    }
    function connected() {
      if (attempts === 0) void sampleRoute()
    }
    room.on(RoomEvent.Connected, connected)
    room.on(RoomEvent.Reconnecting, qos.reconnecting)
    room.on(RoomEvent.SignalReconnecting, qos.reconnecting)
    room.on(RoomEvent.Reconnected, qos.connected)
    room.on(RoomEvent.TrackSubscribed, subscribed)
    if (room.state === ConnectionState.Connected) connected()
    return () => {
      active = false
      window.clearTimeout(timer)
      window.clearTimeout(mosTimer)
      room.off(RoomEvent.Connected, connected)
      room.off(RoomEvent.Reconnecting, qos.reconnecting)
      room.off(RoomEvent.SignalReconnecting, qos.reconnecting)
      room.off(RoomEvent.Reconnected, qos.connected)
      room.off(RoomEvent.TrackSubscribed, subscribed)
    }
  }, [qos, room])
  return null
}

const networkDisconnects = new Set<DisconnectReason>([DisconnectReason.JOIN_FAILURE, DisconnectReason.SIGNAL_CLOSE,
  DisconnectReason.STATE_MISMATCH, DisconnectReason.CONNECTION_TIMEOUT, DisconnectReason.MEDIA_FAILURE])

function LiveMeetingCaptions({ meeting }: { meeting: string }) {
  const { isMicrophoneEnabled, microphoneTrack } = useLocalParticipant()
  const connected = useConnectionState() === ConnectionState.Connected
  const track = microphoneTrack?.track?.mediaStreamTrack
  const microphone = connected && isMicrophoneEnabled && microphoneTrack && track
    ? { track, sid: microphoneTrack.trackSid } : undefined
  return <MeetingCaptions meeting={meeting} microphone={microphone}/>
}

function ConferenceStage({ focus, meeting, screenShareDisabled }: { focus: string | null; meeting: string; screenShareDisabled: boolean }) {
  const network = useMeetingNetwork()
  const tracks = useTracks([
    { source: Track.Source.Camera, withPlaceholder: true },
    { source: Track.Source.ScreenShare, withPlaceholder: false },
  ], { onlySubscribed: false })
  const focused = tracks.find(track => track.source === Track.Source.Camera && parseMeetingMediaIdentity(track.participant.identity)?.actor === focus)
    ?? tracks.find(track => track.source === Track.Source.ScreenShare && track.publication?.isSubscribed)

  return <div className="lk-video-conference">
    <div className="lk-video-conference-inner">
      <div className={styles.networkStatus} role="status" data-quality={network.quality}>
        <Signal size={15} aria-hidden="true"/>
        <span>Network: {network.label}
          {network.mode === 'reduced' && ' · Reduced video quality'}
          {network.mode === 'audio-only' && ' · Audio-only'}
        </span>
      </div>
      {network.mode === 'audio-only' ? <div className={styles.audioOnly}>
        <VideoOff size={24} aria-hidden="true"/>
        <strong>Video paused to keep audio clear</strong>
        <span>Video resumes automatically when the connection improves.</span>
      </div> : focused ? <div className={`lk-focus-layout-wrapper ${styles.videoStage}`} data-focused-participant={parseMeetingMediaIdentity(focused.participant.identity)?.actor}>
        <FocusLayoutContainer>
          <CarouselLayout tracks={tracks.filter(track => track !== focused)}>
            <ParticipantTile/>
          </CarouselLayout>
          <FocusLayout trackRef={focused}/>
        </FocusLayoutContainer>
      </div> : <div className={`lk-grid-layout-wrapper ${styles.videoStage}`}>
        <GridLayout tracks={tracks}><ParticipantTile/></GridLayout>
      </div>}
      <MeetingScreenShare meeting={meeting} disabled={screenShareDisabled}
        presenting={tracks.some(track => track.source === Track.Source.ScreenShare && !track.participant.isLocal)}/>
      <ControlBar controls={{ microphone: true, camera: true, screenShare: false, chat: false, leave: true }}
        saveUserChoices={false}/>
    </div>
    <RoomAudioRenderer/>
    <ConnectionStateToast/>
  </div>
}

export default function MeetingMedia({ url, token, focus, choices, meeting, screenShareDisabled, leave }: {
  url: string; token: string; focus: string | null; choices: MeetingChoices; meeting: string; screenShareDisabled: boolean; leave: () => void
}) {
  const [mediaError, setMediaError] = useState('')
  const [qos] = useState(() => createCallQos('meeting', meeting))
  const configuredRoom = {
    ...roomOptions,
    audioCaptureDefaults: { deviceId: deviceConstraint(choices.microphone) },
    videoCaptureDefaults: { deviceId: deviceConstraint(choices.camera), processor: choices.processor },
    audioOutput: choices.speaker ? { deviceId: choices.speaker } : undefined,
  }
  return <div className="meeting-media" data-lk-theme="default">
    {mediaError && <p className={styles.networkStatus} role="status">{mediaError}</p>}
    <details className="call-menu meeting-call-menu">
      <summary className="secondary" aria-label="Meeting call menu"><MoreHorizontal size={17}/> Call menu</summary>
      <div className="message-menu-panel"><button className="text-button remove-text" type="button" onClick={leave}>Disconnect from media</button></div>
    </details>
    <LiveKitRoom serverUrl={url} token={token} connect audio={choices.audio} video={choices.video}
      options={configuredRoom} onConnected={qos.connected} onDisconnected={reason => {
        if (reason !== undefined && networkDisconnects.has(reason)) qos.failed()
        leave()
      }}
      onMediaDeviceFailure={() => setMediaError('A selected media device could not start. Check your permissions and devices.')}
      onError={error => {
        if (error instanceof ConnectionError) qos.failed()
        setMediaError('Could not start meeting media. Check your devices or reconnect.')
      }}>
      <MeetingQosObserver qos={qos}/>
      <ConferenceStage focus={focus} meeting={meeting} screenShareDisabled={screenShareDisabled}/>
      <LiveMeetingCaptions meeting={meeting}/>
    </LiveKitRoom>
  </div>
}

const roomOptions = { adaptiveStream: true, dynacast: true, publishDefaults: { simulcast: true } }
