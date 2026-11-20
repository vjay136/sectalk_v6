'use client'

import {
  CarouselLayout, ConnectionStateToast, ControlBar, FocusLayout, FocusLayoutContainer,
  GridLayout, LiveKitRoom, ParticipantTile, RoomAudioRenderer, useTracks,
} from '@livekit/components-react'
import { Track } from 'livekit-client'
import { MoreHorizontal, Signal, VideoOff } from 'lucide-react'
import { useState } from 'react'
import '@livekit/components-styles'
import { useMeetingNetwork } from './meeting-network'
import { deviceConstraint, type MeetingChoices } from './meeting-prejoin'
import { MeetingScreenShare } from './meeting-screen-share'
import styles from './meeting-media.module.css'

function ConferenceStage({ focus, meeting }: { focus: string | null; meeting: string }) {
  const network = useMeetingNetwork()
  const tracks = useTracks([
    { source: Track.Source.Camera, withPlaceholder: true },
    { source: Track.Source.ScreenShare, withPlaceholder: false },
  ], { onlySubscribed: false })
  const focused = tracks.find(track => track.source === Track.Source.Camera && track.participant.identity === focus)
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
      </div> : focused ? <div className={`lk-focus-layout-wrapper ${styles.videoStage}`} data-focused-participant={focused.participant.identity}>
        <FocusLayoutContainer>
          <CarouselLayout tracks={tracks.filter(track => track !== focused)}>
            <ParticipantTile/>
          </CarouselLayout>
          <FocusLayout trackRef={focused}/>
        </FocusLayoutContainer>
      </div> : <div className={`lk-grid-layout-wrapper ${styles.videoStage}`}>
        <GridLayout tracks={tracks}><ParticipantTile/></GridLayout>
      </div>}
      <MeetingScreenShare meeting={meeting} presenting={tracks.some(track => track.source === Track.Source.ScreenShare && !track.participant.isLocal)}/>
      <ControlBar controls={{ microphone: true, camera: true, screenShare: false, chat: false, leave: true }}
        saveUserChoices={false}/>
    </div>
    <RoomAudioRenderer/>
    <ConnectionStateToast/>
  </div>
}

export default function MeetingMedia({ url, token, focus, choices, meeting, leave }: {
  url: string; token: string; focus: string | null; choices: MeetingChoices; meeting: string; leave: () => void
}) {
  const [mediaError, setMediaError] = useState('')
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
      options={configuredRoom} onDisconnected={leave}
      onMediaDeviceFailure={() => setMediaError('A selected media device could not start. Check your permissions and devices.')}
      onError={() => setMediaError('Could not start meeting media. Check your devices or reconnect.')}>
      <ConferenceStage focus={focus} meeting={meeting}/>
    </LiveKitRoom>
  </div>
}

const roomOptions = { adaptiveStream: true, dynacast: true, publishDefaults: { simulcast: true } }
