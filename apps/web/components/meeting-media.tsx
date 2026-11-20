'use client'

import {
  CarouselLayout, ConnectionStateToast, ControlBar, FocusLayout, FocusLayoutContainer,
  GridLayout, LiveKitRoom, ParticipantTile, RoomAudioRenderer, useTracks,
} from '@livekit/components-react'
import { Track } from 'livekit-client'
import { MoreHorizontal, Signal, VideoOff } from 'lucide-react'
import '@livekit/components-styles'
import { useMeetingNetwork } from './meeting-network'
import styles from './meeting-media.module.css'

function ConferenceStage({ focus }: { focus: string | null }) {
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
      <ControlBar controls={{ microphone: true, camera: true, screenShare: true, chat: false, leave: true }}
        saveUserChoices={false}/>
    </div>
    <RoomAudioRenderer/>
    <ConnectionStateToast/>
  </div>
}

export default function MeetingMedia({ url, token, focus, leave }: {
  url: string; token: string; focus: string | null; leave: () => void
}) {
  return <div className="meeting-media" data-lk-theme="default">
    <details className="call-menu meeting-call-menu">
      <summary className="secondary" aria-label="Meeting call menu"><MoreHorizontal size={17}/> Call menu</summary>
      <div className="message-menu-panel"><button className="text-button remove-text" type="button" onClick={leave}>Disconnect from media</button></div>
    </details>
    <LiveKitRoom serverUrl={url} token={token} connect audio={false} video={false}
      options={roomOptions} onDisconnected={leave} onError={leave}>
      <ConferenceStage focus={focus}/>
    </LiveKitRoom>
  </div>
}

const roomOptions = { adaptiveStream: true, dynacast: true, publishDefaults: { simulcast: true } }
