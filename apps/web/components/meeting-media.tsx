'use client'

import {
  CarouselLayout, ConnectionStateToast, ControlBar, FocusLayout, FocusLayoutContainer,
  GridLayout, LiveKitRoom, ParticipantTile, RoomAudioRenderer, useTracks,
} from '@livekit/components-react'
import { Track } from 'livekit-client'
import { MoreHorizontal } from 'lucide-react'
import '@livekit/components-styles'

function ConferenceStage({ focus }: { focus: string | null }) {
  const tracks = useTracks([
    { source: Track.Source.Camera, withPlaceholder: true },
    { source: Track.Source.ScreenShare, withPlaceholder: false },
  ], { onlySubscribed: false })
  const focused = tracks.find(track => track.source === Track.Source.Camera && track.participant.identity === focus)
    ?? tracks.find(track => track.source === Track.Source.ScreenShare && track.publication?.isSubscribed)

  return <div className="lk-video-conference">
    <div className="lk-video-conference-inner">
      {focused ? <div className="lk-focus-layout-wrapper" data-focused-participant={focused.participant.identity}>
        <FocusLayoutContainer>
          <CarouselLayout tracks={tracks.filter(track => track !== focused)}>
            <ParticipantTile/>
          </CarouselLayout>
          <FocusLayout trackRef={focused}/>
        </FocusLayoutContainer>
      </div> : <div className="lk-grid-layout-wrapper">
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
    <LiveKitRoom serverUrl={url} token={token} connect audio={false} video={false} onDisconnected={leave} onError={leave}>
      <ConferenceStage focus={focus}/>
    </LiveKitRoom>
  </div>
}
