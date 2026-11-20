'use client'

import { ControlBar, GridLayout, LiveKitRoom, ParticipantTile, RoomAudioRenderer, useTracks } from '@livekit/components-react'
import { Track } from 'livekit-client'
import '@livekit/components-styles'

function GuestStage() {
  const cameras=useTracks([{source:Track.Source.Camera,withPlaceholder:true}])
  return <div className="lk-video-conference">
    <GridLayout tracks={cameras}><ParticipantTile/></GridLayout>
    <RoomAudioRenderer/>
    <ControlBar controls={{microphone:true,camera:true,screenShare:false,chat:false,leave:true}} saveUserChoices={false}/>
  </div>
}

export default function GuestMeetingMedia({url,token,leave}:{url:string;token:string;leave:()=>void}) {
  return <div className="meeting-media" data-lk-theme="default">
    <LiveKitRoom serverUrl={url} token={token} connect audio={false} video={false} onDisconnected={leave} onError={leave}>
      <GuestStage/>
    </LiveKitRoom>
  </div>
}
