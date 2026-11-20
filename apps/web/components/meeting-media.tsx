'use client'

import { LiveKitRoom, VideoConference } from '@livekit/components-react'
import '@livekit/components-styles'

export default function MeetingMedia({ url, token, leave }: { url: string; token: string; leave: () => void }) {
  return <div className="meeting-media" data-lk-theme="default">
    <LiveKitRoom serverUrl={url} token={token} connect audio={false} video={false} onDisconnected={leave} onError={leave}>
      <VideoConference />
    </LiveKitRoom>
  </div>
}
