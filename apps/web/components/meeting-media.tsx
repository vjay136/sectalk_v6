'use client'

import { LiveKitRoom, VideoConference } from '@livekit/components-react'
import { MoreHorizontal } from 'lucide-react'
import '@livekit/components-styles'

export default function MeetingMedia({ url, token, leave }: { url: string; token: string; leave: () => void }) {
  return <div className="meeting-media" data-lk-theme="default">
    <details className="call-menu meeting-call-menu">
      <summary className="secondary" aria-label="Meeting call menu"><MoreHorizontal size={17}/> Call menu</summary>
      <div className="message-menu-panel"><button className="text-button remove-text" type="button" onClick={leave}>Disconnect from media</button></div>
    </details>
    <LiveKitRoom serverUrl={url} token={token} connect audio={false} video={false} onDisconnected={leave} onError={leave}>
      <VideoConference />
    </LiveKitRoom>
  </div>
}
