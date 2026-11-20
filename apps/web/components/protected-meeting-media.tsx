'use client'

import { ControlBar, GridLayout, LiveKitRoom, ParticipantTile, RoomAudioRenderer, useTracks } from '@livekit/components-react'
import { ExternalE2EEKeyProvider, Room, RoomEvent, Track, isE2EESupported, type RemoteTrackPublication } from 'livekit-client'
import { useEffect, useState } from 'react'
import '@livekit/components-styles'

function Stage() {
  const tracks=useTracks([{source:Track.Source.Camera,withPlaceholder:true}])
  return <div className="lk-video-conference">
    <GridLayout tracks={tracks}><ParticipantTile/></GridLayout>
    <RoomAudioRenderer/>
    <ControlBar controls={{microphone:true,camera:true,screenShare:false,chat:false,leave:true}} saveUserChoices={false}/>
  </div>
}

export default function ProtectedMeetingMedia({access,keyBytes,roster,close}:{access:{url:string;token:string};
  keyBytes:ArrayBuffer;roster:string[];close:()=>void}) {
  const [room,setRoom]=useState<Room|null>(null)
  const [connected,setConnected]=useState(false)
  useEffect(()=>{
    if (!isE2EESupported()) { close(); return }
    let active=true
    let instance:Room|undefined
    const worker=new Worker(new URL('livekit-client/e2ee-worker',import.meta.url),{type:'module'})
    async function initialize() {
      const provider=new ExternalE2EEKeyProvider()
      instance=new Room({encryption:{keyProvider:provider,worker},publishDefaults:{simulcast:false,videoCodec:'vp8'}})
      const current=instance
      function check(publication:RemoteTrackPublication,identity:string) {
        if (!publication.isEncrypted || !roster.includes(identity)) {
          close()
          return
        }
        publication.setSubscribed(true)
      }
      current.on(RoomEvent.TrackPublished,(publication,participant)=>check(publication,participant.identity))
      current.on(RoomEvent.ParticipantConnected,participant=>{if (!roster.includes(participant.identity)) close()})
      current.on(RoomEvent.EncryptionError,close)
      current.on(RoomEvent.Connected,()=>{
        for (const participant of current.remoteParticipants.values()) {
          if (!roster.includes(participant.identity)) { close(); return }
          for (const publication of participant.trackPublications.values()) check(publication,participant.identity)
        }
        setConnected(true)
      })
      await provider.setKey(keyBytes)
      await current.setE2EEEnabled(true)
      if (active) setRoom(current)
    }
    void initialize().catch(()=>{if(active) close()})
    return ()=>{
      active=false
      void instance?.disconnect().finally(()=>worker.terminate())
      if (!instance) worker.terminate()
    }
  },[close,keyBytes,roster])
  if (!room) return <p role="status">Starting encrypted meeting media…</p>
  return <div className="meeting-media" data-lk-theme="default">
    <p role="status">{connected?'Protected meeting media connected':'Connecting encrypted meeting media…'}</p>
    <LiveKitRoom room={room} serverUrl={access.url} token={access.token} connect audio={false} video={false}
      connectOptions={{autoSubscribe:false}} onDisconnected={close} onError={close}>
      <Stage/>
    </LiveKitRoom>
  </div>
}
