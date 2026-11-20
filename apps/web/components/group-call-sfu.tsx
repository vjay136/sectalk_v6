'use client'

import { Room, RoomEvent, Track } from 'livekit-client'
import { useEffect, useRef, useState } from 'react'
import { groupConfig, type GroupTracks } from '../lib/group-call'

export function GroupAudio({stream,muted,label}:{stream:MediaStream;muted?:boolean;label:string}) {
  const audio=useRef<HTMLAudioElement|null>(null)
  useEffect(()=>{
    const element=audio.current
    if (!element) return
    element.srcObject=stream
    void element.play().catch(()=>{})
    return ()=>{element.srcObject=null}
  },[stream])
  return <audio ref={audio} aria-label={label} autoPlay muted={muted}/>
}

export function GroupVideo({stream,visible,label}:{stream:MediaStream;visible:boolean;label:string}) {
  const video=useRef<HTMLVideoElement|null>(null)
  useEffect(()=>{
    const element=video.current
    if (!element) return
    element.srcObject=stream
    void element.play().catch(()=>{})
    return ()=>{element.srcObject=null}
  },[stream])
  return <video ref={video} aria-label={label} autoPlay muted playsInline hidden={!visible}
    style={{maxWidth:'min(100%, 300px)',borderRadius:8}}/>
}

export default function GroupCallSfu({call,device,generation,source,enabled,muted,cameraOn,ready,name}:{call:string;device:string;generation:number;
  source:MediaStream;enabled:boolean;muted:boolean;cameraOn:boolean;ready:(generation:number)=>void;name:(id:string)=>string}) {
  const [remote,setRemote]=useState<Record<string,GroupTracks>>({})
  const [error,setError]=useState(false)
  const [tracks,setTracks]=useState<MediaStreamTrack[]>([])
  const muteState=useRef(muted)
  const cameraState=useRef(cameraOn)
  muteState.current=muted
  cameraState.current=cameraOn
  useEffect(()=>{
    const controller=new AbortController()
    const room=new Room()
    const clones=source.getTracks().map(track=>track.clone())
    if (!clones.some(track=>track.kind==='audio')) return
    room.on(RoomEvent.TrackSubscribed,(subscribed,_publication,participant)=>{
      if ((subscribed.kind===Track.Kind.Audio || subscribed.kind===Track.Kind.Video) && !controller.signal.aborted) {
        const kind=subscribed.kind
        setRemote(previous=>({...previous,[participant.identity]:{...previous[participant.identity],
          [kind]:new MediaStream([subscribed.mediaStreamTrack])}}))
      }
    })
    room.on(RoomEvent.TrackUnsubscribed,(track,_publication,participant)=>{
      if (!controller.signal.aborted && (track.kind===Track.Kind.Audio || track.kind===Track.Kind.Video)) {
        const kind=track.kind
        setRemote(previous=>({...previous,[participant.identity]:{...previous[participant.identity],[kind]:undefined}}))
      }
    })
    async function connect() {
      try {
        const access=await groupConfig('sfu',call,device,controller.signal)
        if (controller.signal.aborted || access.generation!==generation) return
        await room.connect(access.url,access.token)
        if (controller.signal.aborted) { await room.disconnect();return }
        for (const clone of clones) {
          clone.enabled=clone.kind==='audio' ? !muteState.current : cameraState.current
          await room.localParticipant.publishTrack(clone,{source:clone.kind==='audio'?Track.Source.Microphone:Track.Source.Camera})
        }
        if (!controller.signal.aborted) {
          setTracks(clones)
          ready(generation)
        }
      } catch { if (!controller.signal.aborted) setError(true) }
    }
    void connect()
    return ()=>{controller.abort();clones.forEach(track=>track.stop());void room.disconnect()}
  },[call,device,generation,source,ready])
  useEffect(()=>{for(const track of tracks) track.enabled=track.kind==='audio'?!muted:cameraOn},[muted,cameraOn,tracks])
  return <div data-group-route="sfu">
    {error && <p role="status">The shared media connection is unavailable.</p>}
    {Object.entries(remote).map(([id,media])=><div key={id}>
      {media.audio && <GroupAudio stream={media.audio} label={'Group audio from '+name(id)} muted={!enabled}/>}
      {media.video && <GroupVideo stream={media.video} label={'Group camera from '+name(id)} visible={enabled}/>}
    </div>)}
  </div>
}
