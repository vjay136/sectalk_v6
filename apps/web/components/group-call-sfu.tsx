'use client'

import { LocalVideoTrack, Room, RoomEvent, Track } from 'livekit-client'
import { useEffect, useRef, useState, type RefObject } from 'react'
import { groupConfig, type GroupTracks } from '../lib/group-call'

export function GroupAudio({stream,muted,label}:{stream:MediaStream;muted?:boolean;label:string}) {
  const audio=useRef<HTMLAudioElement|null>(null)
  const [needsPlay,setNeedsPlay]=useState(false)
  useEffect(()=>{
    const element=audio.current
    if (!element) return
    element.srcObject=stream
    return ()=>{element.srcObject=null}
  },[stream])
  useEffect(()=>{
    const element=audio.current
    if (!element) return
    let active=true
    void element.play().catch(()=>{
      if (active && !muted) setNeedsPlay(true)
    })
    return ()=>{active=false}
  },[stream,muted])
  return <>
    <audio ref={audio} aria-label={label} autoPlay muted={muted} onPlaying={()=>setNeedsPlay(false)}/>
    {!muted&&needsPlay&&<button type="button" className="secondary" aria-label={'Play '+label.toLowerCase()}
      onClick={()=>void audio.current?.play().then(()=>setNeedsPlay(false)).catch(()=>{})}>Play group audio</button>}
  </>
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

export default function GroupCallSfu({call,device,generation,source,enabled,muted,cameraOn,ready,name,promotionFailed,cameraTrack,cameraPublisher}:{call:string;device:string;generation:number;
  source:MediaStream;enabled:boolean;muted:boolean;cameraOn:boolean;ready:(generation:number)=>void;name:(id:string)=>string;
  promotionFailed:(generation:number)=>void;
  cameraTrack:RefObject<MediaStreamTrack|null>;cameraPublisher:RefObject<((track:MediaStreamTrack)=>Promise<void>)|null>}) {
  const [remote,setRemote]=useState<Record<string,GroupTracks>>({})
  const [error,setError]=useState(false)
  const [tracks,setTracks]=useState<MediaStreamTrack[]>([])
  const muteState=useRef(muted)
  const cameraState=useRef(cameraOn)
  const playbackEnabled=useRef(enabled)
  muteState.current=muted
  cameraState.current=cameraOn
  playbackEnabled.current=enabled
  useEffect(()=>{
    const controller=new AbortController()
    const room=new Room()
    const clones=source.getAudioTracks().map(track=>track.clone())
    if (!clones.some(track=>track.kind==='audio')) return
    let publishedServiceCamera:LocalVideoTrack|undefined
    let serviceCameraInput:MediaStreamTrack|null=null
    const replaceCamera=async (track:MediaStreamTrack)=>{
      if (!publishedServiceCamera || serviceCameraInput===track || controller.signal.aborted) return
      const previous=publishedServiceCamera.mediaStreamTrack
      const next=track.clone()
      next.enabled=cameraState.current
      try {
        await publishedServiceCamera.replaceTrack(next,true)
        if (controller.signal.aborted) { next.stop();return }
        next.enabled=cameraState.current
        previous.stop()
        serviceCameraInput=track
        setTracks([...clones,next])
      } catch (error) {
        if (publishedServiceCamera.mediaStreamTrack===next) {
          serviceCameraInput=track
          previous.stop()
        } else next.stop()
        throw error
      }
    }
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
          clone.enabled=!muteState.current
          await room.localParticipant.publishTrack(clone,{source:Track.Source.Microphone})
        }
        serviceCameraInput=cameraTrack.current
        if (serviceCameraInput && !controller.signal.aborted) {
          const track=serviceCameraInput.clone()
          track.enabled=cameraState.current
          try {
            const publication=await room.localParticipant.publishTrack(track,{source:Track.Source.Camera})
            if (publication.track instanceof LocalVideoTrack) publishedServiceCamera=publication.track
            else track.stop()
          } catch (error) { track.stop();throw error }
        }
        if (!controller.signal.aborted) {
          const camera=publishedServiceCamera?.mediaStreamTrack
          setTracks(camera?[...clones,camera]:clones)
          cameraPublisher.current=replaceCamera
          if (cameraTrack.current) await replaceCamera(cameraTrack.current)
          ready(generation)
        }
      } catch {
        if (!controller.signal.aborted) {
          setError(true)
          if (!playbackEnabled.current) promotionFailed(generation)
        }
      }
    }
    void connect()
    return ()=>{
      controller.abort()
      if (cameraPublisher.current===replaceCamera) cameraPublisher.current=null
      clones.forEach(track=>track.stop())
      publishedServiceCamera?.stop()
      void room.disconnect()
    }
  },[call,device,generation,source,ready,promotionFailed,cameraTrack,cameraPublisher])
  useEffect(()=>{for(const track of tracks) track.enabled=track.kind==='audio'?!muted:cameraOn},[muted,cameraOn,tracks])
  return <div data-group-route="sfu">
    {error && <p role="status">The shared media connection is unavailable.</p>}
    {Object.entries(remote).map(([id,media])=><div key={id}>
      {media.audio && <GroupAudio stream={media.audio} label={'Group audio from '+name(id)} muted={!enabled}/>}
      {media.video && <GroupVideo stream={media.video} label={'Group camera from '+name(id)} visible={enabled}/>}
    </div>)}
  </div>
}
