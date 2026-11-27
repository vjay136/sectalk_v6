'use client'

import { useEffect, useRef, useState, type RefObject } from 'react'
import { groupConfig, type GroupCommand, type GroupSignal, type GroupTracks } from './group-call'

type Peer={connection:RTCPeerConnection;pending:RTCIceCandidateInit[]}

export function useGroupMesh(call:string|null,user:string,device:string,roster:string[],stream:MediaStream|null,video:boolean,command:GroupCommand,
  cameraTrack:RefObject<MediaStreamTrack|null>) {
  const targets=useRef(roster)
  targets.current=roster
  const [remote,setRemote]=useState<Record<string,GroupTracks>>({})
  const [error,setError]=useState(false)
  const [connected,setConnected]=useState(0)
  const cameraSenders=useRef(new Set<RTCRtpSender>())
  useEffect(()=>{
    if (!call || !stream) return
    const id=call
    const source=stream
    const controller=new AbortController()
    const peers=new Map<string,Peer>()
    const senders=cameraSenders.current
    let config:RTCConfiguration|undefined
    let refreshAt=Infinity
    let setupRetryDelay=2000
    let cursor=0
    let timer:number|undefined
    async function send(peer:string,kind:GroupSignal['kind'],payload:GroupSignal['payload']) {
      await command('send',id,{p_peer:peer,p_kind:kind,p_payload:payload})
    }
    async function relayConfiguration() {
      if (config && performance.now()<refreshAt) return
      try {
        const {iceServers,iceTransportPolicy,ttlSeconds}=await groupConfig('ice',id,device,controller.signal)
        if (controller.signal.aborted) return
        config={iceServers,iceTransportPolicy}
        for (const peer of peers.values()) peer.connection.setConfiguration(config)
        refreshAt=typeof ttlSeconds==='number' && ttlSeconds>60
          ? performance.now()+(ttlSeconds-60)*1000 : Infinity
      } catch (error) {
        if (!config) {
          refreshAt=performance.now()+setupRetryDelay
          setupRetryDelay=Math.min(setupRetryDelay*2,15_000)
          throw error
        }
        refreshAt=performance.now()+15_000
      }
    }
    async function attach(actor:string) {
      const connection=new RTCPeerConnection(config)
      const value={connection,pending:[]} as Peer
      peers.set(actor,value)
      for (const track of source.getAudioTracks()) connection.addTrack(track,source)
      const camera=cameraTrack.current
      if (video && camera) senders.add(connection.addTrack(camera,source))
      else if (video && user<actor) connection.addTransceiver('video',{direction:'recvonly'})
      connection.onicecandidate=event=>{
        if (event.candidate && !controller.signal.aborted) void send(actor,'ice',event.candidate.toJSON()).catch(()=>{})
      }
      connection.ontrack=event=>{
        const kind=event.track.kind
        if (!controller.signal.aborted && (kind==='audio' || (video && kind==='video'))) {
          setRemote(previous=>({...previous,[actor]:{...previous[actor],[kind]:new MediaStream([event.track])}}))
        }
      }
      connection.onconnectionstatechange=()=>{
        if (!controller.signal.aborted) setConnected([...peers.values()].filter(peer=>peer.connection.connectionState==='connected').length)
      }
      if (user<actor) {
        await connection.setLocalDescription(await connection.createOffer())
        if (connection.localDescription) await send(actor,'offer',connection.localDescription.toJSON())
      }
    }
    async function update() {
      if (controller.signal.aborted) return
      try {
        await relayConfiguration()
        if (controller.signal.aborted) return
        const wanted=targets.current.filter(actor=>actor!==user).slice(0,3)
        for (const [actor,peer] of peers) {
          if (!wanted.includes(actor)) {
            for (const sender of peer.connection.getSenders()) senders.delete(sender)
            peer.connection.close()
            peers.delete(actor)
            setRemote(previous=>Object.fromEntries(Object.entries(previous).filter(([key])=>key!==actor)))
          }
        }
        for (const actor of wanted) {
          if (!peers.has(actor)) await attach(actor)
        }
        const rows=await command('signals',id,{p_after:cursor}) as GroupSignal[]|null
        if (controller.signal.aborted) return
        for (const row of rows ?? []) {
          const peer=peers.get(row.sender)
          if (!peer) break
          cursor=row.id
          if (row.kind==='ice') {
            const candidate=row.payload as RTCIceCandidateInit
            if (peer.connection.remoteDescription) await peer.connection.addIceCandidate(candidate).catch(()=>{})
            else if (peer.pending.length<120) peer.pending.push(candidate)
            continue
          }
          await peer.connection.setRemoteDescription(row.payload as RTCSessionDescriptionInit)
          for (const candidate of peer.pending.splice(0)) await peer.connection.addIceCandidate(candidate).catch(()=>{})
          if (row.kind==='offer') {
            await peer.connection.setLocalDescription(await peer.connection.createAnswer())
            if (peer.connection.localDescription) await send(row.sender,'answer',peer.connection.localDescription.toJSON())
          }
        }
        setError(false)
      } catch { if (!controller.signal.aborted) setError(true) }
      if (!controller.signal.aborted) {
        const nextPoll=config?500:Math.max(500,refreshAt-performance.now())
        timer=window.setTimeout(()=>void update(),nextPoll)
      }
    }
    void update()
    return ()=>{
      controller.abort()
      window.clearTimeout(timer)
      for (const peer of peers.values()) peer.connection.close()
      senders.clear()
      setRemote({})
      setError(false)
      setConnected(0)
    }
  },[call,user,device,stream,video,command,cameraTrack])
  async function replaceCamera(track:MediaStreamTrack) {
    const results=await Promise.allSettled([...cameraSenders.current].map(sender=>sender.replaceTrack(track)))
    if (results.some(result=>result.status==='rejected')) throw new Error('Could not change group camera')
  }
  return {remote,error,connected,replaceCamera}
}
