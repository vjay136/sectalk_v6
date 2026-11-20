'use client'

import { useRoomContext } from '@livekit/components-react'
import {
  ConnectionQuality, ConnectionState, LocalTrackPublication, RoomEvent, Track, VideoQuality,
  type LocalTrack, type Participant, type RemoteTrackPublication, type TrackPublication,
} from 'livekit-client'
import { useEffect, useState } from 'react'

const poorConnectionDelay = 4_000
const videoRecoveryDelay = 8_000
type VideoMode = 'normal' | 'reduced' | 'audio-only'

const qualityLabels: Record<ConnectionQuality, string> = {
  [ConnectionQuality.Excellent]: 'Excellent',
  [ConnectionQuality.Good]: 'Good',
  [ConnectionQuality.Poor]: 'Poor',
  [ConnectionQuality.Lost]: 'Connection lost',
  [ConnectionQuality.Unknown]: 'Measuring',
}

export function useMeetingNetwork() {
  const room = useRoomContext()
  const [state, setState] = useState(room.state)
  const [quality, setQuality] = useState(room.localParticipant.connectionQuality)
  const [mode, setMode] = useState<VideoMode>('normal')

  useEffect(() => {
    function onQualityChanged(next: ConnectionQuality, participant: Participant) {
      if (participant === room.localParticipant) setQuality(next)
    }
    function onStateChanged(next: ConnectionState) {
      setState(next)
      setQuality(next === ConnectionState.Connected ? room.localParticipant.connectionQuality : ConnectionQuality.Unknown)
    }
    room.on(RoomEvent.ConnectionQualityChanged, onQualityChanged)
    room.on(RoomEvent.ConnectionStateChanged, onStateChanged)
    onStateChanged(room.state)
    return () => {
      room.off(RoomEvent.ConnectionQualityChanged, onQualityChanged)
      room.off(RoomEvent.ConnectionStateChanged, onStateChanged)
    }
  }, [room])

  const unavailable = quality === ConnectionQuality.Lost || state === ConnectionState.Reconnecting
  const poor = quality === ConnectionQuality.Poor
  const healthy = quality === ConnectionQuality.Good || quality === ConnectionQuality.Excellent

  useEffect(() => {
    if (unavailable) {
      setMode('audio-only')
      return
    }
    if (state !== ConnectionState.Connected) return

    if (poor && mode !== 'audio-only') {
      if (mode === 'normal') {
        setMode('reduced')
        return
      }
      const timer = window.setTimeout(() => setMode('audio-only'), poorConnectionDelay)
      return () => window.clearTimeout(timer)
    }
    if (healthy && mode !== 'normal') {
      const timer = window.setTimeout(() => setMode('normal'), videoRecoveryDelay)
      return () => window.clearTimeout(timer)
    }
  }, [unavailable, poor, healthy, state, mode])

  const [pausedLocalVideo] = useState(() => new WeakSet<LocalTrack>())
  const [pausedRemoteVideo] = useState(() => new WeakSet<RemoteTrackPublication>())

  useEffect(() => {
    if (state !== ConnectionState.Connected) return

    function updateLocalVideo(publication: LocalTrackPublication) {
      const track = publication.track
      if (publication.kind !== Track.Kind.Video || !track) return
      if (mode === 'audio-only') {
        if (publication.isUpstreamPaused) return
        pausedLocalVideo.add(track)
        void publication.pauseUpstream().catch(() => {
          if (!track.isUpstreamPaused) pausedLocalVideo.delete(track)
        })
      } else if (pausedLocalVideo.delete(track)) {
        void publication.resumeUpstream().catch(() => pausedLocalVideo.add(track))
      }
    }

    function updateRemoteVideo(publication: RemoteTrackPublication) {
      if (publication.kind !== Track.Kind.Video) return
      if (mode === 'audio-only') {
        if (!publication.isDesired) return
        pausedRemoteVideo.add(publication)
        publication.setSubscribed(false)
        return
      }
      if (pausedRemoteVideo.delete(publication)) publication.setSubscribed(true)
      if (publication.isSubscribed) {
        publication.setVideoQuality(mode === 'reduced' ? VideoQuality.LOW : VideoQuality.HIGH)
      }
    }

    function onTrackSubscribed(_track: Track, publication: RemoteTrackPublication) {
      updateRemoteVideo(publication)
    }
    function onTrackUnmuted(publication: TrackPublication) {
      if (publication instanceof LocalTrackPublication) updateLocalVideo(publication)
    }

    room.on(RoomEvent.LocalTrackPublished, updateLocalVideo)
    room.on(RoomEvent.TrackPublished, updateRemoteVideo)
    room.on(RoomEvent.TrackSubscribed, onTrackSubscribed)
    room.on(RoomEvent.TrackUnmuted, onTrackUnmuted)
    room.localParticipant.videoTrackPublications.forEach(updateLocalVideo)
    for (const participant of room.remoteParticipants.values()) {
      participant.videoTrackPublications.forEach(updateRemoteVideo)
    }

    return () => {
      room.off(RoomEvent.LocalTrackPublished, updateLocalVideo)
      room.off(RoomEvent.TrackPublished, updateRemoteVideo)
      room.off(RoomEvent.TrackSubscribed, onTrackSubscribed)
      room.off(RoomEvent.TrackUnmuted, onTrackUnmuted)
    }
  }, [room, state, mode, pausedLocalVideo, pausedRemoteVideo])

  const label = state === ConnectionState.Reconnecting || state === ConnectionState.SignalReconnecting
    ? 'Reconnecting'
    : state === ConnectionState.Connected ? qualityLabels[quality] : 'Connecting'

  return { label, mode, quality }
}
