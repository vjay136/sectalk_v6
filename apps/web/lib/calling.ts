'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { db, formatError, type Call } from './data'

type Signal = {
  id: string; sender: string; kind: 'offer' | 'answer' | 'ice'; payload: RTCSessionDescriptionInit | RTCIceCandidateInit
}

async function callConfiguration(): Promise<RTCConfiguration> {
  const { data } = await db!.auth.getSession()
  const response = await fetch('/api/ice', { headers: { Authorization: 'Bearer ' + data.session?.access_token } })
  if (!response.ok) throw new Error('Unable to initialize call networking.')
  return response.json()
}

async function media(video: boolean) {
  if (!navigator.mediaDevices?.getUserMedia || typeof RTCPeerConnection === 'undefined') {
    throw new Error('Calls require a supported browser and a secure connection.')
  }
  return navigator.mediaDevices.getUserMedia({ audio: true, video })
}

export function useCalling(user: string, notice: (message: string) => void) {
  const [call, setCall] = useState<Call | null>(null)
  const [local, setLocal] = useState<MediaStream | null>(null)
  const [remote, setRemote] = useState<MediaStream | null>(null)
  const [connection, setConnection] = useState('connecting')
  const [busy, setBusy] = useState(false)
  const stream = useRef<MediaStream | null>(null)
  const current = useRef<Call | null>(null)
  const owned = useRef<string | null>(null)
  const stopped = useRef(new Set<string>())
  const lastRead = useRef(0)
  const started = useRef(false)
  const mounted = useRef(true)

  const cleanupMedia = useCallback(() => {
    stream.current?.getTracks().forEach(track => track.stop())
    stream.current = null
    setLocal(null)
    setRemote(null)
    setConnection('connecting')
  }, [])

  const refresh = useCallback(async () => {
    const read = ++lastRead.current
    const { data, error } = await db!.from('st_calls').select('*')
      .or('caller.eq.' + user + ',callee.eq.' + user)
      .in('status', ['ringing', 'active']).gt('expires_at', new Date().toISOString())
      .order('created_at', { ascending: false }).limit(1)
    if (error || lastRead.current !== read || !mounted.current) return
    const next = (data?.[0] ?? null) as Call | null
    const visible = next && !stopped.current.has(next.id) &&
      (owned.current === next.id || (next.callee === user && next.status === 'ringing')) ? next : null
    if (!visible && owned.current) {
      owned.current = null
      cleanupMedia()
    }
    current.current = visible
    setCall(visible)
  }, [user, cleanupMedia])

  const end = useCallback(async () => {
    const active = current.current
    if (!active) return
    stopped.current.add(active.id)
    owned.current = null
    current.current = null
    setCall(null)
    cleanupMedia()
    const { error } = await db!.rpc('st_call_status', { p_call: active.id, p_accept: false })
    if (error) notice('The call closed here. The other participant may need to hang up.')
  }, [cleanupMedia, notice])

  useEffect(() => {
    mounted.current = true
    const channel = db!.channel('call-inbox:' + user)
      .on('postgres_changes', { event: '*', schema: 'public', table: 'st_calls', filter: 'caller=eq.' + user }, refresh)
      .on('postgres_changes', { event: '*', schema: 'public', table: 'st_calls', filter: 'callee=eq.' + user }, refresh)
      .subscribe(status => { if (status === 'SUBSCRIBED') void refresh() })
    void refresh()
    const timer = window.setInterval(refresh, 2500)
    return () => {
      mounted.current = false
      window.clearInterval(timer)
      void db!.removeChannel(channel)
      stream.current?.getTracks().forEach(track => track.stop())
      const id = owned.current
      if (id) void db!.rpc('st_call_status', { p_call: id, p_accept: false })
    }
  }, [user, refresh])

  async function start(chatId: string, video: boolean) {
    if (started.current || current.current) return
    started.current = true
    setBusy(true)
    try {
      const source = await media(video)
      if (!mounted.current) { source.getTracks().forEach(track => track.stop()); return }
      stream.current = source
      const { data, error } = await db!.rpc('st_place_call', { p_chat: chatId, p_video: video })
      if (error) throw error
      if (!mounted.current) {
        await db!.rpc('st_call_status', { p_call: data, p_accept: false })
        return
      }
      owned.current = data
      setLocal(source)
      await refresh()
    } catch (error) {
      cleanupMedia()
      notice(formatError(error, 'The call could not start.'))
    } finally {
      started.current = false
      setBusy(false)
    }
  }

  async function answer() {
    const incoming = current.current
    if (!incoming || started.current) return
    started.current = true
    setBusy(true)
    try {
      const source = await media(incoming.video)
      if (!mounted.current || current.current?.id !== incoming.id) {
        source.getTracks().forEach(track => track.stop())
        return
      }
      stream.current = source
      owned.current = incoming.id
      const { error } = await db!.rpc('st_call_status', { p_call: incoming.id, p_accept: true })
      if (error) throw error
      if (!mounted.current || stopped.current.has(incoming.id)) {
        await db!.rpc('st_call_status', { p_call: incoming.id, p_accept: false })
        return
      }
      setLocal(source)
      await refresh()
    } catch (error) {
      owned.current = null
      cleanupMedia()
      notice(formatError(error, 'The call could not be answered.'))
    } finally {
      started.current = false
      setBusy(false)
    }
  }

  const activeId = call?.status === 'active' ? call.id : null
  const isCaller = call?.caller === user
  useEffect(() => {
    if (!activeId || !local) return
    let disposed = false
    let pc: RTCPeerConnection | undefined
    let retry: number | undefined
    let timeout: number | undefined
    let polling: number | undefined
    let removeChannel: (() => void) | undefined
    let processing = false
    const seen = new Set<string>()
    const pending: RTCIceCandidateInit[] = []

    function fail(message: string) {
      if (disposed) return
      notice(message)
      void end()
    }

    async function transmit(kind: Signal['kind'], payload: Signal['payload']) {
      if (disposed) return
      const { error } = await db!.rpc('st_signal', { p_call: activeId, p_kind: kind, p_payload: payload })
      if (error && !disposed) throw error
    }

    async function offer(peer: RTCPeerConnection, restart = false) {
      const description = await peer.createOffer(restart ? { iceRestart: true } : {})
      await peer.setLocalDescription(description)
      await transmit('offer', description)
    }

    async function readSignals(peer: RTCPeerConnection) {
      if (disposed || processing) return
      processing = true
      try {
        const { data, error } = await db!.from('st_signals').select('id,sender,kind,payload')
          .eq('call_id', activeId).neq('sender', user).order('created_at').order('id').limit(750)
        if (disposed || error) return
        for (const signal of (data ?? []) as Signal[]) {
          if (disposed) return
          if (seen.has(signal.id)) continue
          seen.add(signal.id)
          if (signal.kind === 'ice') {
            if (peer.remoteDescription) await peer.addIceCandidate(signal.payload as RTCIceCandidateInit).catch(() => undefined)
            else pending.push(signal.payload as RTCIceCandidateInit)
            continue
          }
          await peer.setRemoteDescription(signal.payload as RTCSessionDescriptionInit)
          for (const candidate of pending.splice(0)) await peer.addIceCandidate(candidate).catch(() => undefined)
          if (signal.kind === 'offer') {
            const description = await peer.createAnswer()
            await peer.setLocalDescription(description)
            await transmit('answer', description)
          }
        }
      } catch {
        fail('The call connection could not be negotiated.')
      } finally {
        processing = false
      }
    }

    async function negotiate() {
      try {
        const config = await callConfiguration()
        if (disposed) return
        const peer = new RTCPeerConnection(config)
        pc = peer
        local!.getTracks().forEach(track => peer.addTrack(track, local!))
        peer.ontrack = event => { if (!disposed && event.streams[0]) setRemote(event.streams[0]) }
        peer.onicecandidate = event => {
          if (event.candidate) void transmit('ice', event.candidate.toJSON()).catch(() => undefined)
        }
        peer.onconnectionstatechange = () => {
          if (disposed) return
          window.clearTimeout(retry)
          setConnection(peer.connectionState)
          if (peer.connectionState === 'connected') window.clearTimeout(timeout)
          if (peer.connectionState === 'failed' || peer.connectionState === 'disconnected') {
            retry = window.setTimeout(() => {
              if (disposed || peer.connectionState === 'connected') return
              if (isCaller && peer.signalingState === 'stable') {
                void offer(peer, true).catch(() => fail('The call disconnected.'))
              }
              window.clearTimeout(timeout)
              timeout = window.setTimeout(() => fail('The call disconnected.'), 18000)
            }, 2500)
          }
        }
        const channel = db!.channel('signals:' + activeId)
          .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'st_signals', filter: 'call_id=eq.' + activeId },
            () => void readSignals(peer))
          .subscribe(status => { if (status === 'SUBSCRIBED') void readSignals(peer) })
        removeChannel = () => { void db!.removeChannel(channel) }
        polling = window.setInterval(() => void readSignals(peer), 1200)
        timeout = window.setTimeout(() => fail('Connection timed out. Try again or switch networks.'), 30000)
        if (isCaller) await offer(peer)
        else await readSignals(peer)
      } catch {
        fail('Unable to establish an audio or video connection.')
      }
    }
    void negotiate()
    return () => {
      disposed = true
      window.clearTimeout(retry)
      window.clearTimeout(timeout)
      window.clearInterval(polling)
      removeChannel?.()
      pc?.close()
    }
  }, [activeId, isCaller, local, user, end, notice])

  return { call, local, remote, connection, busy, start, answer, end }
}
