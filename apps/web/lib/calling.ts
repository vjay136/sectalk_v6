'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { db, formatError, liveChannel, onReconnect, type Call } from './data'

type Signal = {
  id: string; sender: string; kind: 'offer' | 'answer' | 'ice'; created_at: string
  payload: RTCSessionDescriptionInit | RTCIceCandidateInit
}

async function callConfiguration(callId: string): Promise<{ config: RTCConfiguration; ttlSeconds: number | null }> {
  const { data } = await db!.auth.getSession()
  if (!data.session) throw new Error('Sign in to connect to a call.')
  const query = new URLSearchParams({ call: callId })
  const response = await fetch('/api/ice?' + query, {
    headers: { Authorization: 'Bearer ' + data.session.access_token },
    cache: 'no-store',
  })
  if (!response.ok) throw new Error('Unable to initialize call networking.')
  const { iceServers, iceTransportPolicy, ttlSeconds } = await response.json()
  return { config: { iceServers, iceTransportPolicy }, ttlSeconds }
}

async function media(video: boolean) {
  if (!navigator.mediaDevices?.getUserMedia || typeof RTCPeerConnection === 'undefined') {
    throw new Error('Calls require a supported browser and a secure connection.')
  }
  return navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true }, video })
}

export function useCalling(user: string, notice: (message: string) => void, hints: EventTarget) {
  const [call, setCall] = useState<Call | null>(null)
  const [historyVersion, setHistoryVersion] = useState(0)
  const [local, setLocal] = useState<MediaStream | null>(null)
  const [remote, setRemote] = useState<MediaStream | null>(null)
  const [connection, setConnection] = useState('connecting')
  const [busy, setBusy] = useState(false)
  const [screen, setScreen] = useState<MediaStream | null>(null)
  const [sharingBusy, setSharingBusy] = useState(false)
  const stream = useRef<MediaStream | null>(null)
  const displayStream = useRef<MediaStream | null>(null)
  const activePeer = useRef<RTCPeerConnection | null>(null)
  const current = useRef<Call | null>(null)
  const owned = useRef<string | null>(null)
  const stopped = useRef(new Set<string>())
  const lastRead = useRef(0)
  const started = useRef(false)
  const mounted = useRef(true)

  const cleanupMedia = useCallback(() => {
    displayStream.current?.getTracks().forEach(track => track.stop())
    displayStream.current = null
    setScreen(null)
    stream.current?.getTracks().forEach(track => track.stop())
    stream.current = null
    setLocal(null)
    setRemote(null)
    setConnection('connecting')
  }, [])

  const applyCall = useCallback((next: Call | null) => {
    const visible = next && next.status !== 'ended' && Date.parse(next.expires_at) > Date.now() &&
      !stopped.current.has(next.id) &&
      (owned.current === next.id || (next.callee === user && next.status === 'ringing')) ? next : null
    if (!visible && owned.current) {
      owned.current = null
      cleanupMedia()
    }
    current.current = visible
    setCall(previous => previous?.id === visible?.id && previous?.status === visible?.status ? previous : visible)
  }, [user, cleanupMedia])

  const refresh = useCallback(async () => {
    const version = lastRead.current
    const { data, error } = await db!.from('st_calls').select('*')
      .or('caller.eq.' + user + ',callee.eq.' + user)
      .in('status', ['ringing', 'active']).gt('expires_at', new Date().toISOString())
      .order('created_at', { ascending: false }).limit(1)
    if (!error && lastRead.current === version && mounted.current) applyCall((data?.[0] ?? null) as Call | null)
  }, [user, applyCall])

  const end = useCallback(async () => {
    const active = current.current
    if (!active) return
    ++lastRead.current
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
    function change(payload: { new: Call | Record<string, never> }) {
      const next = payload.new as Call
      if (!next.id) return
      setHistoryVersion(value => value + 1)
      const expected = current.current?.id || owned.current
      if (!expected || expected === next.id) {
        if (current.current?.status === 'active' && next.status === 'ringing') return
        ++lastRead.current
        applyCall(next)
      }
    }
    const channel = liveChannel('call-inbox:' + user, refresh)
      .on<Call>('postgres_changes', { event: '*', schema: 'public', table: 'st_calls', filter: 'caller=eq.' + user }, change)
      .on<Call>('postgres_changes', { event: '*', schema: 'public', table: 'st_calls', filter: 'callee=eq.' + user }, change)
      .subscribe(status => { if (status === 'SUBSCRIBED') void refresh() })
    void refresh()
    const timer = window.setInterval(refresh, 2500)
    const removeReconnect = onReconnect(refresh)
    const onHint = () => { setHistoryVersion(value => value + 1); void refresh() }
    hints.addEventListener('call', onHint)
    hints.addEventListener('ready', onHint)
    return () => {
      mounted.current = false
      ++lastRead.current
      hints.removeEventListener('call', onHint)
      hints.removeEventListener('ready', onHint)
      removeReconnect()
      window.clearInterval(timer)
      void db!.removeChannel(channel)
      stream.current?.getTracks().forEach(track => track.stop())
      displayStream.current?.getTracks().forEach(track => track.stop())
      const id = owned.current
      if (id) void db!.rpc('st_call_status', { p_call: id, p_accept: false })
    }
  }, [user, refresh, applyCall, hints])

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
      ++lastRead.current
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
      ++lastRead.current
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
    const callId = activeId
    let disposed = false
    let pc: RTCPeerConnection | undefined
    let retry: number | undefined
    let timeout: number | undefined
    let polling: number | undefined
    let iceTimer: number | undefined
    let iceDeadline = Infinity
    let iceRenewal: Promise<void> | undefined
    let removeChannel: (() => void) | undefined
    let removeHint: (() => void) | undefined
    let processing = false
    let needsSnapshot = true
    const seen = new Set<string>()
    const arriving = new Map<string, Signal>()
    let pending: RTCIceCandidateInit[] = []
    let remoteUfrags = new Set<string>()

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

    function scheduleIceRenewal(peer: RTCPeerConnection, ttlSeconds: number | null) {
      window.clearTimeout(iceTimer)
      iceDeadline = ttlSeconds === null ? Infinity : performance.now() + ttlSeconds * 1000
      // A lease this short is bounded by the end of the call.
      if (ttlSeconds !== null && ttlSeconds > 60) {
        iceTimer = window.setTimeout(() => renewIce(peer).catch(() => retryIceRenewal(peer)), (ttlSeconds - 60) * 1000)
      }
    }

    function retryIceRenewal(peer: RTCPeerConnection) {
      if (disposed || performance.now() >= iceDeadline) return
      iceTimer = window.setTimeout(() => renewIce(peer).catch(() => retryIceRenewal(peer)), 15000)
    }

    function renewIce(peer: RTCPeerConnection) {
      if (!iceRenewal) {
        iceRenewal = callConfiguration(callId).then(({ config, ttlSeconds }) => {
          if (disposed) return
          peer.setConfiguration(config)
          scheduleIceRenewal(peer, ttlSeconds)
        }).finally(() => { iceRenewal = undefined })
      }
      return iceRenewal
    }

    async function offer(peer: RTCPeerConnection, restart = false) {
      if (restart && iceDeadline - performance.now() <= 60000) await renewIce(peer)
      if (disposed) return
      const description = await peer.createOffer(restart ? { iceRestart: true } : {})
      await peer.setLocalDescription(description)
      await transmit('offer', description)
    }

    async function readSignals(peer: RTCPeerConnection, signal?: Signal) {
      if (disposed) return
      if (signal) {
        if (signal.sender === user || seen.has(signal.id)) return
        arriving.set(signal.id, signal)
      } else {
        needsSnapshot = true
      }
      if (processing) return
      processing = true
      try {
        while (!disposed && (needsSnapshot || arriving.size)) {
          const readHistory = needsSnapshot
          needsSnapshot = false
          if (readHistory) {
            const { data } = await db!.from('st_signals').select('id,sender,kind,payload,created_at')
              .eq('call_id', activeId).neq('sender', user).order('created_at').order('id').limit(750)
            for (const row of (data ?? []) as Signal[]) {
              if (!seen.has(row.id)) arriving.set(row.id, row)
            }
          }
          const batch = [...arriving.values()].sort((a, b) => a.created_at.localeCompare(b.created_at) || a.id.localeCompare(b.id))
          arriving.clear()
          for (const row of batch) {
            if (disposed) return
            if (seen.has(row.id)) continue
            seen.add(row.id)
            if (row.kind === 'ice') {
              const candidate = row.payload as RTCIceCandidateInit
              if (peer.remoteDescription && (!candidate.usernameFragment || remoteUfrags.has(candidate.usernameFragment))) {
                await peer.addIceCandidate(candidate).catch(() => undefined)
              } else {
                pending = [...pending.slice(-149), candidate]
              }
              continue
            }
            const description = row.payload as RTCSessionDescriptionInit
            if (row.kind === 'offer' && iceDeadline - performance.now() <= 60000) await renewIce(peer)
            if (disposed) return
            await peer.setRemoteDescription(description)
            remoteUfrags = new Set([...description.sdp?.matchAll(/^a=ice-ufrag:([^\r\n]+)/gm) ?? []].map(match => match[1]))
            const remaining: RTCIceCandidateInit[] = []
            for (const candidate of pending) {
              if (!candidate.usernameFragment || remoteUfrags.has(candidate.usernameFragment)) {
                await peer.addIceCandidate(candidate).catch(() => undefined)
              } else {
                remaining.push(candidate)
              }
            }
            pending = remaining
            if (row.kind === 'offer') {
              const answer = await peer.createAnswer()
              await peer.setLocalDescription(answer)
              await transmit('answer', answer)
            }
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
        const { config, ttlSeconds } = await callConfiguration(callId)
        if (disposed) return
        const peer = new RTCPeerConnection(config)
        pc = peer
        activePeer.current = peer
        scheduleIceRenewal(peer, ttlSeconds)
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
        const channel = liveChannel('signals:' + activeId, () => void readSignals(peer))
          .on<Signal>('postgres_changes', { event: 'INSERT', schema: 'public', table: 'st_signals', filter: 'call_id=eq.' + activeId },
            payload => void readSignals(peer, payload.new))
          .subscribe(status => { if (status === 'SUBSCRIBED') void readSignals(peer) })
        removeChannel = () => { void db!.removeChannel(channel) }
        const catchUp = () => void readSignals(peer)
        const onHint = (event: Event) => { if ((event as MessageEvent).data === activeId) catchUp() }
        hints.addEventListener('signal', onHint)
        hints.addEventListener('ready', catchUp)
        removeHint = () => {
          hints.removeEventListener('signal', onHint)
          hints.removeEventListener('ready', catchUp)
        }
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
      window.clearTimeout(iceTimer)
      removeChannel?.()
      removeHint?.()
      if (activePeer.current === pc) activePeer.current = null
      pc?.close()
    }
  }, [activeId, isCaller, local, user, end, notice, hints])

  async function stopSharing() {
    const capture = displayStream.current
    if (!capture) return
    displayStream.current = null
    capture.getTracks().forEach(track => track.stop())
    setScreen(null)
    const peer = activePeer.current
    const track = capture.getVideoTracks()[0]
    const sender = peer?.getSenders().find(item => item.track === track)
    if (sender) await sender.replaceTrack(stream.current?.getVideoTracks()[0] ?? null).catch(() => {
      notice('Screen sharing stopped. Toggle your camera or reconnect if video does not resume.')
    })
  }

  async function shareScreen() {
    const peer = activePeer.current
    const camera = stream.current?.getVideoTracks()[0]
    const sender = peer?.getSenders().find(item => item.track === camera)
    if (sharingBusy || displayStream.current || !peer || peer.connectionState !== 'connected' || !camera || !sender) return
    if (!navigator.mediaDevices?.getDisplayMedia) { notice('This browser does not support screen sharing.'); return }
    setSharingBusy(true)
    let capture: MediaStream | undefined
    try {
      capture = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: false })
      const track = capture.getVideoTracks()[0]
      if (!track || activePeer.current !== peer || !current.current) { capture.getTracks().forEach(item => item.stop()); return }
      await sender.replaceTrack(track)
      if (activePeer.current !== peer || !current.current) { capture.getTracks().forEach(item => item.stop()); return }
      displayStream.current = capture
      track.addEventListener('ended', () => { void stopSharing() }, { once: true })
      setScreen(capture)
    } catch {
      capture?.getTracks().forEach(track => track.stop())
      notice('Screen sharing did not start. Check your browser permissions or try again.')
    } finally {
      setSharingBusy(false)
    }
  }

  return { call, local, remote, connection, busy, start, answer, end, historyVersion, screen, sharingBusy, shareScreen, stopSharing }
}
