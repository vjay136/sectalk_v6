'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { db, formatError, liveChannel, onReconnect, type Call } from './data'
import { createCallQos } from './call-qos'
import { protectedCallKeys, protectedCallSupported, protectedDescription, protectedTransports } from './protected-call'

type Signal = {
  id: string; sender: string; kind: 'offer' | 'answer' | 'ice'; created_at: string
  payload: RTCSessionDescriptionInit | RTCIceCandidateInit
}

async function callConfiguration(callId: string): Promise<{ config: RTCConfiguration; ttlSeconds: number | null }> {
  const { data } = await db!.auth.getSession()
  if (!data.session) throw new Error('Sign in to connect to a call.')
  const query = new URLSearchParams({ call: callId })
  const request = () => fetch('/api/ice?' + query, {
    headers: { Authorization: 'Bearer ' + data.session.access_token },
    cache: 'no-store',
    signal: AbortSignal.timeout(8000),
  })
  // Retry once if the server or network was temporarily unavailable. A denial
  // is authoritative and must not fall back to unscoped ICE credentials.
  let response = await request().catch(() => null)
  if (!response || response.status >= 500) response = await request().catch(() => null)
  if (!response?.ok) throw new Error('Unable to initialize call networking.')
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
  const [protection,setProtection] = useState<{code:string;verified:boolean;ready:boolean}|null>(null)
  const approveCode=useRef<(()=>void)|null>(null)
  const stream = useRef<MediaStream | null>(null)
  const displayStream = useRef<MediaStream | null>(null)
  const activePeer = useRef<RTCPeerConnection | null>(null)
  const current = useRef<Call | null>(null)
  const owned = useRef<string | null>(null)
  const answering = useRef<string | null>(null)
  const [device] = useState(() => crypto.randomUUID())
  const stopped = useRef(new Set<string>())
  const lastRead = useRef(0)
  const refreshSequence = useRef(0)
  const appliedRefresh = useRef(0)
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
    setProtection(null)
    approveCode.current?.()
    approveCode.current=null
    setConnection('connecting')
  }, [])

  const applyCall = useCallback((next: Call | null, fromRefresh = false) => {
    const previous = current.current
    if (next?.id === previous?.id && previous?.status === 'active' && next?.status === 'ringing') return
    if (next && next.status === 'active' && answering.current === next.id && owned.current !== next.id) return
    const visible = next && next.status !== 'ended' && Date.parse(next.expires_at) > Date.now() &&
      !stopped.current.has(next.id) &&
      (owned.current === next.id || (next.callee === user && next.status === 'ringing')) ? next : null
    if (fromRefresh && (previous?.id !== visible?.id || previous?.status !== visible?.status ||
      (next?.status === 'ended' && owned.current === next.id))) {
      setHistoryVersion(value => value + 1)
    }
    if (!visible && previous?.status === 'ringing' && next?.id === previous.id && !stopped.current.has(next.id)) {
      if (previous.callee === user) {
        const message = next.status === 'active' ? 'Call answered on another device.'
          : next.end_reason === 'cancelled' ? 'The caller cancelled.'
          : next.end_reason === 'busy' ? 'Call marked busy on another device.'
          : next.end_reason === 'declined' ? 'Call declined on another device.' : null
        if (message) void db!.rpc('st_v6_direct_alert_quiet', { p_chat: previous.chat_id, p_category: 'call' }).then(({ data }) => {
          if (data === false && mounted.current && !current.current) notice(message)
        })
      } else if (next.end_reason === 'busy') notice('Your contact is busy.')
      else if (next.end_reason === 'declined') notice('Your contact declined the call.')
    }
    if (!visible && owned.current) {
      owned.current = null
      cleanupMedia()
    }
    current.current = visible
    setCall(previous => previous?.id === visible?.id && previous?.status === visible?.status ? previous : visible)
  }, [user, cleanupMedia, notice])

  const refresh = useCallback(async () => {
    const sequence = ++refreshSequence.current
    const version = lastRead.current
    const trackedId = current.current?.id ?? owned.current
    const query = db!.from('st_calls').select('*')
    // A call on this tab already has an endpoint. Follow that row instead of
    // allowing a newer call on another device to replace it during polling.
    const { data, error } = await (trackedId ? query.eq('id', trackedId).maybeSingle() :
      query.eq('callee', user).eq('status', 'ringing').gt('expires_at', new Date().toISOString())
        .order('created_at', { ascending: false }).limit(1).maybeSingle())
    if (error || lastRead.current !== version || sequence <= appliedRefresh.current || !mounted.current) return
    appliedRefresh.current = sequence
    applyCall(data as Call | null, true)
  }, [user, applyCall])

  const finish = useCallback(async (reason: 'end'|'busy') => {
    const active = current.current
    if (!active) return
    const action = active.status === 'ringing' && active.callee === user
      ? reason === 'busy' ? 'busy' : 'decline'
      : 'end'
    ++lastRead.current
    stopped.current.add(active.id)
    owned.current = null
    current.current = null
    setCall(null)
    cleanupMedia()
    const { data, error } = await db!.rpc('st_v6_call_action', { p_call: active.id, p_action: action, p_device: device })
    if (error) notice('The call closed here. The other participant may need to hang up.')
    else if (mounted.current) {
      setHistoryVersion(value => value + 1)
      if (data === 'answered_elsewhere') notice('Call answered on another device.')
    }
  }, [cleanupMedia, device, notice, user])
  const end = useCallback(() => finish('end'), [finish])
  const markBusy = useCallback(() => finish('busy'), [finish])

  useEffect(() => {
    mounted.current = true
    function change(payload: { new: Call | Record<string, never> }) {
      const next = payload.new as Call
      if (!next.id) return
      setHistoryVersion(value => value + 1)
      const expected = current.current?.id || owned.current
      if (!expected || expected === next.id) {
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
      if (id) void db!.rpc('st_v6_call_action', { p_call: id, p_action: 'end', p_device: device }).then(() => undefined)
    }
  }, [user, refresh, applyCall, hints, device])

  async function start(chatId: string, video: boolean, secure=false) {
    if (started.current || current.current) return
    started.current = true
    setBusy(true)
    try {
      if (secure && !protectedCallSupported(video)) throw new Error('Protected calls require a browser with encoded media transforms.')
      const source = await media(video)
      if (!mounted.current) { source.getTracks().forEach(track => track.stop()); return }
      stream.current = source
      const { data, error } = await db!.rpc(secure?'st_v6_start_protected_call':'st_v6_start_call', { p_chat: chatId, p_video: video, p_device: device })
      if (error) throw error
      if (!mounted.current) {
        await db!.rpc('st_v6_call_action', { p_call: data, p_action: 'end', p_device: device })
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
    if (!incoming || incoming.status !== 'ringing' || incoming.callee !== user || started.current) return
    started.current = true
    setBusy(true)
    try {
      if (incoming.media_protection && (incoming.media_protection!==1 || !protectedCallSupported(incoming.video))) {
        throw new Error('This browser cannot answer the protected call.')
      }
      const source = await media(incoming.video)
      if (!mounted.current || current.current?.id !== incoming.id) {
        source.getTracks().forEach(track => track.stop())
        return
      }
      stream.current = source
      answering.current = incoming.id
      const accept = () => incoming.media_protection===1
        ? db!.rpc('st_v6_accept_protected_call',{p_call:incoming.id,p_device:device})
        : db!.rpc('st_v6_call_action', { p_call: incoming.id, p_action: 'accept', p_device: device })
      let response = await accept()
      if (response.error && (response.status === 0 || response.status >= 500) && mounted.current) response = await accept()
      const { data, error } = response
      if (error) throw error
      answering.current = null
      if (data !== 'accepted') {
        cleanupMedia()
        await refresh()
        return
      }
      if (!mounted.current || stopped.current.has(incoming.id)) {
        await db!.rpc('st_v6_call_action', { p_call: incoming.id, p_action: 'end', p_device: device })
        return
      }
      owned.current = incoming.id
      ++lastRead.current
      setLocal(source)
      await refresh()
    } catch (error) {
      owned.current = null
      cleanupMedia()
      notice(formatError(error, 'The call could not be answered.'))
    } finally {
      answering.current = null
      started.current = false
      setBusy(false)
    }
  }

  const activeId = call?.status === 'active' ? call.id : null
  const isCaller = call?.caller === user
  useEffect(() => {
    if (!activeId || !local || !call) return
    const callId = activeId
    const secure=Boolean(call.media_protection)
    const video=call.video
    const qos = createCallQos('direct', callId, device, isCaller)
    qos.started()
    let disposed = false
    let pc: RTCPeerConnection | undefined
    let retry: number | undefined
    let timeout: number | undefined
    let initialRestart: number | undefined
    let recoveryTimeout: number | undefined
    let restartInFlight = false
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
    let lastRemoteSdp: string | undefined
    let routeSampled = false
    let mosTimer: number | undefined
    let mosAttempts = 0
    let protectedMedia:ReturnType<typeof protectedTransports>|undefined
    let releaseCode:(()=>void)|undefined
    let verifiedTimer:number|undefined
    let encryptedTimer:number|undefined

    function fail(message: string) {
      if (disposed) return
      qos.failed()
      notice(message)
      void end()
    }

    async function transmit(kind: Signal['kind'], payload: Signal['payload']) {
      for (const delay of [0, 350, 1000]) {
        if (delay) await new Promise<void>(resolve => window.setTimeout(resolve, delay))
        if (disposed) return
        const result = await db!.rpc('st_v6_call_signal', { p_call: activeId, p_kind: kind, p_payload: payload, p_device: device })
        if (!result.error || disposed) return
        if (result.status > 0 && result.status < 500 || delay === 1000) throw result.error
      }
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
      if (restart && !disposed) qos.iceRestart()
    }

    async function restartIce(peer: RTCPeerConnection) {
      if (disposed || !isCaller || restartInFlight || peer.connectionState === 'connected' ||
        peer.signalingState !== 'stable' || !peer.remoteDescription) return
      restartInFlight = true
      try {
        await offer(peer, true)
      } catch {
        if (!disposed) await peer.setLocalDescription({ type: 'rollback' }).catch(() => {})
      } finally {
        restartInFlight = false
      }
    }

    function recover(peer: RTCPeerConnection) {
      if (recoveryTimeout === undefined) {
        recoveryTimeout = window.setTimeout(() => fail('The call disconnected.'), 22_000)
      }
      if (!isCaller || retry !== undefined || restartInFlight) return
      retry = window.setTimeout(async () => {
        retry = undefined
        if (disposed || peer.connectionState === 'connected' || recoveryTimeout === undefined) return
        await restartIce(peer)
        if (!disposed && recoveryTimeout !== undefined) recover(peer)
      }, 2500)
    }

    async function sampleAudioQuality(peer: RTCPeerConnection) {
      if (disposed || mosAttempts >= 3) return
      mosAttempts++
      const stats = await peer.getStats().catch(() => undefined)
      if (!disposed && !qos.mos(stats) && mosAttempts < 3) {
        mosTimer = window.setTimeout(() => void sampleAudioQuality(peer), 2500)
      }
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
              .eq('call_id', activeId).neq('sender', user).order('created_at', { ascending: false })
              .order('id', { ascending: false }).limit(750)
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
            if (lastRemoteSdp === description.sdp ||
                (row.kind === 'answer' && peer.signalingState !== 'have-local-offer')) continue
            if (secure && !protectedDescription(description,video)) throw new Error('Unexpected protected media description')
            if (row.kind === 'offer' && iceDeadline - performance.now() <= 60000) await renewIce(peer)
            if (disposed) return
            await peer.setRemoteDescription(description)
            if (secure && peer.getTransceivers().some(transport=>!protectedMedia?.receivers.has(transport.receiver))) {
              throw new Error('Unexpected unprotected media receiver')
            }
            lastRemoteSdp = description.sdp
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
        const keys=secure ? await protectedCallKeys(call!,user,async key=>{
          const result=await db!.rpc('st_v6_protected_call_key',{p_call:callId,p_device:device,p_key:key})
          if (result.error) throw result.error
          return typeof result.data==='string'?result.data:null
        },()=>disposed) : null
        if (disposed) return
        if (keys) {
          setProtection({code:keys.code,verified:false,ready:false})
          await new Promise<void>(resolve=>{
            releaseCode=resolve
            approveCode.current=resolve
            verifiedTimer=window.setTimeout(()=>fail('The protection code was not verified in time.'),120000)
          })
          window.clearTimeout(verifiedTimer)
          approveCode.current=null
          if (disposed || current.current?.id!==callId) return
          setProtection({code:keys.code,verified:true,ready:false})
        }
        const { config, ttlSeconds } = await callConfiguration(callId)
        if (disposed) return
        const peer = new RTCPeerConnection(config)
        pc = peer
        activePeer.current = peer
        scheduleIceRenewal(peer, ttlSeconds)
        if (keys) {
          const incoming=new MediaStream()
          const confirmed=new Set<string>()
          function showProtectedMedia() {
            if (!disposed && confirmed.has('audio') && (!video || confirmed.has('video')) &&
              incoming.getAudioTracks().length===1 && (!video || incoming.getVideoTracks().length===1)) {
              window.clearTimeout(encryptedTimer)
              setRemote(incoming)
              setProtection({code:keys!.code,verified:true,ready:true})
            }
          }
          protectedMedia=protectedTransports(peer,local!,keys,kind=>{
            confirmed.add(kind)
            showProtectedMedia()
          },()=>fail('Protected media encryption failed.'))
          peer.ontrack=event=>{
            if (!protectedMedia?.receivers.has(event.receiver) || incoming.getTracks().includes(event.track)) return
            incoming.addTrack(event.track)
            showProtectedMedia()
          }
          encryptedTimer=window.setTimeout(()=>fail('Protected media could not be authenticated.'),18000)
        } else {
          local!.getTracks().forEach(track => peer.addTrack(track, local!))
          peer.ontrack = event => { if (!disposed && event.streams[0]) setRemote(event.streams[0]) }
        }
        peer.onicecandidate = event => {
          if (event.candidate) void transmit('ice', event.candidate.toJSON()).catch(() => undefined)
        }
        peer.onconnectionstatechange = () => {
          if (disposed) return
          setConnection(peer.connectionState)
          if (peer.connectionState === 'connected') {
            window.clearTimeout(timeout)
            window.clearTimeout(initialRestart)
            window.clearTimeout(recoveryTimeout)
            window.clearTimeout(retry)
            recoveryTimeout = undefined
            retry = undefined
            qos.connected()
            if (mosTimer === undefined) mosTimer = window.setTimeout(() => void sampleAudioQuality(peer), 2500)
            if (!routeSampled) {
              routeSampled = true
              void peer.getStats().then(stats => { if (!disposed) qos.route(stats) }).catch(() => {})
            }
          }
          if (peer.connectionState === 'failed' || peer.connectionState === 'disconnected') {
            qos.reconnecting()
            recover(peer)
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
        if (isCaller) initialRestart = window.setTimeout(() => void restartIce(peer), 12_000)
        timeout = window.setTimeout(() => {
          if (!peer.remoteDescription) fail('The call did not finish connecting. Check both devices are online and try again.')
          else if (peer.getConfiguration().iceTransportPolicy === 'relay') {
            fail('The call relay could not connect. Open Network diagnostics in Calls to check the connection.')
          } else {
            fail('No direct route was available between these networks. Try another network or run Network diagnostics in Calls.')
          }
        }, 30000)
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
      window.clearTimeout(recoveryTimeout)
      window.clearTimeout(timeout)
      window.clearTimeout(initialRestart)
      window.clearInterval(polling)
      window.clearTimeout(iceTimer)
      window.clearTimeout(mosTimer)
      window.clearTimeout(verifiedTimer)
      window.clearTimeout(encryptedTimer)
      releaseCode?.()
      approveCode.current=null
      removeChannel?.()
      removeHint?.()
      if (activePeer.current === pc) activePeer.current = null
      pc?.close()
      protectedMedia?.close()
    }
  }, [activeId, call, isCaller, local, user, end, notice, hints, device])

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
    if (current.current?.media_protection || sharingBusy || displayStream.current || !peer || peer.connectionState !== 'connected' || !camera || !sender) return
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

  async function setNoiseReduction(enabled: boolean) {
    const source = stream.current
    const microphone = source?.getAudioTracks()[0]
    const peer = activePeer.current
    const sender = peer?.getSenders().find(item => item.track === microphone)
    if (!source || !microphone || !peer || !sender) return false

    const constraints = { ...microphone.getConstraints(), noiseSuppression: { exact: enabled } }
    try {
      await microphone.applyConstraints(constraints)
      if (microphone.getSettings().noiseSuppression === enabled) return true
    } catch {
      // Some browsers can apply this setting only when opening the microphone.
    }

    let capture: MediaStream | undefined
    try {
      const deviceId = microphone.getSettings().deviceId
      capture = await navigator.mediaDevices.getUserMedia({
        audio: { ...constraints, ...(deviceId ? { deviceId: { exact: deviceId } } : {}) },
      })
      const replacement = capture.getAudioTracks()[0]
      if (!replacement || replacement.getSettings().noiseSuppression !== enabled ||
        activePeer.current !== peer || stream.current !== source || sender.track !== microphone) return false

      replacement.enabled = microphone.enabled
      await sender.replaceTrack(replacement)
      if (activePeer.current !== peer || stream.current !== source) return false
      replacement.enabled = microphone.enabled
      source.removeTrack(microphone)
      source.addTrack(replacement)
      microphone.stop()
      capture = undefined
      return true
    } catch {
      return false
    } finally {
      capture?.getTracks().forEach(track => track.stop())
    }
  }

  const confirmProtection=()=>approveCode.current?.()
  return { call, local, remote, connection, busy, start, answer, end, markBusy, historyVersion, screen, sharingBusy, shareScreen, stopSharing,
    protection,confirmProtection,setNoiseReduction }
}
