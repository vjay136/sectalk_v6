'use client'

import { createLocalVideoTrack, Room, type LocalVideoTrack } from 'livekit-client'
import { useEffect, useId, useRef, useState } from 'react'
import { backgroundModel, backgroundWasm } from '../lib/meeting-background'
import styles from './meeting-media.module.css'

type DeviceChoices = { microphone: string; camera: string; speaker: string }
export type MeetingChoices = DeviceChoices & {
  audio: boolean
  video: boolean
  processor?: Awaited<ReturnType<typeof createBackgroundBlur>>
}

export async function createBackgroundBlur() {
  const { BackgroundProcessor, supportsBackgroundProcessors } = await import('@livekit/track-processors')
  if (!supportsBackgroundProcessors()) return undefined
  return BackgroundProcessor({
    mode: 'background-blur',
    assetPaths: { tasksVisionFileSet: backgroundWasm, modelAssetPath: backgroundModel },
  }, 'sectalk-background-' + crypto.randomUUID())
}

export function deviceConstraint(deviceId: string) {
  return deviceId ? { exact: deviceId } : undefined
}

type CheckState = 'idle' | 'starting' | 'on' | 'failed'
type RequestMedia = (networkCheck?: boolean, signal?: AbortSignal) => Promise<{ url: string; token: string }>

function DeviceSelect({ label, kind, devices, value, disabled, onChange }: {
  label: string; kind: MediaDeviceKind; devices: MediaDeviceInfo[]; value: string; disabled: boolean
  onChange: (value: string) => void
}) {
  const id = useId()
  return <div>
    <label htmlFor={id}>{label}</label>
    <select id={id} value={value} disabled={disabled} onChange={event => onChange(event.target.value)}>
      <option value="">System default</option>
      {devices.filter(device => device.kind === kind && device.deviceId && device.deviceId !== 'default')
        .map((device, index) => <option key={device.deviceId} value={device.deviceId}>{device.label || label + ' ' + (index + 1)}</option>)}
    </select>
  </div>
}

export default function MeetingPrejoin({ busy, join, requestMedia }: {
  busy: boolean; join: (choices: MeetingChoices) => Promise<void>; requestMedia: RequestMedia
}) {
  const [devices, setDevices] = useState<MediaDeviceInfo[]>([])
  const [choices, setChoices] = useState<DeviceChoices>({ microphone: '', camera: '', speaker: '' })
  const [mic, setMic] = useState(false)
  const [camera, setCamera] = useState(false)
  const [micCheck, setMicCheck] = useState<CheckState>('idle')
  const [cameraCheck, setCameraCheck] = useState<CheckState>('idle')
  const [level, setLevel] = useState(0)
  const [blurredCamera, setBlurredCamera] = useState<string | null>(null)
  const [blurBusy, setBlurBusy] = useState(false)
  const [blurNotice, setBlurNotice] = useState('')
  const [network, setNetwork] = useState('Idle')
  const preview = useRef<HTMLVideoElement>(null)
  const cameraTrack = useRef<LocalVideoTrack | null>(null)
  const blurUpdate = useRef<symbol | null>(null)
  const networkProbe = useRef<AbortController | null>(null)
  const media = navigator.mediaDevices
  const speakerSupported = 'setSinkId' in HTMLMediaElement.prototype
  const blur = blurredCamera === choices.camera && cameraCheck === 'on'

  useEffect(() => {
    if (!media) return
    let active = true
    async function loadDevices() {
      const list = await media.enumerateDevices().catch(() => [])
      if (!active) return
      setDevices(list)
      setChoices(previous => {
        const keep = (id: string, kind: MediaDeviceKind) => list.some(device => device.deviceId === id && device.kind === kind) ? id : ''
        return {
          microphone: keep(previous.microphone, 'audioinput'),
          camera: keep(previous.camera, 'videoinput'),
          speaker: keep(previous.speaker, 'audiooutput'),
        }
      })
    }
    void loadDevices()
    media.addEventListener('devicechange', loadDevices)
    return () => { active = false; media.removeEventListener('devicechange', loadDevices) }
  }, [media, micCheck, cameraCheck])

  useEffect(() => {
    if (!mic || !media) return
    let active = true
    let stream: MediaStream | undefined
    let context: AudioContext | undefined
    let timer: number | undefined
    setMicCheck('starting')
    setLevel(0)
    async function testMicrophone() {
      try {
        const captured = await media.getUserMedia({ audio: { deviceId: deviceConstraint(choices.microphone) } })
        if (!active) {
          captured.getTracks().forEach(track => track.stop())
          return
        }
        stream = captured
        context = new AudioContext()
        const meter = context.createAnalyser()
        meter.fftSize = 1024
        context.createMediaStreamSource(stream).connect(meter)
        const samples = new Uint8Array(meter.fftSize)
        await context.resume()
        if (!active) return
        timer = window.setInterval(() => {
          meter.getByteTimeDomainData(samples)
          const average = samples.reduce((sum, sample) => sum + ((sample - 128) / 128) ** 2, 0) / samples.length
          setLevel(Math.min(1, Math.sqrt(average) * 4))
        }, 100)
        setMicCheck('on')
      } catch {
        stream?.getTracks().forEach(track => track.stop())
        if (context && context.state !== 'closed') void context.close().catch(() => {})
        if (active) {
          setMic(false)
          setMicCheck('failed')
        }
      }
    }
    void testMicrophone()
    return () => {
      active = false
      window.clearInterval(timer)
      stream?.getTracks().forEach(track => track.stop())
      if (context && context.state !== 'closed') void context.close().catch(() => {})
    }
  }, [choices.microphone, media, mic])

  useEffect(() => {
    if (!camera || !media) return
    let active = true
    const element = preview.current
    setCameraCheck('starting')
    async function testCamera() {
      try {
        const track = await createLocalVideoTrack({ deviceId: deviceConstraint(choices.camera) })
        if (!active) {
          track.stop()
          return
        }
        cameraTrack.current = track
        if (element) track.attach(element)
        setCameraCheck('on')
      } catch {
        if (active) {
          setCamera(false)
          setCameraCheck('failed')
        }
      }
    }
    void testCamera()
    return () => {
      active = false
      const track = cameraTrack.current
      cameraTrack.current = null
      if (element) track?.detach(element)
      track?.stop()
    }
  }, [camera, choices.camera, media])

  useEffect(() => () => networkProbe.current?.abort(), [])

  function selectDevice(kind: keyof DeviceChoices, value: string) {
    if (kind === 'camera') {
      setBlurredCamera(null)
      setBlurNotice('')
    }
    setChoices(previous => ({ ...previous, [kind]: value }))
  }

  async function toggleBlur() {
    const track = cameraTrack.current
    if (!track || blurBusy) return
    const update = Symbol()
    blurUpdate.current = update
    setBlurBusy(true)
    setBlurNotice('')
    let processor
    try {
      if (blur) {
        await track.stopProcessor()
        if (cameraTrack.current === track) setBlurredCamera(null)
      } else {
        processor = await createBackgroundBlur()
        if (cameraTrack.current !== track) return
        if (!processor) {
          setBlurNotice('Background blur is unavailable in this browser.')
          return
        }
        await track.setProcessor(processor)
        if (cameraTrack.current !== track) {
          await track.stopProcessor()
          return
        }
        setBlurredCamera(choices.camera)
      }
    } catch {
      await processor?.destroy().catch(() => {})
      if (cameraTrack.current === track) {
        setBlurredCamera(null)
        setBlurNotice('Background blur could not start. Try again or join with it off.')
      }
    } finally {
      if (blurUpdate.current === update) {
        blurUpdate.current = null
        setBlurBusy(false)
      }
    }
  }

  async function checkNetwork() {
    if (networkProbe.current) return
    const controller = new AbortController()
    networkProbe.current = controller
    setNetwork('Checking connection…')
    const room = new Room()
    const disconnect = () => { void room.disconnect().catch(() => {}) }
    controller.signal.addEventListener('abort', disconnect, { once: true })
    const timeout = window.setTimeout(() => controller.abort(), 12_000)
    try {
      if (!navigator.onLine) {
        setNetwork('You appear to be offline.')
        return
      }
      const { url, token } = await requestMedia(true, controller.signal)
      if (controller.signal.aborted) throw new Error('Network check timed out')
      await room.connect(url, token, {
        autoSubscribe: false, maxRetries: 0, websocketTimeout: 5_000, peerConnectionTimeout: 5_000,
      })
      if (controller.signal.aborted) throw new Error('Network check timed out')
      setNetwork('Connected to the meeting server.')
    } catch {
      setNetwork('Could not connect to the meeting server. Check your connection and try again.')
    } finally {
      window.clearTimeout(timeout)
      controller.signal.removeEventListener('abort', disconnect)
      await room.disconnect().catch(() => {})
      networkProbe.current = null
    }
  }

  async function joinMeeting() {
    let processor
    if (blur) {
      setBlurBusy(true)
      try {
        processor = await createBackgroundBlur()
      } catch {
        setBlurNotice('Background blur is unavailable. Turn it off to join.')
        return
      } finally {
        setBlurBusy(false)
      }
      if (!processor) {
        setBlurNotice('Background blur is unavailable. Turn it off to join.')
        return
      }
    }
    await join({ ...choices, audio: micCheck === 'on', video: cameraCheck === 'on', processor })
  }

  return <section className={styles.prejoin} aria-label="Meeting setup">
    <h3>Meeting setup</h3>
    <p>Test your devices privately. A microphone or camera left on here will start on when you join.</p>
    {!media && <p role="status">Microphone and camera access is unavailable in this browser.</p>}
    <div className={styles.devices}>
      <div>
        <DeviceSelect label="Microphone" kind="audioinput" devices={devices} value={choices.microphone}
          onChange={value => selectDevice('microphone', value)} disabled={busy || !media}/>
        <button type="button" className="secondary" disabled={busy || !media} onClick={() => {
          setMicCheck('idle')
          setMic(!mic)
        }}>{mic ? 'Stop microphone test' : 'Test microphone'}</button>
        {micCheck === 'starting' && <p role="status">Starting microphone…</p>}
        {micCheck === 'on' && <label>Microphone level <meter min={0} max={1} value={level}/></label>}
        {micCheck === 'failed' && <p role="status">Microphone unavailable. Check browser permissions or select another device.</p>}
      </div>
      <div>
        <DeviceSelect label="Camera" kind="videoinput" devices={devices} value={choices.camera}
          onChange={value => selectDevice('camera', value)} disabled={busy || blurBusy || !media}/>
        <button type="button" className="secondary" disabled={busy || !media} onClick={() => {
          blurUpdate.current = null
          setBlurBusy(false)
          setCameraCheck('idle')
          setCamera(!camera)
          setBlurredCamera(null)
          setBlurNotice('')
        }}>{camera ? 'Stop camera test' : 'Test camera'}</button>
        {camera && <video ref={preview} className={styles.cameraPreview} autoPlay muted playsInline aria-label="Camera preview"/>}
        {cameraCheck === 'starting' && <p role="status">Starting camera…</p>}
        {cameraCheck === 'failed' && <p role="status">Camera unavailable. Check browser permissions or select another device.</p>}
        <button type="button" className="secondary" aria-pressed={blur} disabled={busy || blurBusy || cameraCheck !== 'on'}
          onClick={() => void toggleBlur()}>Blur camera background</button>
        {blurBusy && <p role="status">Updating camera background…</p>}
        {blurNotice && <p role="status">{blurNotice}</p>}
      </div>
      {speakerSupported && <div><DeviceSelect label="Speaker" kind="audiooutput" devices={devices}
        value={choices.speaker} onChange={value => selectDevice('speaker', value)} disabled={busy || !media}/></div>}
    </div>
    <div className="release-row">
      <button type="button" className="secondary" disabled={busy || network === 'Checking connection…'} onClick={() => void checkNetwork()}>Check network</button>
      {network !== 'Idle' && <span role="status">{network}</span>}
    </div>
    <button type="button" className="primary" disabled={busy || blurBusy || micCheck === 'starting' || cameraCheck === 'starting'}
      onClick={() => void joinMeeting()}>Join audio and video</button>
  </section>
}
