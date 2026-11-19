'use client'

import { useEffect, useRef, useState } from 'react'
import { Mic, MicOff, Phone, PhoneOff, Video, VideoOff } from 'lucide-react'
import { type useCalling } from '../lib/calling'

function Media({ stream, muted, label }: { stream: MediaStream; muted?: boolean; label: string }) {
  const ref = useRef<HTMLVideoElement>(null)
  const [play, setPlay] = useState(false)
  useEffect(() => {
    if (!ref.current) return
    ref.current.srcObject = stream
    void ref.current.play().catch(() => setPlay(true))
  }, [stream])
  return <div className={stream.getVideoTracks().length ? 'media' : 'audio-media'}>
    <video ref={ref} autoPlay playsInline muted={muted} aria-label={label} />
    {play && <button className="secondary" onClick={() => void ref.current?.play().then(() => setPlay(false))}>Play call audio</button>}
  </div>
}

export function CallPanel({ state, self, name }: { state: ReturnType<typeof useCalling>; self: string; name: string }) {
  const [muted, setMuted] = useState(false)
  const [camera, setCamera] = useState(true)
  const { call, local, remote, connection, busy, answer, end } = state
  if (!call) return null
  const incoming = call.status === 'ringing' && call.callee === self
  const mode = call.video ? 'Video' : 'Audio'
  const status = incoming ? 'Incoming call' : call.status === 'ringing' ? 'Ringing…'
    : connection === 'connected' ? 'Connected' : connection === 'disconnected' || connection === 'failed' ? 'Reconnecting…' : 'Connecting…'
  return <section className="call-panel" aria-label={mode + ' call'}>
    <div className="card-icon">{call.video ? <Video size={22} /> : <Phone size={21} />}</div>
    <div className="call-title"><h2>{name}</h2><p role="status">{mode} · {status}</p></div>
    {remote && <Media stream={remote} label="Remote participant" />}
    {local && call.video && <div className="self-media"><Media stream={local} label="Your camera preview" muted /></div>}
    <div className="action-row">
      {incoming && <button disabled={busy} className="primary" onClick={answer}><Phone size={17} /> Answer</button>}
      {local && <button title={muted ? 'Unmute' : 'Mute microphone'} aria-label={muted ? 'Unmute' : 'Mute microphone'} className="secondary" onClick={() => {
        local.getAudioTracks().forEach(track => { track.enabled = muted })
        setMuted(!muted)
      }}>{muted ? <MicOff size={18} /> : <Mic size={18} />}</button>}
      {local && call.video && <button title={camera ? 'Turn camera off' : 'Turn camera on'} aria-label={camera ? 'Turn camera off' : 'Turn camera on'} className="secondary" onClick={() => {
        local.getVideoTracks().forEach(track => { track.enabled = !camera })
        setCamera(!camera)
      }}>{camera ? <Video size={18} /> : <VideoOff size={18} />}</button>}
      <button className="danger" onClick={end}><PhoneOff size={17} /> {incoming ? 'Decline' : 'Hang up'}</button>
    </div>
  </section>
}
