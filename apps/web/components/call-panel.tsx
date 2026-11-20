'use client'

import { useEffect, useRef, useState } from 'react'
import { Mic, MicOff, Monitor, MonitorOff, MoreHorizontal, Phone, PhoneOff, Video, VideoOff } from 'lucide-react'
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

export function CallPanel({ state, self, name, openChat, reportContact }: {
  state: ReturnType<typeof useCalling>; self:string; name:string; openChat:(chat:string)=>void; reportContact:(chat:string)=>void
}) {
  const [muted, setMuted] = useState(false)
  const [camera, setCamera] = useState(true)
  const { call, local, remote, connection, busy, answer, end, markBusy, screen, sharingBusy, shareScreen, stopSharing,
    protection,confirmProtection } = state
  if (!call) return null
  const incoming = call.status === 'ringing' && call.callee === self
  const mode = call.video ? 'Video' : 'Audio'
  const secure = call.media_protection===1
  const status = incoming ? 'Incoming call' : call.status === 'ringing' ? 'Ringing…'
    : secure && !protection?.verified ? 'Waiting for code verification'
    : secure && connection==='connected' && !protection?.ready ? 'Authenticating protected media…'
    : secure && connection==='connected' && protection?.ready ? 'Protected media connected'
    : connection === 'connected' ? 'Connected' : connection === 'disconnected' || connection === 'failed' ? 'Reconnecting…' : 'Connecting…'
  return <section className="call-panel" aria-label={secure ? 'Protected '+mode.toLowerCase()+' call' : mode+' call'}>
    <div className="card-icon">{call.video ? <Video size={22} /> : <Phone size={21} />}</div>
    <div className="call-title"><h2>{name}</h2><p role="status">{mode} · {status}</p></div>
    {secure && protection && <div>
      <p>Verification code <output aria-label="Call verification code">{protection.code}</output></p>
      {!protection.verified && <>
        <p>Compare this code with your contact in a separate trusted channel. Hang up if the codes differ.</p>
        <button type="button" className="secondary" onClick={confirmProtection}>Codes match</button>
      </>}
    </div>}
    {remote && <Media stream={remote} label="Remote participant" />}
    {local && call.video && <div className="self-media"><Media stream={screen || local} label={screen ? 'Your shared screen' : 'Your camera preview'} muted /></div>}
    <div className="action-row">
      <details className="call-menu">
        <summary className="secondary" aria-label="Call menu"><MoreHorizontal size={18}/> Call menu</summary>
        <div className="message-menu-panel">
          <button type="button" className="text-button" onClick={()=>openChat(call.chat_id)}>Open conversation</button>
          <button type="button" className="text-button" onClick={()=>reportContact(call.chat_id)}>Report contact</button>
          <button type="button" className="text-button remove-text" disabled={busy} onClick={()=>void end()}>{incoming?'Decline call':call.status==='ringing'?'Cancel call':'End call'}</button>
        </div>
      </details>
      {incoming && <button disabled={busy} className="primary" onClick={answer}><Phone size={17} /> Answer</button>}
      {incoming && <button disabled={busy} type="button" className="secondary" onClick={markBusy}>Busy</button>}
      {local && <button title={muted ? 'Unmute' : 'Mute microphone'} aria-label={muted ? 'Unmute' : 'Mute microphone'} className="secondary" onClick={() => {
        local.getAudioTracks().forEach(track => { track.enabled = muted })
        setMuted(!muted)
      }}>{muted ? <MicOff size={18} /> : <Mic size={18} />}</button>}
      {local && call.video && !screen && <button title={camera ? 'Turn camera off' : 'Turn camera on'} aria-label={camera ? 'Turn camera off' : 'Turn camera on'} className="secondary" onClick={() => {
        local.getVideoTracks().forEach(track => { track.enabled = !camera })
        setCamera(!camera)
      }}>{camera ? <Video size={18} /> : <VideoOff size={18} />}</button>}
      {!secure && call.video && (connection === 'connected' || screen) && <button className="secondary" disabled={sharingBusy} onClick={() => void (screen ? stopSharing() : shareScreen())}>
        {screen ? <MonitorOff size={17} /> : <Monitor size={17} />} {screen ? 'Stop sharing' : 'Share screen'}
      </button>}
      <button className="danger" disabled={busy} onClick={end}><PhoneOff size={17} /> {incoming ? 'Decline' : call.status==='ringing'?'Cancel call':'Hang up'}</button>
    </div>
  </section>
}
