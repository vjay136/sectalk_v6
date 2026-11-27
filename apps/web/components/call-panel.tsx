'use client'

import { useEffect, useRef, useState } from 'react'
import { AudioLines, Mic, MicOff, Monitor, MonitorOff, MoreHorizontal, Phone, PhoneOff, ShieldCheck, Video, VideoOff } from 'lucide-react'
import { type useCalling } from '../lib/calling'
import { Avatar } from './avatar'
import styles from './call-panel.module.css'

function Media({ stream, muted, label }: { stream: MediaStream; muted?: boolean; label: string }) {
  const ref = useRef<HTMLVideoElement>(null)
  const [play, setPlay] = useState(false)
  useEffect(() => {
    const video = ref.current
    if (!video) return
    let active = true
    video.srcObject = stream
    void video.play().catch(() => {
      if (active && !muted) setPlay(true)
    })
    return () => { active = false }
  }, [stream, muted])
  return <div className={stream.getVideoTracks().length ? styles.video : styles.audio}>
    <video ref={ref} autoPlay playsInline muted={muted} aria-label={label} onPlaying={() => setPlay(false)} />
    {play && <button type="button" className={`secondary ${styles.resume}`}
      onClick={() => void ref.current?.play().then(() => setPlay(false)).catch(() => setPlay(true))}>Play call audio</button>}
  </div>
}

type CallPanelProps = {
  state: ReturnType<typeof useCalling>; self:string; name:string; openChat:(chat:string)=>void; reportContact:(chat:string)=>void;
  enableSounds?:()=>void; photo?:string
}

function NoiseControl({ source, setNoiseReduction }: {
  source: MediaStream; setNoiseReduction: (enabled: boolean) => Promise<boolean>
}) {
  const [pending, setPending] = useState(false)
  const [error, setError] = useState('')
  const enabled = source.getAudioTracks()[0]?.getSettings().noiseSuppression
  const supported = navigator.mediaDevices?.getSupportedConstraints?.().noiseSuppression && typeof enabled === 'boolean'

  async function toggleNoise() {
    if (pending || !supported) return
    setPending(true)
    setError('')
    const next = !enabled
    try {
      if (!await setNoiseReduction(next)) setError('This microphone could not change noise reduction.')
    } finally {
      setPending(false)
    }
  }

  return <div className={styles.noise}>
    {supported ? <button type="button" className="text-button" aria-label="Noise reduction" aria-pressed={enabled}
      disabled={pending} onClick={() => void toggleNoise()}>
      <AudioLines size={17} aria-hidden="true" /> Noise reduction <span>{enabled ? 'On' : 'Off'}</span>
    </button> : <p>Noise reduction unavailable on this device.</p>}
    {error && <p role="status">{error}</p>}
  </div>
}

export function CallPanel(props: CallPanelProps) {
  return props.state.call ? <CallSession key={props.state.call.id} {...props} /> : null
}

function CallSession({ state, self, name, photo, openChat, reportContact, enableSounds }: CallPanelProps) {
  const [muted, setMuted] = useState(false)
  const [camera, setCamera] = useState(true)
  const { call, local, remote, connection, busy, answer, end, markBusy, screen, sharingBusy, shareScreen, stopSharing,
    protection,confirmProtection,setNoiseReduction } = state
  if (!call) return null
  const incoming = call.status === 'ringing' && call.callee === self
  const mode = call.video ? 'Video' : 'Audio'
  const secure = call.media_protection===1
  const status = incoming ? 'Incoming call' : call.status === 'ringing' ? 'Ringing…'
    : secure && !protection?.verified ? 'Waiting for code verification'
    : secure && connection==='connected' && !protection?.ready ? 'Authenticating protected media…'
    : secure && connection==='connected' && protection?.ready ? 'Protected media connected'
    : connection === 'connected' ? 'Connected' : connection === 'disconnected' || connection === 'failed' ? 'Reconnecting…' : 'Connecting…'
  const hasRemoteVideo = !!remote?.getVideoTracks().length
  return <section className={`call-panel ${styles.panel}`} data-ringing={call.status === 'ringing'}
    aria-label={secure ? 'Protected '+mode.toLowerCase()+' call' : mode+' call'}>
    <header className={styles.header}>
      <Avatar name={name} photo={photo} className={styles.avatar}/>
      <div className={styles.identity}><h2>{name}</h2>
        <p role="status">{call.video ? <Video size={15} aria-hidden="true"/> : <Phone size={14} aria-hidden="true"/>}{mode} · {status}</p>
      </div>
      <div className={styles.headerActions}>
        {secure && <ShieldCheck size={18} aria-label="Protected call"/>}
        <details className={styles.menu}>
          <summary className="secondary" aria-label="Call menu" title="Call menu"><MoreHorizontal size={21} aria-hidden="true"/></summary>
          <div className={styles.options}>
            {local && connection === 'connected' && <NoiseControl source={local} setNoiseReduction={setNoiseReduction} />}
            <button type="button" className="text-button" onClick={()=>openChat(call.chat_id)}>Open conversation</button>
            <button type="button" className="text-button" onClick={()=>reportContact(call.chat_id)}>Report contact</button>
            <button type="button" className="text-button remove-text" disabled={busy} onClick={()=>void end()}>{incoming?'Decline call':call.status==='ringing'?'Cancel call':'End call'}</button>
          </div>
        </details>
      </div>
    </header>
    {secure && protection && <div className={styles.verification}>
      <p>Verification code <output aria-label="Call verification code">{protection.code}</output></p>
      {!protection.verified && <>
        <p>Compare this code with your contact in a separate trusted channel. Hang up if the codes differ.</p>
        <button type="button" className="secondary" onClick={confirmProtection}>Codes match</button>
      </>}
    </div>}
    {(remote || (local && call.video)) && <div className={styles.stage} data-remote-video={hasRemoteVideo}>
      {remote && <Media stream={remote} label="Remote participant" />}
      {local && call.video && <div className={styles.preview} data-camera={camera || !!screen}>
        <Media stream={screen || local} label={screen ? 'Your shared screen' : 'Your camera preview'} muted />
        <span>{screen ? 'Your screen' : camera ? 'You' : 'Camera off'}</span>
      </div>}
    </div>}
    {enableSounds && <button type="button" className={`secondary ${styles.enableSound}`} onClick={enableSounds}>Enable call sounds</button>}
    <div className={styles.controls}>
      {incoming && <button disabled={busy} className="primary" onClick={answer}><Phone size={17} /> Answer</button>}
      {incoming && <button disabled={busy} type="button" className="secondary" onClick={markBusy}>Busy</button>}
      {local && <button title={muted ? 'Unmute' : 'Mute microphone'} aria-label={muted ? 'Unmute' : 'Mute microphone'} aria-pressed={muted} className="secondary" onClick={() => {
        local.getAudioTracks().forEach(track => { track.enabled = muted })
        setMuted(!muted)
      }}>{muted ? <MicOff size={18} /> : <Mic size={18} />}</button>}
      {local && call.video && !screen && <button title={camera ? 'Turn camera off' : 'Turn camera on'} aria-label={camera ? 'Turn camera off' : 'Turn camera on'} aria-pressed={!camera} className="secondary" onClick={() => {
        local.getVideoTracks().forEach(track => { track.enabled = !camera })
        setCamera(!camera)
      }}>{camera ? <Video size={18} /> : <VideoOff size={18} />}</button>}
      {!secure && call.video && (connection === 'connected' || screen) && <button type="button" className="secondary"
        aria-label={screen ? 'Stop sharing' : 'Share screen'} title={screen ? 'Stop sharing' : 'Share screen'}
        aria-pressed={!!screen} disabled={sharingBusy} onClick={() => void (screen ? stopSharing() : shareScreen())}>
        {screen ? <MonitorOff size={19} aria-hidden="true" /> : <Monitor size={19} aria-hidden="true" />}
      </button>}
      <button className="danger" disabled={busy} onClick={end}><PhoneOff size={17} /> {incoming ? 'Decline' : call.status==='ringing'?'Cancel call':'Hang up'}</button>
    </div>
  </section>
}
