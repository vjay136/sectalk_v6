'use client'

import { useEffect, useRef, useState } from 'react'
import { AudioLines, Mic, MicOff, Minimize2, Monitor, MonitorOff, MoreHorizontal, Phone, PhoneOff, ShieldCheck, Sparkles, Video, VideoOff } from 'lucide-react'
import { type useCalling } from '../lib/calling'
import { cameraEffectsSupported, noCameraEffects, type CameraEffects } from '../lib/camera-effects'
import { Avatar } from './avatar'
import styles from './call-panel.module.css'
import presentation from './call-presentation.module.css'

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
  const videoStream = stream.getVideoTracks().length > 0
  return <div className={videoStream ? styles.video : styles.audio} data-playback={videoStream ? 'video' : 'audio'}>
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

export function CameraEffectControls({ effects, busy, apply }: {
  effects: CameraEffects; busy: boolean; apply: (effects: CameraEffects) => void
}) {
  return <details className={styles.effects}>
    <summary className="secondary"><Sparkles size={16} aria-hidden="true" /> Video effects</summary>
    <div className={styles.effectChoices}>
      <label>Color filter<select aria-label="Color filter" disabled={busy} value={effects.filter} onChange={event =>
        apply({ ...effects, filter: event.target.value as CameraEffects['filter'] })}>
        <option value="natural">Natural</option><option value="soft">Soft light</option>
        <option value="warm">Warm</option><option value="cool">Cool</option>
        <option value="vivid">Vivid</option><option value="mono">Black and white</option>
      </select></label>
      <label>Decoration<select aria-label="Decoration" disabled={busy} value={effects.decoration} onChange={event =>
        apply({ ...effects, decoration: event.target.value as CameraEffects['decoration'] })}>
        <option value="none">None</option><option value="fox">🦊 Fox</option><option value="owl">🦉 Owl</option>
        <option value="butterfly">🦋 Butterflies</option><option value="hearts">💕 Hearts</option>
        <option value="stars">✨ Stars</option><option value="glitter">✦ Glitter</option>
      </select></label>
      <button type="button" className="secondary" disabled={busy || (effects.filter === 'natural' && effects.decoration === 'none')}
        onClick={() => apply(noCameraEffects)}>Clear effects</button>
    </div>
  </details>
}

function CallSession({ state, self, name, photo, openChat, reportContact, enableSounds }: CallPanelProps) {
  const [minimized, setMinimized] = useState(false)
  const [muted, setMuted] = useState(false)
  const [camera, setCamera] = useState(true)
  const [effects, setEffects] = useState(noCameraEffects)
  const [effectsBusy, setEffectsBusy] = useState(false)
  const [effectsError, setEffectsError] = useState('')
  const { call, local, remote, connection, busy, answer, end, markBusy, screen, sharingBusy, shareScreen, stopSharing,
    protection,confirmProtection,setNoiseReduction,effectPreview,setCameraEnabled,setCameraEffects } = state

  async function applyEffects(next: CameraEffects) {
    setEffectsBusy(true)
    setEffectsError('')
    try {
      if (await setCameraEffects(next)) setEffects(next)
      else setEffectsError('Could not change the camera effect. Try again.')
    } finally {
      setEffectsBusy(false)
    }
  }
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
  return <section className={`call-panel ${styles.panel} ${presentation.surface}`} data-ringing={call.status === 'ringing'}
    data-expanded={!minimized} data-video={call.video}
    aria-label={secure ? 'Protected '+mode.toLowerCase()+' call' : mode+' call'}>
    <header className={styles.header}>
      <Avatar name={name} photo={photo} className={styles.avatar}/>
      <div className={styles.identity}><h2>{name}</h2>
        <p role="status">{call.video ? <Video size={15} aria-hidden="true"/> : <Phone size={14} aria-hidden="true"/>}{mode} · {status}</p>
      </div>
      <div className={styles.headerActions}>
        {secure && <ShieldCheck size={18} aria-label="Protected call"/>}
        {minimized && <button type="button" className="secondary" onClick={() => setMinimized(false)}>Return to call</button>}
        {!minimized && !incoming && <button type="button" className={`secondary ${presentation.minimize}`} aria-label="Minimize call"
          title="Minimize call" onClick={() => setMinimized(true)}><Minimize2 size={18} aria-hidden="true" /></button>}
        <details className={styles.menu} hidden={minimized}>
          <summary className="secondary" aria-label="Call menu" title="Call menu"><MoreHorizontal size={21} aria-hidden="true"/></summary>
          <div className={styles.options}>
            {local && connection === 'connected' && <NoiseControl source={local} setNoiseReduction={setNoiseReduction} />}
            <button type="button" className="text-button" onClick={event=>{
              event.currentTarget.closest('details')?.removeAttribute('open')
              setMinimized(true)
              openChat(call.chat_id)
            }}>Open conversation</button>
            <button type="button" className="text-button" onClick={()=>reportContact(call.chat_id)}>Report contact</button>
            <button type="button" className="text-button remove-text" disabled={busy} onClick={()=>void end()}>{incoming?'Decline call':call.status==='ringing'?'Cancel call':'End call'}</button>
          </div>
        </details>
      </div>
    </header>
    {secure && protection && <div className={`${styles.verification} ${presentation.verification}`}>
      <p>Verification code <output aria-label="Call verification code">{protection.code}</output></p>
      {!protection.verified && <>
        <p>Compare this code with your contact in a separate trusted channel. Hang up if the codes differ.</p>
        <button type="button" className="secondary" onClick={confirmProtection}>Codes match</button>
      </>}
    </div>}
    <div className={`${styles.stage} ${presentation.stage}`} data-remote-video={hasRemoteVideo}>
      {(!call.video || (!local && !hasRemoteVideo)) && <div className={presentation.contact} aria-hidden="true">
        <Avatar name={name} photo={photo} className={presentation.heroAvatar}/>
      </div>}
      {remote && <Media stream={remote} label="Remote participant" />}
      {local && call.video && <div className={styles.preview} data-camera={camera || !!screen}>
        <Media stream={screen || effectPreview || local} label={screen ? 'Your shared screen' : 'Your camera preview'} muted />
        <span>{screen ? 'Your screen' : camera ? 'You' : 'Camera off'}</span>
      </div>}
    </div>
    <div className={presentation.actions}>
    {!secure && call.video && local && camera && !screen && connection === 'connected' && cameraEffectsSupported() &&
      <CameraEffectControls effects={effects} busy={sharingBusy || effectsBusy} apply={next => void applyEffects(next)} />}
    {effectsError && <p role="status" className={styles.effectsError}>{effectsError}</p>}
    {enableSounds && <button type="button" className={`secondary ${styles.enableSound}`} onClick={enableSounds}>Enable call sounds</button>}
    <div className={styles.controls}>
      {incoming && <button disabled={busy} className="primary" onClick={answer}><Phone size={17} /> Answer</button>}
      {incoming && <button disabled={busy} type="button" className="secondary" onClick={markBusy}>Busy</button>}
      {local && <button title={muted ? 'Unmute' : 'Mute microphone'} aria-label={muted ? 'Unmute' : 'Mute microphone'} aria-pressed={muted} className="secondary" onClick={() => {
        local.getAudioTracks().forEach(track => { track.enabled = muted })
        setMuted(!muted)
      }}>{muted ? <MicOff size={18} /> : <Mic size={18} />}</button>}
      {local && call.video && !screen && <button title={camera ? 'Turn camera off' : 'Turn camera on'} aria-label={camera ? 'Turn camera off' : 'Turn camera on'} aria-pressed={!camera} className="secondary" onClick={() => {
        setCameraEnabled(!camera)
        setCamera(!camera)
      }}>{camera ? <Video size={18} /> : <VideoOff size={18} />}</button>}
      {!secure && call.video && (connection === 'connected' || screen) && <button type="button" className="secondary"
        aria-label={screen ? 'Stop sharing' : 'Share screen'} title={screen ? 'Stop sharing' : 'Share screen'}
        aria-pressed={!!screen} disabled={sharingBusy || effectsBusy} onClick={() => void (screen ? stopSharing() : shareScreen())}>
        {screen ? <MonitorOff size={19} aria-hidden="true" /> : <Monitor size={19} aria-hidden="true" />}
      </button>}
      <button className="danger" disabled={busy} onClick={end}><PhoneOff size={17} /> {incoming ? 'Decline' : call.status==='ringing'?'Cancel call':'Hang up'}</button>
    </div>
    </div>
  </section>
}
