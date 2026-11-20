'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { db } from '../lib/data'
import { voiceSampleRate,voiceWave,voiceWaveform } from '../lib/voice-note-format'

const endpoint='/api/voice-notes'
type Note={duration:number;waveform:number[];transcript:string|null;canTranscribe:boolean;expiresAt:string|null}
type Capture={stream:MediaStream;context:AudioContext;node:AudioWorkletNode}

async function noteRequest(chat:string,message:string,params:Record<string,string>={},init?:RequestInit) {
  const {data}=await db!.auth.getSession()
  const response=await fetch(endpoint+'?'+new URLSearchParams({chat,message,...params}),{
    ...init,headers:{Authorization:'Bearer '+data.session?.access_token,...init?.headers},
  })
  if (!response.ok) throw new Error('Voice note unavailable')
  return response
}

function Waveform({waveform}:{waveform:number[]}) {
  return <div role="img" aria-label="Voice note waveform"
    style={{height:26,display:'flex',alignItems:'center',gap:2,marginBlock:5}}>
    {waveform.map((value,index)=><span key={index} style={{background:'currentColor',width:3,
      height:Math.max(2,value*.25),borderRadius:3}}/>)}
  </div>
}

function usePlayback() {
  const [playing,setPlaying]=useState(false)
  const playback=useRef<{context:AudioContext;abort:AbortController}|null>(null)
  const stop=useCallback(()=>{
    const current=playback.current
    playback.current=null
    current?.abort.abort()
    void current?.context.close().catch(()=>{})
    setPlaying(false)
  },[])
  useEffect(()=>stop,[stop])
  async function play(load:(signal:AbortSignal)=>Promise<ArrayBuffer>) {
    stop()
    const context=new AudioContext()
    const abort=new AbortController()
    playback.current={context,abort}
    try {
      await context.resume()
      const pcm=await load(abort.signal)
      if (abort.signal.aborted) return
      const audio=await context.decodeAudioData(pcm)
      if (abort.signal.aborted) return
      const source=context.createBufferSource()
      source.buffer=audio
      source.connect(context.destination)
      source.onended=()=>{if(playback.current?.context===context) stop()}
      source.start()
      setPlaying(true)
    } catch(error) {
      if (abort.signal.aborted) return
      stop()
      throw error
    }
  }
  return {play,stop,playing}
}

export function VoiceNoteRecorder({chat,blocked,disabled,timer,onSent}:{chat:string;blocked:boolean;disabled:boolean;timer:number;onSent:()=>void}) {
  const [config,setConfig]=useState<{configured:boolean;speech:boolean}|null>(null)
  const [recording,setRecording]=useState(false)
  const [busy,setBusy]=useState(false)
  const [preview,setPreview]=useState<{pcm:Uint8Array<ArrayBuffer>;waveform:number[];message:string}|null>(null)
  const [speech,setSpeech]=useState(false)
  const [notice,setNotice]=useState('')
  const capture=useRef<Capture|null>(null)
  const closing=useRef<number|undefined>(undefined)
  const mounted=useRef(true)
  const blockedNow=useRef(blocked)
  blockedNow.current=blocked
  const playback=usePlayback()
  const stopPlayback=playback.stop
  const release=useCallback(()=>{
    window.clearTimeout(closing.current)
    const current=capture.current
    capture.current=null
    current?.node.disconnect()
    current?.node.port.close()
    current?.stream.getTracks().forEach(track=>track.stop())
    void current?.context.close().catch(()=>{})
  },[])

  useEffect(()=>{
    mounted.current=true
    const controller=new AbortController()
    void fetch(endpoint,{signal:controller.signal}).then(response=>response.json()).then(data=>{
      if (!controller.signal.aborted) setConfig(data)
    }).catch(()=>{})
    return ()=>{mounted.current=false;controller.abort();release()}
  },[release])
  useEffect(()=>{
    if (blocked) {
      release()
      stopPlayback()
      setRecording(false)
      setPreview(null)
      setSpeech(false)
    }
  },[blocked,release,stopPlayback])

  async function start() {
    if (busy || blocked || disabled) return
    setBusy(true)
    setNotice('')
    let stream:MediaStream|undefined
    let context:AudioContext|undefined
    try {
      stream=await navigator.mediaDevices.getUserMedia({audio:{echoCancellation:true},video:false})
      context=new AudioContext({sampleRate:voiceSampleRate})
      if (context.sampleRate!==voiceSampleRate) throw new Error('Sample rate unsupported')
      await context.audioWorklet.addModule('/voice-note-pcm.js')
      if (!mounted.current || blockedNow.current) throw new Error('Recorder closed')
      const node=new AudioWorkletNode(context,'voice-note-pcm')
      const source=context.createMediaStreamSource(stream)
      capture.current={stream,context,node}
      node.port.onmessage=event=>{
        if (!(event.data instanceof ArrayBuffer) || capture.current?.node!==node) return
        const pcm=new Uint8Array(event.data)
        release()
        setRecording(false)
        if (pcm.length<2000) {setNotice('Record a little longer.');return}
        setPreview({pcm,waveform:voiceWaveform(pcm),message:crypto.randomUUID()})
      }
      source.connect(node).connect(context.destination)
      await context.resume()
      if (capture.current?.node===node) setRecording(true)
    } catch {
      stream?.getTracks().forEach(track=>track.stop())
      void context?.close().catch(()=>{})
      if (mounted.current) setNotice('Could not record from the microphone.')
    } finally { if (mounted.current) setBusy(false) }
  }

  function finish() {
    capture.current?.node.port.postMessage('stop')
    closing.current=window.setTimeout(()=>{
      release()
      setRecording(false)
      setNotice('Could not finish the recording.')
    },1500)
  }

  async function send() {
    if (!preview || busy || blocked || disabled) return
    setBusy(true)
    setNotice('')
    try {
      playback.stop()
      await noteRequest(chat,preview.message,{timer:String(timer),speech:speech?'1':'0'},
        {method:'POST',headers:{'Content-Type':'application/octet-stream'},body:preview.pcm})
      setPreview(null)
      setSpeech(false)
      onSent()
    } catch { setNotice('Could not send the voice note. The recording is still available here.') }
    finally { setBusy(false) }
  }

  if (!config?.configured || blocked) return null
  return <div className="attachment-capacity" aria-label="Voice note recorder">
    {!recording && !preview && <button type="button" className="secondary" disabled={busy||disabled} onClick={()=>void start()}>Record voice note</button>}
    {recording && <button type="button" className="secondary" onClick={finish}>Stop recording</button>}
    {preview && <>
      <Waveform waveform={preview.waveform}/>
      <button type="button" className="secondary" onClick={()=>playback.playing?playback.stop():
        void playback.play(async()=>voiceWave(preview.pcm).buffer).catch(()=>setNotice('Could not play the preview.'))}>
        {playback.playing?'Stop preview':'Play recording preview'}
      </button>
      {config.speech && <label className="task-check"><input type="checkbox" checked={speech} onChange={event=>setSpeech(event.target.checked)}/>
        Allow an English transcript for this note</label>}
      <button type="button" className="primary" disabled={busy||disabled} onClick={()=>void send()}>Send voice note</button>
      <button type="button" className="secondary" disabled={busy} onClick={()=>{playback.stop();setPreview(null);setSpeech(false)}}>Discard recording</button>
    </>}
    {notice && <p role="status">{notice}</p>}
  </div>
}

export function VoiceNotePlayer({chat,message,blocked,revision}:{chat:string;message:string;blocked:boolean;revision:boolean}) {
  const [note,setNote]=useState<Note|null>(null)
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)
  const playback=usePlayback()
  const stop=playback.stop
  useEffect(()=>{
    const controller=new AbortController()
    if (blocked) {
      setNote(null)
      stop()
    } else {
      void noteRequest(chat,message,{}, {signal:controller.signal}).then(response=>response.json()).then(data=>{
        if (!controller.signal.aborted) setNote(data)
      }).catch(()=>{if (!controller.signal.aborted) setError('Voice note unavailable.')})
    }
    return ()=>controller.abort()
  },[blocked,chat,message,revision,stop])
  useEffect(()=>{
    if (!note?.expiresAt) return
    const timer=window.setTimeout(()=>{stop();setNote(null)},Math.max(0,Date.parse(note.expiresAt)-Date.now()))
    return ()=>window.clearTimeout(timer)
  },[note?.expiresAt,stop])

  async function transcribe() {
    setBusy(true)
    setError('')
    try {
      await noteRequest(chat,message,{mode:'transcribe'},{method:'POST'})
      setNote(await (await noteRequest(chat,message)).json())
    } catch { setError('The transcript could not be created. Try again later.') }
    finally { setBusy(false) }
  }
  async function play() {
    setError('')
    try { await playback.play(async signal=>(await noteRequest(chat,message,{mode:'audio'},{signal})).arrayBuffer()) }
    catch { setNote(null);setError('Voice note unavailable.') }
  }

  return <div aria-label="Voice note">
    <strong>Voice note</strong>
    {note && !blocked && <>
      <Waveform waveform={note.waveform}/>
      <small>{Math.ceil(note.duration)} s · Encrypted in managed storage</small>
      <button type="button" className="text-button" onClick={()=>playback.playing?playback.stop():void play()}>
        {playback.playing?'Stop voice note':'Play voice note'}
      </button>
      {note.transcript && <p>Transcript · {note.transcript}</p>}
      {!note.transcript && note.canTranscribe && <button type="button" className="text-button" disabled={busy}
        onClick={()=>void transcribe()}>Generate English transcript</button>}
    </>}
    {error && <p role="status">{error}</p>}
  </div>
}
