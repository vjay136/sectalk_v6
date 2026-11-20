'use client'

import { useEffect, useId, useRef, useState } from 'react'
import { db } from '../lib/data'

const endpoint = '/api/meetings/captions'
const languages = [['en','English'],['es','Spanish'],['fr','French'],['de','German'],['hi','Hindi']] as const
type Line = { sequence: number; speaker: string; line: string }
type CaptionView = { admitted: boolean; active: boolean; host: boolean; language: string|null;
  consented: boolean; sending: boolean; lines: Line[] }
type Microphone = { track: MediaStreamTrack; sid:string }

async function send(meeting:string,action:string,signal?:AbortSignal,language?:string,after?:number) {
  const {data} = await db!.auth.getSession()
  const response = await fetch(endpoint,{method:'POST',signal,
    headers:{'Content-Type':'application/json',Authorization:'Bearer '+data.session?.access_token},
    body:JSON.stringify({meeting,action,language,after})})
  if (!response.ok) throw new Error('Captions unavailable.')
  return response.json() as Promise<CaptionView>
}

function useCaptionMicrophone(meeting:string,microphone:Microphone|undefined,enabled:boolean) {
  const track=microphone?.track
  const sid=microphone?.sid
  const [failure,setFailure] = useState(false)
  useEffect(()=>{
    if (!track || !sid || !enabled || !window.AudioContext) return
    const abort = new AbortController()
    let context:AudioContext | undefined
    let source:MediaStreamAudioSourceNode | undefined
    let node:AudioWorkletNode | undefined
    let sending=false
    const activeTrack=track
    const microphoneSid=sid
    async function upload(event:MessageEvent<ArrayBuffer>) {
      if (abort.signal.aborted || sending || activeTrack.muted || !activeTrack.enabled || activeTrack.readyState!=='live') return
      sending=true
      try {
        const {data}=await db!.auth.getSession()
        const response=await fetch(endpoint+'?'+new URLSearchParams({meeting}),{method:'PUT',signal:abort.signal,
          headers:{'Content-Type':'application/octet-stream','X-Microphone-Track':microphoneSid,Authorization:'Bearer '+data.session?.access_token},
          body:event.data})
        if (!abort.signal.aborted) setFailure(!response.ok && response.status!==403)
      } catch { if (!abort.signal.aborted) setFailure(true) }
      finally { sending=false }
    }
    async function listen() {
      context=new AudioContext({sampleRate:16000})
      if (context.sampleRate!==16000) throw new Error('Captions require 16 kHz audio')
      await context.audioWorklet.addModule('/meeting-caption-pcm.js')
      if (abort.signal.aborted) return
      source=context.createMediaStreamSource(new MediaStream([activeTrack]))
      node=new AudioWorkletNode(context,'meeting-caption-pcm')
      node.port.onmessage=event=>void upload(event)
      source.connect(node).connect(context.destination)
      await context.resume()
    }
    void listen().catch(()=>{if (!abort.signal.aborted) setFailure(true)})
    return ()=>{
      abort.abort()
      source?.disconnect()
      node?.disconnect()
      node?.port.close()
      void context?.close()
    }
  },[meeting,track,sid,enabled])
  return enabled && Boolean(track) && failure
}

export function MeetingCaptions({ meeting, microphone, ended=false }: {
  meeting:string; microphone?:Microphone; ended?:boolean
}) {
  const [view,setView] = useState<CaptionView|null>(null)
  const languageId=useId()
  const [language,setLanguage] = useState('en')
  const [busy,setBusy] = useState(false)
  const [paused,setPaused] = useState(false)
  const [error,setError] = useState('')
  const [page,setPage] = useState(0)
  const generation=useRef(0)
  const micFailure=useCaptionMicrophone(meeting,microphone,Boolean(view?.sending && !paused && !ended))

  useEffect(()=>{
    const controller=new AbortController()
    let timer:number | undefined
    async function refresh() {
      const current=generation.current
      const latest=await send(meeting,'view',controller.signal,undefined,page).catch(()=>null)
      if (!controller.signal.aborted && current===generation.current) setView(latest)
    }
    void fetch(endpoint,{signal:controller.signal}).then(response=>response.json()).then(value=>{
      if (!value.configured || controller.signal.aborted) return
      void refresh()
      timer=window.setInterval(()=>void refresh(),3500)
    }).catch(()=>{})
    return ()=>{controller.abort();window.clearInterval(timer)}
  },[meeting,page])

  async function act(action:string) {
    if (busy) return
    if (action==='withdraw') setPaused(true)
    setBusy(true)
    setError('')
    ++generation.current
    try {
      const next=await send(meeting,action,undefined,language)
      ++generation.current
      setView(next)
      setPaused(false)
    } catch { setError(action==='withdraw'?'Your microphone sharing is paused. Try removing consent again.':'Captions unavailable.') }
    finally { setBusy(false) }
  }

  if (!view || (!view.language && (ended || !view.host || !view.admitted))) return null
  const title=!view.language?'Meeting captions':view.active?'Live captions':'Meeting transcript'
  return <section className="release-section" aria-label={title}>
    <h3>{title}</h3>
    {error && <p role="alert">{error}</p>}
    {!view.language && <div className="release-row">
      <label htmlFor={languageId}>Spoken language</label>
        <select id={languageId} value={language} onChange={event=>setLanguage(event.target.value)}>
          {languages.map(([code,name])=><option key={code} value={code}>{name}</option>)}
        </select>
      <button type="button" className="secondary" disabled={busy} onClick={()=>void act('start')}>Open captions</button>
    </div>}
    {view.active && !view.sending && view.admitted && <>
      <p>Allow transcription of your microphone for live captions and a saved meeting transcript. Participants who agree can read it. Your captions include your display name.</p>
      <button type="button" className="primary" disabled={busy} onClick={()=>void act('join')}>Agree to captions and transcript</button>
    </>}
    {view.active && view.sending && (!microphone || micFailure) &&
      <p role="status">{micFailure?'This browser could not send microphone audio for captions.':'Turn on your microphone to add captions.'}</p>}
    {view.active && view.host && <button type="button" className="secondary" disabled={busy} onClick={()=>void act('stop')}>Stop live captions</button>}
    {view.consented && <button type="button" className="secondary" disabled={busy} onClick={()=>void act('withdraw')}>Withdraw caption consent</button>}
    {view.language && <p>Spoken language {languages.find(([code])=>code===view.language)?.[1]}</p>}
    {view.lines.length>0 && <ol aria-label={view.active?'Recent captions':'Transcript lines'} aria-live={view.active?'polite':undefined}>
      {view.lines.slice(view.active?-8:0).map(line=><li key={line.sequence}><strong>{line.speaker}</strong> {line.line}</li>)}
    </ol>}
    {!view.active && view.consented && view.lines.length===100 &&
      <button type="button" className="secondary" onClick={()=>setPage(view.lines.at(-1)!.sequence)}>Next transcript page</button>}
    {!view.active && page>0 && <button type="button" className="secondary" onClick={()=>setPage(0)}>Back to transcript start</button>}
  </section>
}
