'use client'

import dynamic from 'next/dynamic'
import Script from 'next/script'
import { useEffect, useRef, useState } from 'react'

const Media=dynamic(()=>import('./guest-meeting-media'),{ssr:false})
const endpoint='/api/meetings/guests'
type Visitor={access:string;state:'waiting'|'approved'|'denied';expiresAt:string}
type Widget={
  render:(element:HTMLElement, options:{sitekey:string;action:string;callback:(value:string)=>void;
    'expired-callback':()=>void;'error-callback':()=>void})=>string
  reset:(id:string)=>void
  remove:(id:string)=>void
}
const turnstile=()=>(window as Window & {turnstile?:Widget}).turnstile

async function guestRequest(action:string,body:Record<string,string>,access?:string,signal?:AbortSignal) {
  return fetch(endpoint,{method:'POST',signal,headers:{'Content-Type':'application/json',
    ...(access?{Authorization:'Guest '+access}:{})},body:JSON.stringify({action,...body})})
}

export function GuestMeeting() {
  const [ticket,setTicket]=useState<string|null>(null)
  const [siteKey,setSiteKey]=useState('')
  const [ready,setReady]=useState(false)
  const [name,setName]=useState('')
  const [captcha,setCaptcha]=useState('')
  const [visitor,setVisitor]=useState<Visitor|null>(null)
  const [media,setMedia]=useState<{url:string;token:string}|null>(null)
  const [error,setError]=useState('')
  const [closed,setClosed]=useState(false)
  const [busy,setBusy]=useState(false)
  const widget=useRef<HTMLDivElement|null>(null)
  const widgetId=useRef<string|null>(null)
  const initialFragment=useRef<string|null>(null)
  const access=visitor?.access

  useEffect(()=>{
    const controller=new AbortController()
    if (initialFragment.current===null) {
      initialFragment.current=location.hash.slice(1)
      if (initialFragment.current) history.replaceState(history.state,'',location.pathname)
    }
    const fragment=initialFragment.current
    if (/^[\w-]{43}$/.test(fragment)) {
      setTicket(fragment)
      void fetch(endpoint,{signal:controller.signal}).then(response=>response.json()).then(value=>{
        if (!controller.signal.aborted && value.configured && typeof value.siteKey==='string') setSiteKey(value.siteKey)
        else if (!controller.signal.aborted) setClosed(true)
      }).catch(()=>{if(!controller.signal.aborted) setClosed(true)})
    } else setClosed(true)
    return ()=>controller.abort()
  },[])

  useEffect(()=>{
    if (!ready || !siteKey || !widget.current || visitor || closed) return
    const provider=turnstile()
    if (!provider) return
    const id=provider.render(widget.current,{sitekey:siteKey,action:'meeting_guest',callback:setCaptcha,
      'expired-callback':()=>setCaptcha(''),'error-callback':()=>setError('Verification could not load.')})
    widgetId.current=id
    return ()=>{provider.remove(id);widgetId.current=null}
  },[ready,siteKey,visitor,closed])

  useEffect(()=>{
    if (!access) return
    const controller=new AbortController()
    let timer:number | undefined
    async function poll() {
      try {
        const response=await guestRequest('status',{},access,controller.signal)
        if (!response.ok) throw new Error('Guest access expired')
        const next=await response.json()
        if (controller.signal.aborted) return
        if (next.state==='denied') {
          setMedia(null)
          setClosed(true)
          return
        }
        setVisitor(previous=>previous ? {...previous,state:next.state} : null)
        timer=window.setTimeout(()=>void poll(),2500)
      } catch {
        if (!controller.signal.aborted) {
          setMedia(null)
          setClosed(true)
        }
      }
    }
    timer=window.setTimeout(()=>void poll(),1200)
    return ()=>{controller.abort();window.clearTimeout(timer)}
  },[access])

  async function joinLobby(event:React.FormEvent) {
    event.preventDefault()
    if (!ticket || !name.trim() || !captcha || busy) return
    setBusy(true)
    setError('')
    try {
      const response=await guestRequest('request',{ticket,name,captcha})
      if (!response.ok) throw new Error('Guest access unavailable')
      setVisitor(await response.json())
      setTicket(null)
    } catch {
      setError('Could not join the lobby. Complete a new verification or ask for another link.')
      setCaptcha('')
      if (widgetId.current) turnstile()?.reset(widgetId.current)
    } finally { setBusy(false) }
  }

  async function joinMedia() {
    if (!access || visitor?.state!=='approved' || busy || closed) return
    setBusy(true)
    setError('')
    try {
      const response=await guestRequest('token',{},access)
      if (!response.ok) throw new Error('Guest access unavailable')
      setMedia(await response.json())
    } catch { setError('Could not join meeting media. Try again in a few seconds.') }
    finally { setBusy(false) }
  }

  return <main className="content-page">
    <section className="release-section" aria-label="Guest meeting">
      <h1>Guest meeting</h1>
      {closed ? <p role="status">This guest session is closed. Ask the host for a new link.</p>
        : visitor?.state==='waiting' ? <p role="status">Waiting for the host to admit you.</p>
        : visitor?.state==='approved' && !media ? <button type="button" className="primary" disabled={busy}
          onClick={()=>void joinMedia()}>Join meeting media</button>
        : ticket && siteKey ? <form className="auth-card" onSubmit={joinLobby}>
          <label>Display name<input value={name} onChange={event=>setName(event.target.value)} required maxLength={60}/></label>
          <Script src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit" strategy="afterInteractive"
            onReady={()=>setReady(true)} onError={()=>setError('Verification could not load.')}/>
          <div ref={widget}/>
          <button type="submit" className="primary" disabled={busy || !captcha}>Request admission</button>
        </form> : !media && <p role="status">Checking the guest link…</p>}
      {error && <p role="alert">{error}</p>}
    </section>
    {media && !closed && <Media {...media} leave={()=>setMedia(null)}/>}
  </main>
}
