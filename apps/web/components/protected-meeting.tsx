'use client'

import dynamic from 'next/dynamic'
import { useCallback, useEffect, useRef, useState } from 'react'
import { db } from '../lib/data'
import { meetingCode, meetingIdentity, unwrapMeetingKey, wrapMeetingKey } from '../lib/protected-meeting'

const Media=dynamic(()=>import('./protected-meeting-media'),{ssr:false})
const endpoint='/api/meetings/protected'
type State={host:string;roster:string[];keys:Record<string,string>;wrapped:boolean;envelope:string|null;verified:boolean;ready:boolean}
type Access={url:string;token:string;roster:string[]}

async function route(meeting:string,action:string,device?:string) {
  const {data}=await db!.auth.getSession()
  const response=await fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json',
    Authorization:'Bearer '+data.session?.access_token},body:JSON.stringify({meeting,action,device})})
  if (!response.ok) throw new Error('Protected meeting unavailable')
  return response.json()
}

export function ProtectedMeetingStart({meeting,refresh}:{meeting:string;refresh:()=>Promise<void>}) {
  const [configured,setConfigured]=useState(false)
  const [busy,setBusy]=useState(false)
  const [message,setMessage]=useState('')
  useEffect(()=>{
    const controller=new AbortController()
    void fetch(endpoint,{signal:controller.signal}).then(response=>response.json())
      .then(result=>{if(!controller.signal.aborted) setConfigured(result.configured===true)}).catch(()=>{})
    return ()=>controller.abort()
  },[])
  if (!configured) return null
  async function start() {
    setBusy(true)
    setMessage('')
    try { await route(meeting,'start');await refresh() }
    catch { setMessage('Admit two to eight participants before starting protected media. Disconnect any managed media first.') }
    finally { setBusy(false) }
  }
  return <div className="release-section">
    <button type="button" className="secondary" disabled={busy} onClick={()=>void start()}>Protect meeting media</button>
    <p>Locks the admitted roster for this meeting. Recording, captions, chat, screen sharing and guest access are unavailable in protected mode.</p>
    {message && <p role="alert">{message}</p>}
  </div>
}

export function ProtectedMeeting({meeting,user}:{meeting:string;user:string}) {
  const [device]=useState(()=>crypto.randomUUID())
  const [started,setStarted]=useState(false)
  const [state,setState]=useState<State|null>(null)
  const [code,setCode]=useState('')
  const [access,setAccess]=useState<Access|null>(null)
  const [closed,setClosed]=useState(false)
  const [busy,setBusy]=useState(false)
  const [message,setMessage]=useState('')
  const identity=useRef<Awaited<ReturnType<typeof meetingIdentity>>|null>(null)
  const groupKey=useRef<ArrayBuffer|null>(null)
  const acceptedCode=useRef('')
  const exchange=useCallback(async (action:string,values:Record<string,unknown>={})=>{
    const result=await db!.rpc('st_v6_protected_meeting_exchange',{p_meeting:meeting,p_device:device,p_action:action,...values})
      .abortSignal(AbortSignal.timeout(4500))
    if (result.error || !result.data) throw new Error('Protected roster unavailable')
    return result.data as State
  },[device,meeting])

  const closeMedia=useCallback(()=>{
    setAccess(null)
    setMessage('Protected media disconnected.')
  },[])

  useEffect(()=>{
    if (!started || closed) return
    let disposed=false
    let timer:number|undefined
    async function update() {
      try {
        let current=await exchange('view')
        const own=identity.current
        if (disposed || !own) return
        if (Object.keys(current.keys).length===current.roster.length) {
          if (!current.wrapped && current.host===user) {
            groupKey.current=crypto.getRandomValues(new Uint8Array(32)).buffer
            const envelopes=await wrapMeetingKey(meeting,current,own,groupKey.current)
            if (disposed) return
            current=await exchange('wrap',{p_envelopes:envelopes})
          } else if (current.wrapped && !groupKey.current && current.envelope) {
            groupKey.current=await unwrapMeetingKey(meeting,current,own,user,current.envelope)
          }
          if (!disposed && current.wrapped && groupKey.current) {
            const next=await meetingCode(meeting,current,groupKey.current)
            if (acceptedCode.current && acceptedCode.current!==next) throw new Error('Protected transcript changed')
            if (!disposed) setCode(next)
          }
        }
        if (!disposed) {
          setState(current)
          timer=window.setTimeout(()=>void update(),2000)
        }
      } catch {
        if (!disposed) {
          setAccess(null)
          setCode('')
          if (groupKey.current) new Uint8Array(groupKey.current).fill(0)
          groupKey.current=null
          identity.current=null
          setClosed(true)
        }
      }
    }
    void update()
    return ()=>{disposed=true;window.clearTimeout(timer)}
  },[closed,exchange,meeting,started,user])

  useEffect(()=>()=>{
    if (groupKey.current) new Uint8Array(groupKey.current).fill(0)
    groupKey.current=null
    identity.current=null
  },[])

  async function prepare() {
    setMessage('')
    setBusy(true)
    try {
      if (!window.isSecureContext || !crypto.subtle || typeof RTCRtpScriptTransform==='undefined') {
        throw new Error('Protected meetings require browser support for encoded media transforms.')
      }
      identity.current=await meetingIdentity()
      setState(await exchange('key',{p_key:identity.current.publicKey}))
      setStarted(true)
    } catch(error) {
      identity.current=null
      setMessage(error instanceof Error ? error.message : 'Could not prepare encrypted media.')
    } finally { setBusy(false) }
  }

  async function verify() {
    setBusy(true)
    setMessage('')
    acceptedCode.current=code
    try { setState(await exchange('verify')) }
    catch {
      acceptedCode.current=''
      setMessage('The protection code could not be confirmed.')
    }
    finally { setBusy(false) }
  }

  async function join() {
    if (!state?.ready || !groupKey.current) return
    setBusy(true)
    setMessage('')
    try { setAccess({...await route(meeting,'token',device),roster:state.roster}) }
    catch { setMessage('Could not join protected media.') }
    finally { setBusy(false) }
  }

  return <section className="release-section" aria-label="Protected meeting">
    <h3>Protected meeting media</h3>
    {closed ? <p role="status">The protected roster is closed. Start a new meeting for a different roster.</p> : <>
      {!started && <button type="button" className="secondary" disabled={busy} onClick={()=>void prepare()}>Prepare encrypted media</button>}
      {started && !code && <p role="status">Waiting for admitted participants to prepare encrypted media.</p>}
      {code && <>
        <p>Group verification code <output aria-label="Group verification code">{code}</output></p>
        {!state?.verified && <>
          <p>Compare this code with every admitted participant in a separate trusted channel.</p>
          <button type="button" className="secondary" disabled={busy} onClick={()=>void verify()}>Group codes match</button>
        </>}
        {state?.verified && !state.ready && <p role="status">Waiting for everyone to confirm the group code.</p>}
        {state?.ready && !access && <button type="button" className="primary" disabled={busy} onClick={()=>void join()}>Join protected meeting media</button>}
      </>}
      {access && groupKey.current && <Media access={access} roster={access.roster} keyBytes={groupKey.current} close={closeMedia}/>}
    </>}
    {message && <p role="alert">{message}</p>}
  </section>
}
