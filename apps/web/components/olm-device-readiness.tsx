'use client'

import {useEffect,useState} from 'react'
import {getApprovedOlmDevice,prepareApprovedOlmDevice} from '../lib/olm-browser'

export function OlmDeviceReadiness({user,hints}:{user:string;hints:EventTarget}) {
  const [available,setAvailable]=useState(false)
  const [ready,setReady]=useState(false)
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')

  useEffect(()=>{
    let subscribed=true
    const update=()=>void getApprovedOlmDevice(user).then(approval=>{
      if (!subscribed)return
      setAvailable(Boolean(approval))
      setReady(Boolean(approval?.bundle))
    }).catch(()=>{if (subscribed)setAvailable(false)})
    update()
    hints.addEventListener('device_registry',update)
    return ()=>{subscribed=false;hints.removeEventListener('device_registry',update)}
  },[user,hints])

  async function prepare() {
    setBusy(true)
    setError('')
    try {
      const configured=await prepareApprovedOlmDevice(user)
      if (!configured) throw new Error('The browser did not finish preparing its encryption keys.')
      setReady(true)
    } catch (cause) {
      setError(cause instanceof Error?cause.message:'Could not prepare this browser.')
    } finally {
      setBusy(false)
    }
  }

  if (!available)return null
  return <section className="release-section" aria-label="Secure conversation keys">
    <h2>Secure conversation keys</h2>
    <p>Prepare the encryption keys stored in this approved browser.</p>
    <button type="button" className="secondary" onClick={()=>void prepare()} disabled={busy||ready}>
      {busy?'Preparing encryption keys…':'Prepare this browser'}
    </button>
    {ready&&<p role="status">This approved browser has published its encryption keys.</p>}
    {error&&<p role="alert">{error}</p>}
  </section>
}
