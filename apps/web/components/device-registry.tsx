'use client'

import { BrowserReputationLink } from './browser-reputation-link'
import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db } from '../lib/data'
import { verifyAccountCredential } from '../lib/account-credential'
import { enrollCurrentDevice } from '../lib/device-identity'
import { DeviceRemoteControls, type DeviceCommand } from './device-remote-controls'

type Trust = 'known' | 'trusted' | 'managed' | 'blocked'
type Device = {id: string;state: Trust;fingerprint: string;created_at: string;current_device: boolean;active_sessions: number}
type Decision = {device: Device;state: Exclude<Trust,'managed'>}
const labels = {known:'Known',trusted:'Trusted',managed:'Managed',blocked:'Blocked'}
const decisionLabels = {known:'Remove trust',trusted:'Trust device',blocked:'Block device'}

export function DeviceRegistry({hints}: {hints: EventTarget}) {
  const [rows,setRows]=useState<Device[]|null>(null)
  const [commands,setCommands]=useState<DeviceCommand[]>([])
  const [hasFactor,setHasFactor]=useState(false)
  const [decision,setDecision]=useState<Decision|null>(null)
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [feedback,setFeedback]=useState('')
  const load=useCallback(async()=>{
    const [registry,factors,remote]=await Promise.all([
      db!.rpc('st_v7_list_devices'),db!.auth.mfa.listFactors(),db!.rpc('st_v7_list_device_commands'),
    ])
    if (registry.error || factors.error || remote.error) {
      setError('Could not load the device trust registry.')
      return
    }
    setHasFactor(factors.data.totp.some(factor=>factor.status==='verified'))
    setRows(registry.data as Device[])
    setCommands(remote.data as DeviceCommand[])
  },[])

  useEffect(()=>{
    void load()
    const reload=()=>void load()
    hints.addEventListener('device_registry',reload)
    hints.addEventListener('session_lifecycle',reload)
    return ()=>{
      hints.removeEventListener('device_registry',reload)
      hints.removeEventListener('session_lifecycle',reload)
    }
  },[hints,load])

  async function enroll() {
    if (busy) return
    setBusy(true)
    setError('')
    setFeedback('')
    try {
      await enrollCurrentDevice()
      await load()
      setFeedback('Device registered.')
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Could not register this device.')
    } finally {setBusy(false)}
  }

  async function changeTrust(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!decision || busy) return
    const form=event.currentTarget
    const fields=new FormData(form)
    setBusy(true)
    setError('')
    setFeedback('')
    try {
      await verifyAccountCredential(String(fields.get('verification')??''),hasFactor)
      // Password reauthentication creates a new native session.
      if (!hasFactor) await enrollCurrentDevice()
      const result=await db!.rpc('st_v7_set_device_trust',{p_device:decision.device.id,p_state:decision.state})
      if (result.error || !result.data) throw new Error()
      if (decision.state==='blocked' && decision.device.current_device) {
        await db!.auth.signOut({scope:'local'})
        return
      }
      setDecision(null)
      await load()
      setFeedback('Device trust updated.')
    } catch {
      setError('Could not change device trust. Check your credentials and use an existing trusted device to approve another device.')
    } finally {
      form.reset()
      setBusy(false)
    }
  }

  const current=rows?.find(row=>row.current_device)
  return <section className="panel release-panel" aria-label="Device trust">
    <div className="panel-header"><h2>Device trust</h2>
      <button type="button" className="secondary" onClick={()=>{setError('');void load()}} disabled={busy}>Refresh device trust</button>
    </div>
    {error && <p className="error" role="alert">{error}</p>}
    {feedback && <p role="status">{feedback}</p>}
    {!rows && !error && <p role="status">Loading device trust…</p>}
    {rows && !current && <>
      <p>This device is unknown. Register it to create a device key bundle in this browser.</p>
      <button className="secondary" type="button" disabled={busy} onClick={()=>void enroll()}>Register this device</button>
    </>}
    {rows?.map(device=><article className="release-board-item" key={device.id}>
      <div className="release-row"><strong>{labels[device.state]}</strong>{device.current_device && <span>This registered device</span>}</div>
      <p>Fingerprint <code>{device.fingerprint.match(/.{4}/g)?.join(' ')}</code></p>
      <p>{device.active_sessions} active {device.active_sessions===1?'session':'sessions'}</p>
      <div className="actions">
        {device.state==='known' && <button className="secondary" type="button" disabled={busy}
          onClick={()=>setDecision({device,state:'trusted'})}>Trust device</button>}
        {device.state==='trusted' && <button className="secondary" type="button" disabled={busy}
          onClick={()=>setDecision({device,state:'known'})}>Remove trust</button>}
        {device.state!=='blocked' && <button className="secondary" type="button" disabled={busy}
          onClick={()=>setDecision({device,state:'blocked'})}>Block device</button>}
      </div>
      {decision?.device.id===device.id && <form className="release-form" onSubmit={changeTrust}>
        {decision.state==='blocked' && <p>Blocking this device ends all its linked sessions and removes its bundle from the trusted directory.</p>}
        <label>{hasFactor?'Current authenticator code':'Current password'}<input name="verification" required
          type={hasFactor?'text':'password'} autoComplete={hasFactor?'one-time-code':'current-password'}
          inputMode={hasFactor?'numeric':undefined} pattern={hasFactor?'[0-9]{6}':undefined}/></label>
        <div className="actions"><button className="primary" disabled={busy}>Confirm {decisionLabels[decision.state].toLowerCase()}</button>
          <button className="secondary" type="button" disabled={busy} onClick={()=>setDecision(null)}>Cancel trust change</button></div>
      </form>}
      {commands.filter(command=>command.device===device.id).map(command=><DeviceRemoteControls key={command.device}
        status={command} hasFactor={hasFactor} hasRegisteredDevice={Boolean(current)} onChange={load}/>)}
    </article>)}
    {(current?.state === 'trusted' || current?.state === 'managed') && <BrowserReputationLink key={current.id}/>}
  </section>
}
