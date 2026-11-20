'use client'

import { useEffect, useState, type FormEvent } from 'react'
import { db } from '../lib/data'
import { receiveDeviceCommands, type DeviceProtection } from '../lib/device-commands'
import { enrollCurrentDevice } from '../lib/device-identity'
import { verifyAccountCredential } from '../lib/account-credential'
import { Brand } from './entry'

export function useDeviceProtection(user?:string) {
  const [snapshot,setSnapshot]=useState<{user?:string;value:DeviceProtection;checked:boolean}>({value:null,checked:false})
  const [version,setVersion]=useState(0)
  useEffect(()=>{
    let active=true
    let busy=false
    async function check() {
      if (busy || document.visibilityState==='hidden') return
      busy=true
      try {
        const value=await receiveDeviceCommands(user)
        if (!active) return
        setSnapshot({user,value,checked:true})
        if (user&&value?.wiped) void db!.auth.signOut({scope:'local'})
      } catch {
        if (active) setSnapshot({user,value:null,checked:true})
      } finally {busy=false}
    }
    void check()
    const interval=window.setInterval(check,10000)
    document.addEventListener('visibilitychange',check)
    window.addEventListener('online',check)
    window.addEventListener('sectalk-device-command',check)
    return ()=>{
      active=false
      window.clearInterval(interval)
      document.removeEventListener('visibilitychange',check)
      window.removeEventListener('online',check)
      window.removeEventListener('sectalk-device-command',check)
    }
  },[user,version])
  return {checked:snapshot.user===user&&snapshot.checked,value:snapshot.user===user?snapshot.value:null,
    refresh:()=>setVersion(value=>value+1)}
}

export function DeviceLockScreen({device,unavailable,blocked,refresh}: {
  device:string;unavailable:boolean;blocked?:boolean;refresh:()=>void
}) {
  const [hasFactor,setHasFactor]=useState<boolean|null>(null)
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  useEffect(()=>{
    if (blocked||unavailable) return
    let active=true
    void db!.auth.mfa.listFactors().then(({data,error})=>{
      if (!active) return
      if (error) setError('Could not load account verification.')
      else setHasFactor(data.totp.some(factor=>factor.status==='verified'))
    })
    return ()=>{active=false}
  },[blocked,unavailable])
  async function unlock(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy||hasFactor===null) return
    const form=event.currentTarget
    const credential=String(new FormData(form).get('credential')??'')
    setBusy(true)
    setError('')
    try {
      await verifyAccountCredential(credential,hasFactor)
      const result=await db!.rpc('st_v7_issue_device_command',{p_device:device,p_action:'unlock'})
      if (result.error||!result.data) throw new Error()
      await enrollCurrentDevice()
      refresh()
    } catch {setError('Could not unlock this device. Check your account credentials and device status.')}
    finally {setBusy(false);form.reset()}
  }
  return <main className="center-page"><Brand/><section className="panel mfa-panel">
    <h1>{blocked?'This registered device is blocked':unavailable?'Check device access':'This registered device is locked'}</h1>
    <p>{blocked?'Continue on another device.':unavailable?'Reconnect to verify the status of this browser’s registered keys.':'Verify your account credentials to unlock this device.'}</p>
    {!blocked&&!unavailable&&hasFactor!==null&&<form className="release-form" onSubmit={unlock}>
      <label>{hasFactor?'Current authenticator code':'Current password'}<input name="credential" type={hasFactor?'text':'password'}
        autoComplete={hasFactor?'one-time-code':'current-password'} inputMode={hasFactor?'numeric':undefined}
        pattern={hasFactor?'[0-9]{6}':undefined} required/></label>
      <button disabled={busy}>Verify and unlock device</button>
    </form>}
    {error&&<p className="error" role="alert">{error}</p>}
    <button className="secondary" type="button" disabled={busy} onClick={refresh}>Check device status</button>
    <button className="secondary" type="button" disabled={busy} onClick={()=>void db!.auth.signOut({scope:'local'})}>Sign out</button>
  </section></main>
}
