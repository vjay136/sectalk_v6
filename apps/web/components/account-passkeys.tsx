'use client'

import {useCallback,useEffect,useState,type FormEvent} from 'react'
import type {PasskeyListItem} from '@supabase/supabase-js'
import {db} from '../lib/data'

export function AccountPasskeys() {
  const [rows,setRows]=useState<PasskeyListItem[]|null>(null)
  const [passwordless,setPasswordless]=useState(false)
  const [rename,setRename]=useState<string|null>(null)
  const [remove,setRemove]=useState<string|null>(null)
  const [confirmMode,setConfirmMode]=useState(false)
  const [busy,setBusy]=useState(false)
  const [message,setMessage]=useState('')
  const [error,setError]=useState('')
  const load=useCallback(async()=>{
    const [list,mode]=await Promise.all([db!.auth.passkey.list(),db!.rpc('st_v7_passkey_only')])
    if (list.error||mode.error) {
      setError('Could not load your passkeys.')
      return
    }
    setRows(list.data)
    setPasswordless(mode.data)
  },[])
  useEffect(()=>{if (window.PublicKeyCredential) void load()},[load])

  async function act(operation:()=>Promise<void>,success:string,problem:string) {
    if (busy) return
    setBusy(true)
    setError('')
    setMessage('')
    try {
      await operation()
      setRename(null)
      setRemove(null)
      setConfirmMode(false)
      setMessage(success)
      await load()
    } catch {setError(problem)}
    finally {setBusy(false)}
  }

  function register() {
    void act(async()=>{
      const result=await db!.auth.registerPasskey()
      if (result.error) throw result.error
    },'Passkey registered.','Could not register a passkey.')
  }

  function update(event:FormEvent<HTMLFormElement>,id:string) {
    event.preventDefault()
    const friendlyName=String(new FormData(event.currentTarget).get('passkey-name')??'').trim()
    if (!friendlyName) return
    void act(async()=>{
      const result=await db!.auth.passkey.update({passkeyId:id,friendlyName})
      if (result.error) throw result.error
    },'Passkey renamed.','Could not rename the passkey.')
  }

  function deletePasskey(id:string) {
    void act(async()=>{
      const result=await db!.auth.passkey.delete({passkeyId:id})
      if (result.error) throw result.error
    },'Passkey removed.','Could not remove the passkey.')
  }

  function changeMode() {
    const p_enabled=!passwordless
    void act(async()=>{
      const result=await db!.rpc('st_v7_passkey_only',{p_enabled})
      if (result.error||result.data!==p_enabled) throw new Error()
    },p_enabled?'Passwordless-only sign-in enabled.':'Password sign-in restored.',
    'Sign out and sign in with a passkey before changing this setting.')
  }

  if (!rows && !error) return null
  return <section className="panel mfa-panel" aria-label="Passkeys">
    <h2>Passkeys</h2>
    <button type="button" className="secondary" disabled={busy||!rows} onClick={register}>Register a passkey</button>
    {rows?.map(item=><article className="release-board-item" key={item.id}>
      <strong>{item.friendly_name||'Passkey'}</strong>
      {item.last_used_at&&<p>Last used {new Date(item.last_used_at).toLocaleString()}</p>}
      <div className="actions">
        <button type="button" className="secondary" disabled={busy} onClick={()=>{setRename(item.id);setRemove(null)}}>Rename passkey</button>
        <button type="button" className="secondary" disabled={busy||(passwordless&&rows.length===1)}
          onClick={()=>{setRemove(item.id);setRename(null)}}>Remove passkey</button>
      </div>
      {rename===item.id&&<form onSubmit={event=>update(event,item.id)}>
        <label>Passkey name<input name="passkey-name" defaultValue={item.friendly_name} maxLength={120} required/></label>
        <button disabled={busy}>Save passkey name</button>
        <button type="button" className="secondary" onClick={()=>setRename(null)}>Cancel</button>
      </form>}
      {remove===item.id&&<div className="actions">
        <button type="button" className="danger" disabled={busy} onClick={()=>deletePasskey(item.id)}>Confirm passkey removal</button>
        <button type="button" className="secondary" onClick={()=>setRemove(null)}>Cancel</button>
      </div>}
    </article>)}
    {rows&&rows.length>0&&<>
      <p>{passwordless?'Passwordless-only sign-in is on. Keep at least one passkey.':'Password sign-in is available.'}</p>
      {!confirmMode&&<button type="button" className="secondary" disabled={busy} onClick={()=>setConfirmMode(true)}>
        {passwordless?'Restore password sign-in':'Use passwordless-only sign-in'}
      </button>}
      {confirmMode&&<div>
        <p>{passwordless?'This restores password sign-in.':'This ends sessions that did not sign in with a passkey and turns off password-based recovery. Save a spare passkey before continuing.'}</p>
        <button type="button" disabled={busy} onClick={changeMode}>{passwordless?'Confirm password sign-in':'Confirm passwordless-only sign-in'}</button>
        <button type="button" className="secondary" onClick={()=>setConfirmMode(false)}>Cancel</button>
      </div>}
    </>}
    {error&&<p role="alert">{error}</p>}
    {message&&<p role="status">{message}</p>}
  </section>
}
