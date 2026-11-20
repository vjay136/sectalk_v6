'use client'

import {useState,type FormEvent} from 'react'
import {db,transientAuthClient} from '../lib/data'
import {verifyAccountCredential} from '../lib/account-credential'

type Scope='billing'|'room_role'|'export'
type Method='password'|'totp'|'passkey'
type Pending={method:Method; run:()=>Promise<void>; scope:Scope}

export function useSensitiveAction() {
  const [pending,setPending]=useState<Pending|null>(null)
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')

  async function authorize(scope:Scope,run:()=>Promise<void>) {
    if (busy || pending) return
    setBusy(true)
    setError('')
    try {
      const result=await db!.rpc('st_v7_sensitive_action_status',{p_kind:scope})
      if (!result.error&&result.data==='verified') await run()
      else if (!result.error&&['password','totp','passkey'].includes(result.data)) {
        setPending({method:result.data,run,scope})
      } else setError('Your current session cannot authorize this action.')
    } catch {setError('Could not verify your current sign-in.')}
    finally {setBusy(false)}
  }

  async function submit(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy || !pending) return
    const form=event.currentTarget
    const secret=String(new FormData(form).get('action-proof')??'')
    setBusy(true)
    setError('')
    try {
      if (pending.method==='passkey') {
        const current=await db!.auth.getUser()
        const client=transientAuthClient()
        const result=await client!.auth.signInWithPasskey()
        if (current.error||result.error||!result.data.session||result.data.user?.id!==current.data.user?.id) throw new Error()
        const {access_token,refresh_token}=result.data.session
        if ((await db!.auth.setSession({access_token,refresh_token})).error) throw new Error()
      } else await verifyAccountCredential(secret,pending.method==='totp')
      const result=await db!.rpc('st_v7_sensitive_action_status',{p_kind:pending.scope})
      if (result.error||result.data!=='verified') throw new Error()
      setPending(null)
      await pending.run()
    } catch {setError('Verification failed. Check your credentials and try again.')}
    finally {form.reset();setBusy(false)}
  }

  const confirmation=<>
    {pending&&<form className="panel release-panel release-form" aria-label="Verify your current sign-in" onSubmit={submit}>
      <h3>Verify your current sign-in</h3>
      {pending.method!=='passkey'&&<label>{pending.method==='totp'?'Current authenticator code':'Current password'}
        <input name="action-proof" autoComplete={pending.method==='totp'?'one-time-code':'current-password'}
          type={pending.method==='totp'?'text':'password'} autoFocus required
          inputMode={pending.method==='totp'?'numeric':undefined}
          pattern={pending.method==='totp'?'[0-9]{6}':undefined} maxLength={pending.method==='totp'?6:256}/>
      </label>}
      <div className="actions"><button className="primary" disabled={busy} autoFocus={pending.method==='passkey'}>
        {pending.method==='passkey'?'Verify with a passkey':'Verify and continue'}</button>
        <button className="secondary" type="button" disabled={busy} onClick={()=>{setPending(null);setError('')}}>Cancel verification</button></div>
    </form>}
    {error&&<p className="error" role="alert">{error}</p>}
  </>
  return {authorize,confirmation}
}
