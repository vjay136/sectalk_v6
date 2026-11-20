'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { db, transientAuthClient } from '../lib/data'
import { enrollCurrentDevice, refreshVerifiedSignIn } from '../lib/device-identity'
import { Brand } from './entry'

function verificationInput(email:string,value:string) {
  const credential=value.trim()
  if (/^[0-9]{6,10}$/.test(credential)) return {email,token:credential,type:'email' as const}
  const address=new URL(credential)
  const issuer=new URL(process.env.NEXT_PUBLIC_SUPABASE_URL!)
  const token=address.searchParams.get('token')
  if (address.origin!==issuer.origin||address.pathname!=='/auth/v1/verify'||
    !['email','magiclink'].includes(address.searchParams.get('type')??'')||
    !token||!/^[A-Za-z0-9_-]{20,200}$/.test(token)) throw new Error()
  return {token_hash:token,type:'email' as const}
}

export function LoginStepUp({email,refreshNeeded,hasLocalDevice,complete}:{
  email:string|null;refreshNeeded:boolean;hasLocalDevice:boolean;complete:()=>void
}) {
  const [challenge,setChallenge]=useState<string|null>(null)
  const [code,setCode]=useState('')
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const proof=useRef<ReturnType<typeof transientAuthClient>>(null)
  const refreshStarted=useRef(false)

  const refresh=useCallback(async()=>{
    setBusy(true)
    setError('')
    try {
      await refreshVerifiedSignIn()
      complete()
    } catch {setError('Could not refresh your verified sign-in. Try again.')}
    finally {setBusy(false)}
  },[complete])

  useEffect(()=>{
    if (!refreshNeeded||refreshStarted.current) return
    refreshStarted.current=true
    void refresh()
  },[refreshNeeded,refresh])

  async function verifyTrustedDevice() {
    if (busy) return
    setBusy(true)
    setError('')
    try {await enrollCurrentDevice({existingOnly:true});complete()}
    catch {setError('Could not verify this registered device. Use the email code to continue.')}
    finally {setBusy(false)}
  }

  async function send() {
    if (busy||!email) return
    setBusy(true)
    setError('')
    try {
      const reservation=await db!.rpc('st_v7_request_signin_code')
      if (reservation.error||!reservation.data) throw new Error()
      const client=transientAuthClient()
      const delivered=await client!.auth.signInWithOtp({email,options:{shouldCreateUser:false}})
      if (delivered.error) throw new Error()
      proof.current=client
      setChallenge(reservation.data)
    } catch {setError('Could not send a verification code. Try again shortly.')}
    finally {setBusy(false)}
  }

  async function verify(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy||!email||!challenge||!proof.current) return
    const client=proof.current
    setBusy(true)
    setError('')
    try {
      const result=await client.auth.verifyOtp(verificationInput(email,code))
      if (result.error) throw new Error()
      const confirmed=await client.rpc('st_v7_confirm_signin_code',{p_challenge:challenge})
      await client.auth.signOut({scope:'local'})
      if (confirmed.error||!confirmed.data) throw new Error()
      proof.current=null
      setChallenge(null)
      await refresh()
    } catch {setError('Could not verify this sign-in. Check the code or request a new one.')}
    finally {setBusy(false);setCode('')}
  }

  return <main className="center-page"><Brand/><section className="panel mfa-panel" aria-label="Sign-in verification">
    <h1>Verify this sign-in</h1>
    <p>SecTalk needs additional verification before opening your account.</p>
    {refreshNeeded?(busy?<p role="status">Finishing sign-in…</p>:
      <button type="button" onClick={()=>void refresh()}>Refresh verified sign-in</button>):<>
      {challenge&&<form className="release-form" onSubmit={verify}>
        <label>Email verification code or link<input autoComplete="one-time-code"
          maxLength={2048} required value={code} onChange={event=>setCode(event.target.value)}/></label>
        <button className="primary" disabled={busy}>Verify email code</button>
      </form>}
      <button className="secondary" type="button" disabled={busy||!email} onClick={()=>void send()}>
        {challenge?'Send a new code':'Send verification code'}
      </button>
      {hasLocalDevice&&<button className="secondary" type="button" disabled={busy} onClick={()=>void verifyTrustedDevice()}>
        Verify this trusted device
      </button>}
    </>}
    {error&&<p className="error" role="alert">{error}</p>}
    <button className="secondary" type="button" onClick={()=>void db!.auth.signOut({scope:'local'})}>Sign out</button>
  </section></main>
}
