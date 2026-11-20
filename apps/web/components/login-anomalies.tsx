'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db } from '../lib/data'
import { verifyAccountCredential } from '../lib/account-credential'
import { enrollCurrentDevice } from '../lib/device-identity'
import { Brand } from './entry'

type Anomaly={id:string;observed_at:string;detected_at:string;state:'pending'|'recognized'|'locked'|'recovered'}
type Review={id:string;action:'recognize'|'lockdown'}
export type AccountLock={locked:boolean;ready_at?:string;password_verified?:boolean}

const labels={pending:'Needs review',recognized:'Recognized',locked:'Account locked',recovered:'Account recovered'}

export function LoginAnomalies({hints,hasFactor}: {hints:EventTarget;hasFactor:boolean}) {
  const [rows,setRows]=useState<Anomaly[]|null>(null)
  const [review,setReview]=useState<Review|null>(null)
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [feedback,setFeedback]=useState('')
  const load=useCallback(async()=>{
    const {data,error}=await db!.rpc('st_v7_list_login_anomalies')
    if (error) setError('Could not load sign-in alerts.')
    else setRows(data as Anomaly[])
  },[])
  useEffect(()=>{
    void load()
    const reload=()=>void load()
    hints.addEventListener('login_anomaly',reload)
    return ()=>hints.removeEventListener('login_anomaly',reload)
  },[hints,load])

  async function submit(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!review||busy) return
    const form=event.currentTarget
    setBusy(true)
    setError('')
    try {
      await verifyAccountCredential(String(new FormData(form).get('credential')??''),hasFactor)
      await enrollCurrentDevice()
      const result=await db!.rpc('st_v7_review_login_anomaly',{p_anomaly:review.id,p_action:review.action})
      if (result.error||!result.data) throw new Error()
      if (review.action==='lockdown') {
        await db!.auth.signOut({scope:'local'})
        return
      }
      setReview(null)
      setFeedback('Sign-in marked as recognized.')
      await load()
    } catch {setError('Could not review this sign-in. Verify your credentials on a device you trusted before the alert.')}
    finally {setBusy(false);form.reset()}
  }

  return <section className="panel release-panel" aria-label="Sign-in alerts">
    <div className="panel-header"><h2>Sign-in alerts</h2><button className="secondary" type="button"
      disabled={busy} onClick={()=>{setError('');void load()}}>Refresh sign-in alerts</button></div>
    {rows?.length===0&&<p>No unusual sign-ins to review.</p>}
    {!rows&&!error&&<p role="status">Loading sign-in alerts…</p>}
    {error&&<p className="error" role="alert">{error}</p>}
    {feedback&&<p role="status">{feedback}</p>}
    {rows?.map(row=><article className="release-board-item" key={row.id}>
      <strong>Unusual sign-in</strong><p>Both the browser family and network differed from your trusted devices.</p>
      <p>{labels[row.state]} · <time dateTime={row.observed_at}>{new Date(row.observed_at).toLocaleString()}</time></p>
      {row.state==='pending'&&<div className="actions">
        <button className="secondary" type="button" disabled={busy}
          onClick={()=>{setError('');setReview({id:row.id,action:'recognize'})}}>I recognize this sign-in</button>
        <button className="secondary" type="button" disabled={busy}
          onClick={()=>{setError('');setReview({id:row.id,action:'lockdown'})}}>This wasn’t me</button>
      </div>}
      {review?.id===row.id&&<form className="release-form" onSubmit={submit}>
        {review.action==='lockdown'&&<p>Locking ends every session. To restore access, complete email password recovery and verify a previously trusted device after the 15-minute hold.</p>}
        <label>{hasFactor?'Current authenticator code':'Current password'}<input name="credential" required
          type={hasFactor?'text':'password'} autoComplete={hasFactor?'one-time-code':'current-password'}
          inputMode={hasFactor?'numeric':undefined} pattern={hasFactor?'[0-9]{6}':undefined}/></label>
        <div className="actions">
          <button className="primary" disabled={busy}>{review.action==='lockdown'?'Verify and lock account':'Verify and recognize sign-in'}</button>
          <button className="secondary" disabled={busy} type="button" onClick={()=>setReview(null)}>Cancel sign-in review</button>
        </div>
      </form>}
    </article>)}
  </section>
}

export function AccountLockdownScreen({status,refresh,startRecovery}: {
  status:AccountLock;refresh:()=>void;startRecovery:()=>void
}) {
  const [hasFactor,setHasFactor]=useState(false)
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [clock,setClock]=useState(Date.now)
  useEffect(()=>{
    let active=true
    void db!.auth.mfa.listFactors().then(({data,error})=>{
      if (active&&!error) setHasFactor(data.totp.some(factor=>factor.status==='verified'))
    })
    const timer=window.setInterval(()=>setClock(Date.now()),10000)
    return ()=>{ active=false;window.clearInterval(timer) }
  },[])
  async function restore(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    const form=event.currentTarget
    setBusy(true)
    setError('')
    try {
      await verifyAccountCredential(String(new FormData(form).get('credential')??''),hasFactor)
      await enrollCurrentDevice()
      const result=await db!.rpc('st_v7_recover_account_lockdown')
      if (result.error||!result.data) throw new Error()
      refresh()
    } catch {setError('Could not restore access. Complete all recovery steps on a previously trusted device.')}
    finally {setBusy(false);form.reset()}
  }

  return <main className="center-page"><Brand/><section className="panel mfa-panel" aria-label="Account lockdown">
    <h1>Your account is locked</h1>
    <p>Change your password using the code sent to your email. Then sign in on a previously trusted device.</p>
    {status.ready_at&&<p>Recovery is available after <time dateTime={status.ready_at}>{new Date(status.ready_at).toLocaleString()}</time>.</p>}
    {status.password_verified?<p>Password recovery verified.</p>:<button type="button" className="secondary" onClick={startRecovery}>Start email password recovery</button>}
    {status.password_verified&&status.ready_at&&Date.parse(status.ready_at)<=clock&&<form className="release-form" onSubmit={restore}>
      <label>{hasFactor?'Current authenticator code':'Current password'}<input name="credential" required
        type={hasFactor?'text':'password'} autoComplete={hasFactor?'one-time-code':'current-password'}
        inputMode={hasFactor?'numeric':undefined} pattern={hasFactor?'[0-9]{6}':undefined}/></label>
      <button className="primary" disabled={busy}>Verify and restore account access</button>
    </form>}
    {error&&<p className="error" role="alert">{error}</p>}
    <button type="button" className="secondary" onClick={refresh}>Refresh account recovery status</button>
    <button type="button" className="secondary" onClick={()=>void db!.auth.signOut({scope:'local'})}>Sign out</button>
  </section></main>
}
