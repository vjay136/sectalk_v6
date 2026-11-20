'use client'

import { useEffect, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'
import { clearWorkspaceInvite, pendingWorkspaceInvite } from '../lib/workspace-invite'

export function PendingWorkspaceInvite({onJoined}:{onJoined:(workspace:string)=>Promise<void>}){
  const [token,setToken]=useState<string|null>(null)
  const [working,setWorking]=useState(false)
  const [info,setInfo]=useState('')
  useEffect(()=>setToken(pendingWorkspaceInvite()),[])
  async function accept(){
    if(!token||working)return
    setWorking(true)
    setInfo('')
    const result=await db!.rpc('st_v6_workspace_link_accept',{p_token:token})
    if(result.error)setInfo('This invitation is unavailable. Make sure you signed in with the invited email and the link is still valid.')
    else{
      clearWorkspaceInvite()
      setToken(null)
      await onJoined(result.data as string)
      setInfo('Workspace invitation accepted.')
    }
    setWorking(false)
  }
  if(!token&&!info)return null
  return <section className="panel release-panel" aria-labelledby="pending-link-heading">
    <h2 id="pending-link-heading">Workspace invitation link</h2>
    {info&&<p role={token?'alert':'status'}>{info}</p>}
    {token&&<>
      <p>Accept using the SecTalk account registered to the invited email.</p>
      <div className="action-row">
        <button type="button" className="primary" disabled={working} onClick={()=>void accept()}>Accept invitation link</button>
        <button type="button" className="secondary" disabled={working} onClick={()=>{
          clearWorkspaceInvite();setToken(null);setInfo('')
        }}>Dismiss invitation link</button>
      </div>
    </>}
  </section>
}

export function WorkspaceLinkInvites({workspace,profile}:{workspace:string;profile?:{invite_hours:number;require_domains:boolean}|null}){
  const [domains,setDomains]=useState<string|null>(null)
  const [issued,setIssued]=useState<{url:string;email:string;expires:string}|null>(null)
  const [message,setMessage]=useState('')
  const [error,setError]=useState('')
  const [working,setWorking]=useState(false)
  const expiries=[{hours:24,label:'24 hours'},{hours:72,label:'3 days'},{hours:168,label:'7 days'}]
    .filter(option=>option.hours<=(profile?.invite_hours??168))
  useEffect(()=>{
    let active=true
    void db!.rpc('st_v6_workspace_link_policy_get',{p_workspace:workspace}).then(result=>{
      if(!active)return
      if(result.error)setError('Could not load invitation policy.')
      else setDomains((result.data as string[]).join(', '))
    })
    return()=>{active=false}
  },[workspace])
  async function savePolicy(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    if(working||domains===null)return
    setWorking(true);setError('');setMessage('')
    const {error}=await db!.rpc('st_v6_workspace_link_policy_set',{
      p_workspace:workspace,p_domains:domains.split(',').map(domain=>domain.trim()).filter(Boolean),
    })
    if(error)setError(formatError(error,'Could not save the invitation policy.'))
    else setMessage('Invitation domain policy saved.')
    setWorking(false)
  }
  async function issue(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    if(working)return
    const form=new FormData(event.currentTarget)
    const email=String(form.get('email')||'').trim().toLowerCase()
    const hours=Number(form.get('hours'))
    const sendEmail=(event.nativeEvent as SubmitEvent).submitter?.getAttribute('data-email')==='true'
    setWorking(true);setError('');setMessage('');setIssued(null)
    try{
      if(sendEmail){
        const {data:{session}}=await db!.auth.getSession()
        if(!session)throw new Error('Sign in again to send your invitation.')
        const response=await fetch('/api/workspaces/invitations',{
          method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+session.access_token},
          body:JSON.stringify({workspace,email,hours}),
        })
        const result=await response.json()
        if(!response.ok)throw new Error(result.error)
        setIssued({url:result.url,email,expires:result.expires})
        if(result.delivered)setMessage('Invitation email sent.')
        else setError('The invitation link is ready. Email delivery failed, so share the link directly.')
      }else{
        const {data,error}=await db!.rpc('st_v6_workspace_link_create',{
          p_workspace:workspace,p_email:email,p_hours:hours,
        })
        if(error)throw error
        const result=data as {token:string;expires_at:string}
        const url=new URL('/invite',window.location.origin)
        url.hash=new URLSearchParams({link:result.token}).toString()
        setIssued({url:url.href,email,expires:result.expires_at})
      }
    }catch(error){
      setError(formatError(error,'Could not create the invitation.'))
    }finally{
      setWorking(false)
    }
  }
  return <details className="release-create">
    <summary>Email invitation links</summary>
    {profile?.require_domains&&<p>Save at least one approved email domain before creating an invitation link.</p>}
    {error&&<p role="alert" className="error">{error}</p>}
    {message&&<p role="status">{message}</p>}
    {domains!==null&&<form className="release-form" onSubmit={savePolicy}>
      <label>Allowed email domains<input value={domains} onChange={event=>setDomains(event.target.value)}
        maxLength={2000} placeholder="example.com, example.org"/></label>
      <button type="submit" className="secondary" disabled={working}>Save invitation policy</button>
    </form>}
    <form className="release-form" onSubmit={issue}>
      <label>Invited email<input name="email" type="email" maxLength={254} required/></label>
      <label>Expiry<select name="hours" aria-label="Expiry">{expiries.map(option=>
        <option value={option.hours} key={option.hours}>{option.label}</option>)}</select></label>
      <div className="action-row">
        <button type="submit" className="secondary" disabled={working||domains===null}>Create single-use link</button>
        <button type="submit" data-email="true" className="primary" disabled={working||domains===null}>Send invitation email</button>
      </div>
    </form>
    {issued&&<div className="release-form">
      <label>Invitation link<input value={issued.url} readOnly/></label>
      <p>Expires <time dateTime={issued.expires}>{new Date(issued.expires).toLocaleString()}</time></p>
      <div className="action-row">
        <button type="button" className="secondary" onClick={async()=>{
          try{await navigator.clipboard.writeText(issued.url);setMessage('Invitation link copied.')}
          catch{setMessage('Select the invitation link to copy it.')}
        }}>Copy link</button>
        <a className="secondary" href={'mailto:'+encodeURIComponent(issued.email)+'?subject='+
          encodeURIComponent('SecTalk workspace invitation')+'&body='+encodeURIComponent(issued.url)}>Open email draft</a>
      </div>
    </div>}
  </details>
}
