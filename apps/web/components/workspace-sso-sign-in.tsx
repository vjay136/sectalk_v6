'use client'

import { useState, type FormEvent } from 'react'
import { rememberWorkspaceSsoLink } from '../lib/workspace-link'
import { isFreeRelease } from '../lib/release-scope'

export function WorkspaceSsoSignIn({workspace}:{workspace?:string}={}) {
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  async function start(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    if(busy)return
    const domain=String(new FormData(event.currentTarget).get('domain')??'')
    setBusy(true);setError('')
    try{
      const response=await fetch('/api/auth/workspace-sso',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({action:'start',domain})})
      const result=await response.json()
      if(!response.ok||typeof result.destination!=='string')throw new Error()
      rememberWorkspaceSsoLink(workspace?new URLSearchParams({workspace}).toString():window.location.search)
      window.location.assign(result.destination)
    }catch{setError('Workspace sign-in is unavailable. Check the domain or contact your administrator.');setBusy(false)}
  }
  return <details className="release-create">
    <summary>Sign in with workspace SSO</summary>
    {isFreeRelease&&!workspace ? <p role="status">Enterprise SSO is planned for a future release. Use email and password for standard workspaces.</p> :
    <form className="release-form" onSubmit={event=>void start(event)}>
      <label>Workspace email domain<input name="domain" dir="ltr" placeholder="example.org" required maxLength={225} autoComplete="off"/></label>
      <button type="submit" className="secondary" disabled={busy}>{busy?'Opening workspace sign-in…':'Continue with workspace SSO'}</button>
      {error&&<p role="alert">{error}</p>}
    </form>}
  </details>
}
