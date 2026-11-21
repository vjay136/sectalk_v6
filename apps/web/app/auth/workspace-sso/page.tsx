'use client'

import { useEffect, useRef, useState } from 'react'
import { db } from '../../../lib/data'
import { takeWorkspaceSsoLink } from '../../../lib/workspace-link'

export default function WorkspaceSsoReturn(){
  const [status,setStatus]=useState<'working'|'error'|'done'>('working')
  const submitted=useRef(false)
  const [returnPath,setReturnPath]=useState('/')
  useEffect(()=>{
    if(submitted.current)return
    submitted.current=true
    const next=takeWorkspaceSsoLink()
    setReturnPath(next)
    const code=new URLSearchParams(window.location.search).get('code')
    window.history.replaceState(null,'','/auth/workspace-sso')
    if(!code||!db){setStatus('error');return}
    void (async()=>{
      try{
        const response=await fetch('/api/auth/workspace-sso',{method:'POST',headers:{'Content-Type':'application/json'},
          body:JSON.stringify({action:'complete',code})})
        if(!response.ok)throw new Error()
        const result=await response.json()
        const signed=await db.auth.setSession({access_token:result.access_token,refresh_token:result.refresh_token})
        if(signed.error||!signed.data.user)throw new Error()
        try{localStorage.setItem('sectalk.workspace.v1:'+signed.data.user.id,result.workspace)}catch{/* The workspace remains available. */}
        setStatus('done')
        window.location.assign(next)
      }catch{setStatus('error')}
    })()
  },[])
  return <main className="center-page">
    <section className="auth-card" aria-label="Workspace sign-in">
      <h1>Workspace sign-in</h1>
      {status==='error'?<><p role="alert">Workspace sign-in could not be completed. Return to sign in and try again.</p>
        <a href={returnPath+'#account'}>Back to sign in</a></>:<p role="status">{status==='done'?'Opening SecTalk…':'Verifying your organization session…'}</p>}
    </section>
  </main>
}
