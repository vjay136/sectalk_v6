'use client'

import { useEffect, useState } from 'react'
import { rememberWorkspaceInvite } from '../../lib/workspace-invite'

export default function WorkspaceInvitationPage(){
  const [invalid,setInvalid]=useState(false)
  useEffect(()=>{
    const fragment=new URLSearchParams(location.hash.slice(1))
    const token=fragment.get('link')
    if(!token||!rememberWorkspaceInvite(token)){setInvalid(true);return}
    location.replace('/#account')
  },[])
  return <main className="content-page">
    <section className="panel release-panel">
      <h1>SecTalk workspace invitation</h1>
      {invalid?<><p role="alert">This invitation link could not be opened.</p><a href="/#account">Open SecTalk</a></>:
        <p role="status">Opening SecTalk…</p>}
    </section>
  </main>
}
