'use client'

import {useEffect,useState,type FormEvent} from 'react'
import {verifyAccountCredential} from '../lib/account-credential'
import {db,formatError} from '../lib/data'

type Consent='inactive'|'ready'|'approved'

export function WorkspaceResidencyBoardAuthor({workspace,scope='board'}:{workspace:string;scope?:'board'|'channels'}) {
  const channels=scope==='channels'
  const rpcName=channels?'st_v8_residency_channel_author_consent':'st_v8_residency_board_author_consent'
  const title=channels?'My chat message recovery':'My Board task recovery'
  const content=channels?'chat messages':'Board tasks'
  const approvalKind=channels?'chat':'task'
  const [state,setState]=useState<Consent>('inactive')
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')

  useEffect(()=>{
    const controller=new AbortController()
    void db!.rpc(rpcName,{p_workspace:workspace}).abortSignal(controller.signal).then(result=>{
      if(!controller.signal.aborted&&!result.error)setState(result.data as Consent)
    })
    return ()=>controller.abort()
  },[workspace,rpcName])

  async function submit(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    if(busy)return
    const form=event.currentTarget
    const fields=new FormData(form)
    const confirmation=String(fields.get('workspace')||'')
    setBusy(true);setError('')
    try {
      if(confirmation!==workspace)throw new Error('Enter the exact workspace ID shown above.')
      const assurance=await db!.rpc('st_v7_sensitive_action_status',{p_kind:'room_role'})
      if(assurance.error)throw assurance.error
      if(assurance.data!=='verified'){
        const code=String(fields.get('code')||'')
        if(!code)throw new Error('Enter a current authenticator code.')
        await verifyAccountCredential(code,true)
      }
      const result=await db!.rpc(rpcName,{
        p_workspace:workspace,p_action:state==='approved'?'revoke':'approve',p_confirmation:confirmation,
      })
      if(result.error)throw result.error
      setState(result.data as Consent)
      form.reset()
    } catch(cause){setError(formatError(cause,`Could not update your ${approvalKind} recovery approval.`))}
    finally{setBusy(false)}
  }

  if(state==='inactive')return null
  return <section className="release-section" aria-label={title}>
    <h3>{title}</h3>
    <p>Approve on both workspace installations using accounts with the same verified email. SecTalk can then restore reviewed {content} under your own name.</p>
    {state==='approved'&&<p role="status">{channels?'Your chat message recovery approval is recorded.':'Your Board task recovery approval is recorded.'}</p>}
    <form className="release-form" onSubmit={event=>void submit(event)}>
      <p>Workspace ID <code>{workspace}</code></p>
      <label>{`Confirm my ${channels?'chat':'Board'} recovery workspace ID`}<input name="workspace" required autoComplete="off" disabled={busy}/></label>
      <label>Authenticator code if prompted<input name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" disabled={busy}/></label>
      <button className="secondary" type="submit" disabled={busy}>{state==='approved'?
        `Withdraw my ${approvalKind} recovery approval`:`Approve my ${approvalKind} recovery`}</button>
    </form>
    {error&&<p role="alert">{error}</p>}
  </section>
}
