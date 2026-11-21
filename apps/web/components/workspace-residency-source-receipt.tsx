'use client'

import {useEffect,useState,type FormEvent} from 'react'
import {verifyAccountCredential} from '../lib/account-credential'
import {db,formatError} from '../lib/data'

type VerifiedReceipt={id:string;checkedAt:string;reviewedAt:string;expiresAt:string;
  counts:{matched:number;missing:number;changed:number;check_bytes:number;unsupported:number}}
type Review={role:'owner'|'reviewer';receipt:VerifiedReceipt|null}

export function WorkspaceResidencySourceReceipt({workspace,approval}:{workspace:string;approval:string}) {
  const [state,setState]=useState<Review>()
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')

  useEffect(()=>{
    const abort=new AbortController()
    void db!.rpc('st_v8_residency_review_comparison_receipt',{p_workspace:workspace,p_approval:approval})
      .abortSignal(abort.signal).then(({data,error})=>{
        if(!abort.signal.aborted&&!error)setState(data as Review)
      })
    return ()=>abort.abort()
  },[workspace,approval])

  async function review(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    if(busy||state?.role!=='reviewer')return
    const form=event.currentTarget
    const values=new FormData(form)
    setBusy(true);setError('')
    try {
      const proof=JSON.parse(String(values.get('proof')||''))
      if(typeof proof?.payload!=='string'||typeof proof?.signature!=='string')throw new Error('Paste a destination comparison receipt.')
      const {data,error}=await db!.rpc('st_v7_sensitive_action_status',{p_kind:'room_role'})
      if(error)throw error
      if(data!=='verified'){
        const code=String(values.get('code')||'')
        if(!code)throw new Error('Enter a current authenticator code to review the receipt.')
        await verifyAccountCredential(code,true)
      }
      const result=await db!.rpc('st_v8_residency_review_comparison_receipt',{
        p_workspace:workspace,p_approval:approval,p_proof:proof,
      })
      if(result.error)throw result.error
      setState(result.data as Review)
      form.reset()
    } catch(cause){setError(formatError(cause,'The receipt could not be verified for this approval.'))}
    finally{setBusy(false)}
  }

  if(!state)return null
  const receipt=state.receipt
  return <section className="release-section" aria-label="Destination comparison review">
    <h4>Destination comparison review</h4>
    {receipt&&<>
      <p role="status">Destination receipt accepted at {new Date(receipt.reviewedAt).toLocaleString()}.</p>
      <p>Comparison captured at <time dateTime={receipt.checkedAt}>{new Date(receipt.checkedAt).toLocaleString()}</time>.</p>
      <ul aria-label="Reviewed comparison totals">
        <li>Matched {receipt.counts.matched}</li><li>Missing {receipt.counts.missing}</li><li>Changed {receipt.counts.changed}</li>
        <li>Need byte verification {receipt.counts.check_bytes}</li><li>Unsupported {receipt.counts.unsupported}</li>
      </ul>
      <p>Use a fresh comparison for decisions after {new Date(receipt.expiresAt).toLocaleTimeString()}.</p>
    </>}
    {!receipt&&<p>Waiting for the destination comparison.</p>}
    {state.role==='reviewer'&&<form className="release-form" onSubmit={event=>void review(event)}>
      <label>Paste destination comparison receipt<textarea name="proof" required maxLength={2048} rows={4} disabled={busy}/></label>
      <label>Authenticator code if prompted<input name="code" autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]{6}" disabled={busy}/></label>
      <button className="secondary" disabled={busy} type="submit">Verify destination receipt</button>
    </form>}
    {error&&<p role="alert">{error}</p>}
  </section>
}
