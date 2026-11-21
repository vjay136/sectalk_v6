'use client'

import {useState,type FormEvent} from 'react'

export function DisclosureForm() {
  const [receipt,setReceipt]=useState('')
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)
  async function submit(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy||receipt) return
    const form=new FormData(event.currentTarget)
    setBusy(true)
    setError('')
    try {
      const response=await fetch('/api/security/disclosure',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({title:form.get('title'),feature:form.get('feature'),details:form.get('details'),contact:form.get('contact')})})
      const result=await response.json()
      if (!response.ok||!result.receipt) throw new Error(result.error||'Could not submit the report.')
      setReceipt(result.receipt)
    } catch(error) {setError(error instanceof Error?error.message:'Could not submit the report.')}
    finally {setBusy(false)}
  }
  if (receipt) return <div role="status"><p>Report received. Save this receipt for your records.</p><code>{receipt}</code></div>
  return <form onSubmit={submit} className="form-stack">
    <label>Title<input name="title" minLength={4} maxLength={160} required /></label>
    <label>Affected feature or version<input name="feature" maxLength={160} required /></label>
    <label>Report details<textarea name="details" minLength={20} maxLength={8000} rows={8} required /></label>
    <label>Reply email (optional)<input name="contact" type="email" autoComplete="email" maxLength={254} /></label>
    <button type="submit" className="primary" disabled={busy}>Submit private report</button>
    {error&&<p role="alert">{error}</p>}
  </form>
}
