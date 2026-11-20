'use client'

import { useEffect, useId, useRef, useState } from 'react'
import { db } from '../lib/data'

const endpoint='/api/meetings/summaries'
type View={owner:boolean;policy:boolean;eligible:boolean;consented:boolean;revision:string|null}
type Draft={revision:string; summary:string; actions:string[]}
type Result=View & {draft?:{summary:string[];actions:string[]}}

async function request(meeting:string,action:string,enabled?:boolean,signal?:AbortSignal) {
  const {data}=await db!.auth.getSession()
  const response=await fetch(endpoint,{method:'POST',signal,headers:{
    Authorization:'Bearer '+data.session?.access_token,'Content-Type':'application/json',
  },body:JSON.stringify({meeting,action,enabled})})
  if (!response.ok) throw new Error('Meeting summary unavailable.')
  return response.json() as Promise<Result>
}

export function MeetingSummary({meeting}:{meeting:string}) {
  const editorId=useId()
  const [view,setView]=useState<View|null>(null)
  const [draft,setDraft]=useState<Draft|null>(null)
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [notice,setNotice]=useState('')
  const generation=useRef(0)

  useEffect(()=>{
    const controller=new AbortController()
    let timer:number|undefined
    async function refresh() {
      const revision=++generation.current
      const latest=await request(meeting,'view',undefined,controller.signal).catch(()=>null)
      if (controller.signal.aborted || revision!==generation.current) return
      setView(latest)
      setDraft(current=>current?.revision===latest?.revision && latest?.policy ? current : null)
    }
    void fetch(endpoint,{signal:controller.signal}).then(response=>response.json()).then(value=>{
      if (controller.signal.aborted || !value.configured) return
      void refresh()
      timer=window.setInterval(()=>void refresh(),5000)
    }).catch(()=>{})
    return ()=>{controller.abort();window.clearInterval(timer)}
  },[meeting])

  async function act(action:string,enabled?:boolean) {
    if (busy) return
    ++generation.current
    setBusy(true)
    setError('')
    setNotice('')
    if (action==='withdraw' || enabled===false) setDraft(null)
    try {
      const next=await request(meeting,action,enabled)
      ++generation.current
      setView(next)
      if (next.draft && next.revision) setDraft({
        revision:next.revision,summary:next.draft.summary.join('\n'),actions:next.draft.actions,
      })
    } catch { setError('The summary action could not be completed.') }
    finally { setBusy(false) }
  }

  async function copy() {
    if (!draft) return
    setNotice('')
    setError('')
    try {
      const latest=await request(meeting,'view')
      if (!latest.policy || latest.revision!==draft.revision) {
        setView(latest)
        setDraft(null)
        setError('Transcript permissions changed. Generate a new draft.')
        return
      }
      const actions=draft.actions.map(action=>action.trim()).filter(Boolean).map(action=>'- '+action)
      const blocks=[draft.summary.trim(),actions.length?'Action items\n'+actions.join('\n'):''].filter(Boolean)
      if (blocks.length) {
        await navigator.clipboard.writeText(blocks.join('\n\n'))
        setNotice('Draft copied.')
      }
    } catch { setError('Could not copy the draft.') }
  }

  if (!view || (!view.owner && !view.eligible && !view.consented)) return null
  const canEdit=Boolean(view.eligible && view.consented && view.policy && draft?.revision===view.revision)
  return <section className="release-section" aria-label="Meeting summary">
    <h3>Meeting summary draft</h3>
    {view.owner && <button type="button" className="secondary" disabled={busy}
      onClick={()=>void act('policy',!view.policy)}>{view.policy?'Disable workspace summaries':'Allow workspace summaries'}</button>}
    {!view.policy && <p>Meeting summaries are disabled for this workspace.</p>}
    {view.eligible && view.policy && !view.consented && <>
      <p>Allow your transcript lines to be used in summary drafts for opted-in participants. You can withdraw consent at any time.</p>
      <button type="button" className="primary" disabled={busy} onClick={()=>void act('opt-in')}>Opt in to meeting summaries</button>
    </>}
    {view.consented && <button type="button" className="secondary" disabled={busy}
      onClick={()=>void act('withdraw')}>Withdraw summary consent</button>}
    {view.eligible && view.policy && view.consented && <>
      <button type="button" className="primary" disabled={busy || !view.revision}
        onClick={()=>void act('generate')}>Generate summary draft</button>
      {!view.revision && <p>No eligible transcript lines yet.</p>}
    </>}
    {canEdit && draft && <div className="release-row">
      <label htmlFor={editorId}>Summary text</label>
      <textarea id={editorId} rows={5} maxLength={1400} value={draft.summary}
        onChange={event=>setDraft({...draft,summary:event.target.value})}/>
      {draft.actions.map((action,index)=><div className="release-row" key={index}>
        <label htmlFor={editorId+'-action-'+index}>Suggested action {index+1}</label>
        <input id={editorId+'-action-'+index} maxLength={220} value={action} onChange={event=>setDraft({...draft,
          actions:draft.actions.map((item,position)=>position===index?event.target.value:item)})}/>
        <button type="button" className="secondary" aria-label={'Remove action '+(index+1)}
          onClick={()=>setDraft({...draft,actions:draft.actions.filter((_,position)=>position!==index)})}>Remove</button>
      </div>)}
      <button type="button" className="secondary" disabled={draft.actions.length===6}
        onClick={()=>setDraft({...draft,actions:[...draft.actions,'']})}>Add action item</button>
      <button type="button" className="secondary" onClick={()=>void copy()}>Copy draft</button>
    </div>}
    {notice && <p role="status">{notice}</p>}
    {error && <p role="alert">{error}</p>}
  </section>
}
