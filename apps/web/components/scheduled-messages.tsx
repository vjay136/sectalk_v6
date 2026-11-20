'use client'

import { useCallback, useEffect, useState } from 'react'
import { db, formatError, liveChannel, onReconnect } from '../lib/data'
import { SectionTabs } from './section-tabs'

type Scheduled = {
  id:string; body:string|null; send_at:string; completed_at:string|null; state:'pending'|'sent'|'cancelled'|'failed'
}
const labels={pending:'Scheduled',sent:'Sent',cancelled:'Cancelled',failed:'Could not deliver'}

export function ScheduledMessages({chat,draft,canSchedule,schedule}:{
  chat:string; draft:string; canSchedule:boolean; schedule:(time:string)=>Promise<void>
}) {
  const [tab,setTab]=useState<'compose'|'upcoming'|'history'>(canSchedule?'compose':'upcoming')
  const [rows,setRows]=useState<{upcoming:Scheduled[];history:Scheduled[]}|null>(null)
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [notice,setNotice]=useState('')
  const load=useCallback(async()=>{
    const build=()=>db!.from('st_v6_scheduled_messages').select('id,body,send_at,state,completed_at').eq('chat_id',chat)
    const [upcoming,history]=await Promise.all([
      build().eq('state','pending').order('send_at').order('id').limit(50).returns<Scheduled[]>(),
      build().neq('state','pending').order('completed_at',{ascending:false}).order('id',{ascending:false}).limit(50).returns<Scheduled[]>(),
    ])
    if(upcoming.error||history.error){setError('Could not load scheduled messages.');return}
    setRows({upcoming:upcoming.data,history:history.data})
  },[chat])

  useEffect(()=>{
    void load()
    const channel=liveChannel('scheduled:'+chat,load)
      .on('postgres_changes',{event:'*',schema:'public',table:'st_v6_scheduled_messages',filter:'chat_id=eq.'+chat},load)
      .subscribe(status=>{if(status==='SUBSCRIBED')void load()})
    const timer=window.setInterval(()=>{if(document.visibilityState==='visible')void load()},12000)
    const reconnect=onReconnect(load)
    return ()=>{clearInterval(timer);reconnect();void db!.removeChannel(channel)}
  },[chat,load])

  async function cancel(id:string) {
    if(busy)return
    setBusy(true);setError('');setNotice('')
    try {
      const {data,error}=await db!.rpc('st_v6_cancel_scheduled_message',{p_id:id})
      if(error)throw error
      setNotice(data==='cancelled'?'Scheduled message cancelled.':'This message is no longer scheduled.')
      await load()
    }catch(error){setError(formatError(error,'Could not cancel the scheduled message.'))}
    finally{setBusy(false)}
  }

  const tabs=canSchedule||tab==='compose'
    ? [['compose','Schedule draft'],['upcoming','Upcoming'],['history','History']] as const
    : [['upcoming','Upcoming'],['history','History']] as const
  return <>
    <SectionTabs label="Scheduled message views" value={tab} onChange={next=>{if(!busy){setTab(next);setNotice('');setError('')}}} options={tabs}/>
    {error&&<p className="error" role="alert">{error}</p>}
    {notice&&<p role="status">{notice}</p>}
    {tab==='compose'?<form className="release-form" onSubmit={async event=>{
      event.preventDefault()
      if(busy||!canSchedule)return
      const date=new Date(String(new FormData(event.currentTarget).get('when')))
      if(!Number.isFinite(date.valueOf())||date.valueOf()<=Date.now()){setError('Choose a future date and time.');return}
      setBusy(true);setError('');setNotice('')
      try{
        await schedule(date.toISOString())
        setNotice('Message scheduled.');setTab('upcoming')
        await load()
      }catch(error){setError(formatError(error,'Could not schedule the message. Your draft is still here.'))}
      finally{setBusy(false)}
    }}>
      <p className="meeting-agenda">{draft}</p>
      <label>Send date and time<input type="datetime-local" name="when" required disabled={busy}/></label>
      <small>{Intl.DateTimeFormat().resolvedOptions().timeZone} · Choose a time within the next 30 days.</small>
      <button type="submit" className="primary" disabled={busy||!canSchedule}>Schedule message</button>
    </form>:<>
      {!rows&&!error&&<p role="status">Loading scheduled messages…</p>}
      {rows?.[tab].length===0&&<p>{tab==='upcoming'?'No messages are scheduled.':'No scheduled message history.'}</p>}
      {rows?.[tab].map(row=><article className="release-board-item" key={row.id}>
        <div className="release-row"><strong>{labels[row.state]}</strong><time dateTime={row.send_at}>{new Date(row.send_at).toLocaleString()}</time></div>
        {row.body&&<p>{row.body}</p>}
        {row.state==='pending'&&<button type="button" className="secondary" onClick={()=>void cancel(row.id)} disabled={busy}>Cancel schedule</button>}
      </article>)}
    </>}
  </>
}
