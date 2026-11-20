'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { Hand } from 'lucide-react'
import { db, liveChannel, onReconnect } from '../lib/data'

const reactions={
  clap:{emoji:'👏',label:'Clap',verb:'clapped'},
  thumbs_up:{emoji:'👍',label:'Thumbs up',verb:'gave a thumbs up'},
  heart:{emoji:'❤️',label:'Heart',verb:'sent a heart'},
  celebrate:{emoji:'🎉',label:'Celebrate',verb:'celebrated'},
} as const
type ReactionName=keyof typeof reactions
type HandState={user_id:string;raised_at:string;person:{name:string}|null}
type ReactionState={user_id:string;reaction:ReactionName;reacted_at:string;expires_at:string;person:{name:string}|null}

export function MeetingEngagement({meeting,user}:{meeting:string;user:string}) {
  const [hands,setHands]=useState<HandState[]|null>(null)
  const [recent,setRecent]=useState<ReactionState[]>([])
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)
  const version=useRef(0)

  const reload=useCallback(async()=>{
    const request=++version.current
    const [raised,reacted]=await Promise.all([
      db!.from('st_v6_meeting_hands').select('user_id,raised_at,person:st_profiles(name)')
        .eq('meeting_id',meeting).not('raised_at','is',null).order('raised_at').order('user_id').limit(12).returns<HandState[]>(),
      db!.from('st_v6_meeting_reactions').select('user_id,reaction,reacted_at,expires_at,person:st_profiles(name)')
        .eq('meeting_id',meeting).order('reacted_at').order('user_id').limit(12).returns<ReactionState[]>(),
    ])
    if(request!==version.current)return
    if(raised.error||reacted.error){setHands(null);setRecent([]);setError('Could not load meeting participation.');return}
    setHands(raised.data)
    setRecent(reacted.data)
  },[meeting])

  useEffect(()=>{
    const filter={schema:'public',filter:'meeting_id=eq.'+meeting} as const
    const channel=liveChannel('meeting-engagement:'+meeting,reload)
      .on('postgres_changes',{event:'INSERT',table:'st_v6_meeting_hands',...filter},reload)
      .on('postgres_changes',{event:'UPDATE',table:'st_v6_meeting_hands',...filter},reload)
      .on('postgres_changes',{event:'INSERT',table:'st_v6_meeting_reactions',...filter},reload)
      .on('postgres_changes',{event:'UPDATE',table:'st_v6_meeting_reactions',...filter},reload)
      .on('postgres_changes',{event:'UPDATE',table:'st_v3_attendance',...filter},reload)
      .subscribe(status=>{if(status==='SUBSCRIBED')void reload()})
    void reload()
    const reconnect=onReconnect(reload)
    const timer=window.setInterval(reload,5000)
    return()=>{++version.current;reconnect();window.clearInterval(timer);void db!.removeChannel(channel)}
  },[meeting,reload])

  useEffect(()=>{
    if(!recent.length)return
    const firstExpiry=Math.min(...recent.map(item=>Date.parse(item.expires_at)))
    const timer=window.setTimeout(()=>setRecent(previous=>previous.filter(item=>Date.parse(item.expires_at)>Date.now())),
      Math.max(0,firstExpiry-Date.now()))
    return()=>window.clearTimeout(timer)
  },[recent])

  const raised=hands?.some(hand=>hand.user_id===user)===true
  const name=(item:HandState|ReactionState)=>item.user_id===user?'You':item.person?.name||'Participant'
  async function act(value:boolean|ReactionName){
    if(busy)return
    setBusy(true);setError('')
    try{
      const result=typeof value==='boolean'
        ?await db!.rpc('st_v6_set_meeting_hand',{p_meeting:meeting,p_raised:value})
        :await db!.rpc('st_v6_send_meeting_reaction',{p_meeting:meeting,p_reaction:value})
      if(result.error)throw result.error
      await reload()
    }catch(error){
      const code=typeof error==='object'&&error!==null&&'code' in error?error.code:null
      setError(code==='PT429'?'Pause for a moment before sending another update.':'Could not update your meeting participation.')
    }finally{setBusy(false)}
  }

  return <section className="release-section" aria-label="Meeting participation">
    <h2>Raise hands and react</h2>
    {error&&<p role="alert" className="error">{error}</p>}
    <div className="release-row">
      <button type="button" className="secondary" disabled={busy||!hands} aria-pressed={raised} onClick={()=>void act(!raised)}>
        <Hand size={17}/>{raised?'Lower hand':'Raise hand'}
      </button>
      {Object.entries(reactions).map(([key,reaction])=><button type="button" key={key} className="secondary"
        aria-label={reaction.label} title={reaction.label} disabled={busy||!hands}
        onClick={()=>void act(key as ReactionName)}>{reaction.emoji}</button>)}
    </div>
    <div aria-live="polite">
      {hands?.length?<ul aria-label="Raised hands">{hands.map(item=><li key={item.user_id}>{name(item)}</li>)}</ul>:
        <p>{hands?'No hands raised.':'Loading meeting participation…'}</p>}
    </div>
    {recent.length>0&&<ul aria-label="Recent meeting reactions" aria-live="polite">
      {recent.map(item=><li key={item.user_id+item.reacted_at}><span aria-hidden="true">{reactions[item.reaction].emoji}</span> {name(item)} {reactions[item.reaction].verb}.</li>)}
    </ul>}
  </section>
}
