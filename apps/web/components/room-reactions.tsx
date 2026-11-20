'use client'

import dynamic from 'next/dynamic'
import {useCallback,useEffect,useRef,useState} from 'react'
import {db,formatError,liveChannel,onReconnect} from '../lib/data'
import {EmojiText} from './emoji-text'

const ChatEmoji=dynamic(()=>import('./chat-emoji'),{loading:()=> <p role="status">Loading emoji…</p>})
const sets={all:'All emoji',native:'Unicode emoji only',essential:'Essential reactions',off:'Reactions off'} as const
const essentials=[['👍','Thumbs up'],['❤️','Heart'],['✅','Check mark'],['👀','Eyes']] as const
export type RoomReactionPolicy={emoji_set:keyof typeof sets;per_person:number}
const defaultPolicy:RoomReactionPolicy={emoji_set:'all',per_person:8}
type RoomReaction={post_id:string;emoji:string;amount:number;mine:boolean}
const emptyCounts:Record<string,RoomReaction[]>={}

export function useWorkspaceReactionPolicy(workspace:string) {
  const [state,setState]=useState<{workspace:string;policy:RoomReactionPolicy|null;error:string}>()
  const version=useRef(0)
  const refresh=useCallback(async()=>{
    const request=++version.current
    const result=await db!.from('st_v6_workspace_reaction_policy')
      .select('emoji_set,per_person').eq('workspace_id',workspace).maybeSingle<RoomReactionPolicy>()
    if(request!==version.current)return
    setState({workspace,policy:result.error?null:result.data??defaultPolicy,error:result.error?'Could not load room reaction policy.':''})
  },[workspace])

  useEffect(()=>{
    const reload=()=>void refresh()
    const filter={schema:'public',table:'st_v6_workspace_reaction_policy',filter:'workspace_id=eq.'+workspace}
    const channel=liveChannel('workspace-reactions:'+workspace,reload)
      .on('postgres_changes',{...filter,event:'INSERT'},reload)
      .on('postgres_changes',{...filter,event:'UPDATE'},reload)
      .subscribe(status=>{if(status==='SUBSCRIBED')reload()})
    reload()
    const cleanup=onReconnect(reload)
    return ()=>{version.current++;cleanup();void db!.removeChannel(channel)}
  },[refresh,workspace])

  return {...(state?.workspace===workspace?state:{policy:null,error:''}),refresh}
}

export function RoomReactionSettings({workspace,policy,onSaved}:{
  workspace:string;policy:RoomReactionPolicy;onSaved:()=>Promise<void>
}) {
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [saved,setSaved]=useState(false)
  return <details>
    <summary>Room reaction settings</summary>
    <form className="release-form" onSubmit={async event=>{
      event.preventDefault()
      const fields=new FormData(event.currentTarget)
      setBusy(true);setError('');setSaved(false)
      try {
        const result=await db!.rpc('st_v6_set_workspace_reactions',{
          p_workspace:workspace,p_set:fields.get('emojiSet'),p_limit:Number(fields.get('perPerson')),
        })
        if(result.error)throw result.error
        await onSaved()
        setSaved(true)
      } catch(cause) {
        setError(formatError(cause,'Could not save room reaction settings.'))
      } finally {setBusy(false)}
    }}>
      <p>Choose the emoji and per-person limit for messages and thread replies in every room in this workspace.</p>
      <label>Room emoji set
        <select name="emojiSet" defaultValue={policy.emoji_set} key={policy.emoji_set} disabled={busy}>
          {Object.entries(sets).map(([value,label])=><option key={value} value={value}>{label}</option>)}
        </select>
      </label>
      <label>Reactions per person per message
        <select name="perPerson" defaultValue={policy.per_person} key={policy.per_person} disabled={busy}>
          {Array.from({length:8},(_,index)=>index+1).map(value=><option key={value} value={value}>{value}</option>)}
        </select>
      </label>
      <button className="primary" disabled={busy}>Save reaction settings</button>
      {saved&&<p role="status">Room reaction settings saved.</p>}
      {error&&<p role="alert" className="error">{error}</p>}
    </form>
  </details>
}

export function useRoomReactionCounts(room:string|null,ids:string[]) {
  const postKey=ids.join(',')
  const [state,setState]=useState<{room:string;postKey:string;items:Record<string,RoomReaction[]>;error:string}>()
  const version=useRef(0)
  const refresh=useCallback(async()=>{
    if(!room||!postKey)return
    const request=++version.current
    const posts=postKey.split(',')
    const batches=[]
    // Each post has at most 24 distinct reactions. Keep each response below the API row limit.
    for(let offset=0;offset<posts.length;offset+=40){
      batches.push(db!.rpc('st_v6_room_reaction_counts',{p_room:room,p_posts:posts.slice(offset,offset+40)}))
    }
    const results=await Promise.all(batches)
    if(request!==version.current)return
    if(results.some(result=>result.error)){
      setState({room,postKey,items:{},error:'Could not load room reactions.'})
      return
    }
    const items:Record<string,RoomReaction[]>={}
    for(const result of results){
      for(const reaction of (result.data??[]) as RoomReaction[]) (items[reaction.post_id]??=[]).push(reaction)
    }
    setState({room,postKey,items,error:''})
  },[room,postKey])

  useEffect(()=>{
    if(!room||!postKey)return
    const reload=()=>void refresh()
    const filter={schema:'public',table:'st_v6_room_reaction_changes',filter:'room_id=eq.'+room}
    const channel=liveChannel('room-reactions:'+room,reload)
      .on('postgres_changes',{...filter,event:'INSERT'},reload)
      .on('postgres_changes',{...filter,event:'UPDATE'},reload)
      .subscribe(status=>{if(status==='SUBSCRIBED')reload()})
    reload()
    const cleanup=onReconnect(reload)
    return ()=>{version.current++;cleanup();void db!.removeChannel(channel)}
  },[room,postKey,refresh])

  return {...(state?.room===room&&state?.postKey===postKey?state:{items:emptyCounts,error:''}),refresh}
}

export function RoomPostReactions({room,post,policy,reactions=[],canAdd,canRemove,onChange}:{
  room:string;post:string;policy:RoomReactionPolicy|null;reactions?:RoomReaction[]
  canAdd:boolean;canRemove:boolean;onChange:()=>Promise<void>
}) {
  const [open,setOpen]=useState(false)
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const available=canAdd&&policy&&policy.emoji_set!=='off'
  const atLimit=available&&reactions.filter(reaction=>reaction.mine).length>=policy.per_person
  async function setReaction(emoji:string,enabled:boolean) {
    setBusy(true);setError('')
    try {
      const result=await db!.rpc('st_v6_react_room_post',{p_room:room,p_post:post,p_emoji:emoji,p_enabled:enabled})
      if(result.error)throw result.error
      if(enabled)setOpen(false)
      await onChange()
    } catch(cause){
      setError(formatError(cause,'Could not update reaction.'))
    } finally {setBusy(false)}
  }

  if(!reactions.length&&!available)return null
  return <div role="group" aria-label="Room message reactions">
    <div className="action-row">
      {reactions.map(({emoji,amount,mine})=>{
        const label='Reaction '+emoji+', '+amount
        const content=<><EmojiText value={emoji}/> {amount}</>
        return mine&&canRemove
          ?<button key={emoji} type="button" className="secondary" title="Remove your reaction" aria-label={label}
            aria-pressed="true" disabled={busy} onClick={()=>void setReaction(emoji,false)}>{content}</button>
          :<span key={emoji} className="pill" role="img" aria-label={label}><span aria-hidden="true">{content}</span></span>
      })}
      {available&&<button className="secondary" type="button" aria-expanded={open&&!atLimit} disabled={busy||Boolean(atLimit)}
        onClick={()=>setOpen(value=>!value)}>Add room reaction</button>}
    </div>
    {atLimit&&<small className="muted">You reached the reaction limit for this message.</small>}
    {open&&available&&!atLimit&&(policy.emoji_set==='essential'
      ?<div className="action-row">{essentials.map(([emoji,label])=><button key={emoji} type="button" className="emoji-choice"
        disabled={busy} aria-label={label} onClick={()=>void setReaction(emoji,true)}>{emoji}</button>)}</div>
      :<ChatEmoji key={policy.emoji_set} allowCustom={policy.emoji_set==='all'} onPick={emoji=>{if(!busy)void setReaction(emoji,true)}}/>)}
    {error&&<p role="alert" className="error">{error}</p>}
  </div>
}
