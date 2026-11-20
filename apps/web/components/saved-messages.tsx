'use client'

import { useCallback, useEffect, useState } from 'react'
import { Bookmark } from 'lucide-react'
import { db, onReconnect, type Message } from '../lib/data'
import { EmojiText } from './emoji-text'

export async function setSavedMessage(messageId: string, saved: boolean) {
  const collection = db!.from('st_v6_saved_messages')
  return saved
    ? collection.upsert({ message_id: messageId }, { onConflict: 'user_id,message_id', ignoreDuplicates: true })
    : collection.delete().eq('message_id', messageId)
}

type Saved = { message_id:string; saved_at:string; message:Message & { profile:{name:string} | null } }
const pageSize = 25

export function SavedMessages({ openChat }: { openChat:(id:string)=>void }) {
  const [rows,setRows] = useState<Saved[]|null>(null)
  const [older,setOlder] = useState(false)
  const [error,setError] = useState('')
  const [working,setWorking] = useState(false)
  const load = useCallback(async (before?: Saved) => {
    let query = db!.from('st_v6_saved_messages')
      .select('message_id,saved_at,message:st_messages!st_v6_saved_messages_message_id_fkey!inner(id,chat_id,sender,body,created_at,profile:st_profiles!st_messages_sender_fkey(name))')
    if (before) query = query.or('saved_at.lt.'+before.saved_at+',and(saved_at.eq.'+before.saved_at+',message_id.lt.'+before.message_id+')')
    const {data,error} = await query.order('saved_at',{ascending:false}).order('message_id',{ascending:false}).limit(pageSize+1).returns<Saved[]>()
    if(error){setError('Your saved messages could not be loaded.');return}
    setError('')
    setOlder(data.length>pageSize)
    setRows(previous=>before?[...(previous||[]),...data.slice(0,pageSize)]:data.slice(0,pageSize))
  },[])
  useEffect(()=>{
    void load()
    return onReconnect(()=>void load())
  },[load])

  return <section className="content-page">
    <header className="content-title"><div className="card-icon"><Bookmark size={22}/></div><div><h1>Saved messages</h1><p>Keep messages you want to find again.</p></div></header>
    {error&&<p className="error" role="alert">{error}</p>}
    <button type="button" className="secondary" disabled={working} onClick={()=>void load()}>Refresh</button>
    {!rows&&!error&&<p role="status">Loading saved messages…</p>}
    {rows?.length===0&&<p>Use a message’s action menu to save it here.</p>}
    {rows?.map(row=><article className="panel release-panel" key={row.message_id}>
      <h2>{row.message.profile?.name||'Contact'}</h2>
      <p className="meeting-agenda"><EmojiText value={row.message.body}/></p>
      <div className="action-row">
        <button type="button" className="secondary" onClick={()=>openChat(row.message.chat_id)}>Open conversation</button>
        <button type="button" className="text-button" disabled={working} onClick={async()=>{
          setWorking(true)
          try{
            const result=await setSavedMessage(row.message_id,false)
            if(result.error){setError('Could not remove the saved message.');return}
            setError('')
            setRows(previous=>previous?.filter(item=>item.message_id!==row.message_id)??null)
          }finally{setWorking(false)}
        }}>Remove from saved</button>
      </div>
    </article>)}
    {older&&rows&&rows.length>0&&<button type="button" className="secondary" disabled={working} onClick={async()=>{
      setWorking(true)
      try{await load(rows[rows.length-1])}finally{setWorking(false)}
    }}>Load more</button>}
  </section>
}
