'use client'

import { useEffect, useRef, useState } from 'react'
import { db, onReconnect } from '../lib/data'

const draftEvents=new EventTarget()
type Scope='chat'|'room'
type Revision={revision:number;body:string}
type DraftView={body:string;error:boolean;conflict:boolean;saved:boolean}
type DraftActions={change:(body:string)=>void;clear:(sent:string)=>void;resolve:(keepLocal:boolean)=>void;flush:()=>void}
const empty:DraftView={body:'',error:false,conflict:false,saved:false}

export function notifyDraftChange(payload:Record<string,unknown>){
  if(typeof payload.conversation==='string'&&(payload.scope==='chat'||payload.scope==='room')){
    draftEvents.dispatchEvent(new MessageEvent('draft',{data:payload}))
  }
}

export function useSyncedDraft(actor:string,scope:Scope,conversation:string,parent:string|null,enabled=true){
  const [view,setView]=useState<DraftView>(empty)
  const actions=useRef<DraftActions|null>(null)
  useEffect(()=>{
    setView(empty)
    if(!enabled){actions.current=null;return}
    const args={p_actor:actor,p_scope:scope,p_conversation:conversation,p_parent:parent}
    let visible=true
    let known=false
    let reading=false
    let saving=false
    let failed=false
    let dirty=false
    let body=''
    let server:Revision={revision:0,body:''}
    let conflict:Revision|null=null
    let timer:number|undefined

    function render(){
      if(visible)setView({body,error:failed,conflict:conflict!==null,saved:known&&!dirty&&!conflict})
    }
    function enqueue(){
      window.clearTimeout(timer)
      if(!visible){void flush();return}
      timer=window.setTimeout(()=>void flush(),400)
    }
    function accept(remote:Revision){
      if(known&&remote.revision<server.revision)return
      const changed=remote.revision!==server.revision&&remote.body!==server.body
      known=true
      server=remote
      if(!dirty){
        body=remote.body
        conflict=null
      }else if(body===remote.body){
        dirty=false
        conflict=null
      }else if(changed){
        conflict=remote
      }
    }
    async function reload(){
      if(reading||saving||!navigator.onLine)return
      reading=true
      const result=await db!.rpc('st_v6_read_draft',args)
      reading=false
      if(!visible&&!dirty)return
      failed=Boolean(result.error)
      if(!result.error)accept(result.data as Revision)
      render()
      if(dirty&&!failed&&!conflict)enqueue()
    }
    async function flush(){
      if(saving||!dirty||conflict)return
      if(!navigator.onLine){failed=true;render();return}
      if(!known){void reload();return}
      saving=true
      const submitted=body
      const result=await db!.rpc('st_v6_save_draft',{...args,p_expected:server.revision,p_body:submitted})
      saving=false
      failed=Boolean(result.error)
      if(!failed){
        const remote=result.data as Revision&{saved:boolean}
        if(remote.saved||remote.body===submitted){
          server=remote
          conflict=null
          dirty=body!==remote.body
        }else{
          accept(remote)
        }
      }
      render()
      if(dirty&&!failed&&!conflict)enqueue()
    }
    function change(value:string){
      body=value
      dirty=!known||body!==server.body
      failed=false
      if(!dirty)conflict=null
      render()
      enqueue()
    }
    actions.current={
      change,
      clear:sent=>{if(body.trim()===sent.trim())change('')},
      resolve:keepLocal=>{
        if(!conflict)return
        if(!keepLocal)body=conflict.body
        conflict=null
        dirty=body!==server.body
        render()
        if(dirty)void flush()
      },
      flush:()=>void flush(),
    }
    const onHint=(event:Event)=>{
      const data=(event as MessageEvent).data
      if(data.scope===scope&&data.conversation===conversation&&(data.parent??null)===parent)void reload()
    }
    draftEvents.addEventListener('draft',onHint)
    const stop=onReconnect(reload)
    const check=window.setInterval(()=>{if(document.visibilityState==='visible')void reload()},10000)
    void reload()
    return ()=>{
      visible=false
      window.clearTimeout(timer)
      window.clearInterval(check)
      draftEvents.removeEventListener('draft',onHint)
      stop()
      if(known)void flush()
    }
  },[actor,scope,conversation,parent,enabled])
  return {
    ...view,
    change:(body:string)=>actions.current?.change(body),
    clear:(sent:string)=>actions.current?.clear(sent),
    resolve:(keepLocal:boolean)=>actions.current?.resolve(keepLocal),
    flush:()=>actions.current?.flush(),
  }
}

export function DraftStatus({draft}:{draft:ReturnType<typeof useSyncedDraft>}){
  if(draft.conflict)return <div className="inline-warning" role="status">
    <span>Your draft changed on another device.</span>
    <button type="button" className="secondary" onClick={()=>draft.resolve(true)}>Keep this draft</button>
    <button type="button" className="secondary" onClick={()=>draft.resolve(false)}>Use synced draft</button>
  </div>
  if(draft.error&&draft.body)return <p className="muted" role="status">Draft is unsynced. SecTalk will retry when connected.</p>
  if(draft.saved&&draft.body)return <p className="muted" role="status">Draft saved to your devices.</p>
  return null
}
