'use client'

import {useEffect,useRef,useState} from 'react'
import {saveDownload} from '../lib/chat-files'
import {db} from '../lib/data'
import {openGroupFile,type GroupFileDescriptor} from '../lib/group-file-crypto'

export function GroupFileDownload({actor,group,epoch,message,file}:{actor:string;group:string;epoch:number;message:string;file:GroupFileDescriptor}){
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const active=useRef<AbortController|null>(null)
  useEffect(()=>()=>{active.current?.abort()},[actor,group,message,file.id])

  async function download(){
    if(active.current)return
    const controller=new AbortController()
    active.current=controller
    setBusy(true);setError('')
    try{
      const {data}=await db!.auth.getSession()
      if(data.session?.user.id!==actor)throw new Error('Sign in on the authorized browser to download this attachment.')
      const result=await fetch('/api/group-files?file='+file.id+'&message='+message,{
        headers:{Authorization:'Bearer '+data.session.access_token},cache:'no-store',signal:controller.signal,
      })
      if(!result.ok)throw new Error('This encrypted attachment is unavailable to your current browser.')
      const restored=await openGroupFile(group,epoch,file,await result.arrayBuffer())
      const current=await db!.auth.getSession()
      if(controller.signal.aborted||current.data.session?.user.id!==actor){new Uint8Array(restored).fill(0);return}
      const blob=new Blob([restored],{type:'application/octet-stream'})
      new Uint8Array(restored).fill(0)
      saveDownload(blob,file.name)
    }catch(cause){if(!controller.signal.aborted)setError(cause instanceof Error?cause.message:'Could not download the encrypted attachment.')}
    finally{if(active.current===controller){active.current=null;setBusy(false)}}
  }

  return <div className="actions">
    <button className="secondary" type="button" onClick={()=>void download()} disabled={busy}>
      {busy?'Verifying attachment…':'Download '+file.name}
    </button>
    <small>{Math.ceil(file.size/1024)} KiB · Encrypted attachment</small>
    {error&&<p className="error" role="alert">{error}</p>}
  </div>
}
