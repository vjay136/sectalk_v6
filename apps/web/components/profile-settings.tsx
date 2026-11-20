'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'

type Extras = { status_message:string; photo_revision:string|null; share_last_seen:boolean }
type Counts = { sent:number;received:number;reports:number;open_reports:number }

export function useProfileExtras(user: string|undefined) {
  const [details,setDetails]=useState<{user:string;value:Extras}|null>(null)
  const [photo,setPhoto]=useState<{user:string;url:string}|null>(null)
  const refresh=useCallback(async()=>{
    if(!user)return
    const {data,error}=await db!.from('st_v5_profile_details').select('status_message,photo_revision,share_last_seen').eq('user_id',user).maybeSingle()
    if(error)return
    setDetails(previous=>previous?.user===user&&previous.value.photo_revision===data?.photo_revision&&previous.value.status_message===data?.status_message&&previous.value.share_last_seen===data?.share_last_seen
      ? previous : data?{user,value:data}:null)
  },[user])
  useEffect(()=>{
    void refresh()
    const timer=window.setInterval(refresh,14000)
    return ()=>window.clearInterval(timer)
  },[refresh])
  const revision=details?.user===user?details?.value.photo_revision:null
  useEffect(()=>{
    setPhoto(null)
    if(!user||!revision)return
    let live=true
    let url:string|undefined
    void db!.storage.from('sectalk-avatars').download(user+'.jpg').then(({data,error})=>{
      if(live&&!error){url=URL.createObjectURL(new Blob([data],{type:'image/jpeg'}));setPhoto({user,url})}
    })
    return ()=>{live=false;if(url)URL.revokeObjectURL(url)}
  },[revision,user])
  return {details:details?.user===user?details?.value:undefined,photo:photo?.user===user?photo?.url:undefined,refresh}
}

async function encodePhoto(file:File) {
  if(!['image/jpeg','image/png','image/webp'].includes(file.type)||file.size>6*1024*1024)
    throw new Error('Choose a JPEG, PNG, or WebP image up to 6 MiB.')
  const bitmap=await createImageBitmap(file)
  try{
    const canvas=document.createElement('canvas')
    canvas.width=256;canvas.height=256
    const context=canvas.getContext('2d')
    if(!context)throw new Error('Image processing is unavailable.')
    const side=Math.min(bitmap.width,bitmap.height)
    context.fillStyle='#ffffff'
    context.fillRect(0,0,256,256)
    context.drawImage(bitmap,(bitmap.width-side)/2,(bitmap.height-side)/2,side,side,0,0,256,256)
    return await new Promise<Blob>((resolve,reject)=>canvas.toBlob(blob=>{
      if(blob) resolve(blob)
      else reject(new Error('Could not prepare this image.'))
    },'image/jpeg',.88))
  }finally{bitmap.close()}
}

export function ProfileAppearance({user,profile}: {user:string;profile:ReturnType<typeof useProfileExtras>}) {
  const [error,setError]=useState('')
  const [message,setMessage]=useState('')
  const [busy,setBusy]=useState(false)
  async function savePhoto(file?:File) {
    if(busy)return
    setBusy(true);setError('');setMessage('')
    try{
      const bucket=db!.storage.from('sectalk-avatars')
      const path=user+'.jpg'
      const result=file ? await bucket.upload(path,await(await encodePhoto(file)).arrayBuffer(),{upsert:true,contentType:'image/jpeg',cacheControl:'0'}) : await bucket.remove([path])
      if(result.error)throw result.error
      const saved=await db!.rpc('st_v5_profile_details_save',{p_status:null,p_refresh_photo:true})
      if(saved.error)throw saved.error
      await profile.refresh()
      setMessage(file?'Profile photo updated.':'Profile photo removed.')
    }catch(error){setError(formatError(error,'Could not save your profile photo.'))}
    finally{setBusy(false)}
  }
  async function saveStatus(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    if(busy)return
    const status=String(new FormData(event.currentTarget).get('status'))
    setBusy(true);setError('');setMessage('')
    const result=await db!.rpc('st_v5_profile_details_save',{p_status:status,p_refresh_photo:false})
    if(result.error)setError(formatError(result.error,'Could not save status.'))
    else{await profile.refresh();setMessage(status?'Status updated.':'Status cleared.')}
    setBusy(false)
  }
  return <div className="panel release-panel release-section">
    <h2>Photo and text status</h2><p>Only you and your accepted, unblocked contacts can see these.</p>
    {profile.photo&&<img src={profile.photo} alt="Your profile photo" className="profile-photo-preview" width={96} height={96}/>}
    <div className="release-flex"><label>Upload profile photo<input type="file" disabled={busy} accept="image/jpeg,image/png,image/webp" onChange={event=>{
      const file=event.target.files?.[0];event.target.value=''
      if(file)void savePhoto(file)
    }}/></label>
      {profile.details?.photo_revision&&<button type="button" className="secondary" disabled={busy} onClick={()=>void savePhoto()}>Remove photo</button>}
    </div>
    <form className="release-form" onSubmit={saveStatus}><label>Text status<input key={profile.details?.status_message??''} name="status" maxLength={140}
      placeholder="Add a short status" defaultValue={profile.details?.status_message||''}/></label>
      <button className="primary" disabled={busy}>Save status</button></form>
    {error&&<p role="alert" className="error">{error}</p>}
    {message&&<p role="status">{message}</p>}
  </div>
}

export function ProfileActivity({openReports}: {openReports:()=>void}) {
  const [counts,setCounts]=useState<Counts|null>(null)
  const [error,setError]=useState(false)
  const refresh=useCallback(async()=>{
    const {data,error}=await db!.rpc('st_v5_profile_activity')
    if(error)setError(true)
    else{setError(false);setCounts(data)}
  },[])
  useEffect(()=>{void refresh()},[refresh])
  return <div className="panel release-panel"><h2>Your activity</h2><p>Message counts cover messages currently visible in your chats.</p>
    {counts&&<dl className="activity-stats">
      <div><dt>Messages sent</dt><dd>{counts.sent.toLocaleString()}</dd></div>
      <div><dt>Messages received</dt><dd>{counts.received.toLocaleString()}</dd></div>
      <div><dt>Reports submitted</dt><dd>{counts.reports.toLocaleString()}</dd></div>
      <div><dt>Reports open or in review</dt><dd>{counts.open_reports.toLocaleString()}</dd></div>
    </dl>}
    {error&&<p className="error" role="alert">Could not load your activity.</p>}
    {!counts&&!error&&<p role="status">Loading activity…</p>}
    <div className="action-row"><button className="secondary" onClick={()=>void refresh()}>Refresh</button>
      <button className="primary" onClick={openReports}>Track my reports</button></div>
  </div>
}
