'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { Camera, Check, Trash2, X } from 'lucide-react'
import { db, formatError } from '../lib/data'
import { Avatar } from './avatar'
import { downloadProfilePhoto } from './contact-photos'

type Extras = { status_message:string; photo_revision:string|null; share_last_seen:boolean }
type Counts = { sent:number;received:number;reports:number;open_reports:number }

export function useProfileExtras(user: string|undefined) {
  const [details,setDetails]=useState<{user:string;value:Extras}|null>(null)
  const [photo,setPhoto]=useState<{user:string;revision:string;url?:string}|null>(null)
  const [loading,setLoading]=useState(true)
  const [loadError,setLoadError]=useState(false)
  const [retry,setRetry]=useState(0)
  const refresh=useCallback(async()=>{
    if(!user)return
    const {data,error}=await db!.from('st_v5_profile_details').select('status_message,photo_revision,share_last_seen').eq('user_id',user).maybeSingle()
    setLoading(false)
    setLoadError(!!error)
    if(error)return
    setDetails(previous=>previous?.user===user&&previous.value.photo_revision===data?.photo_revision&&previous.value.status_message===data?.status_message&&previous.value.share_last_seen===data?.share_last_seen
      ? previous : data?{user,value:data}:null)
  },[user])
  useEffect(()=>{
    void refresh()
    const sync=()=>{if(document.visibilityState==='visible')void refresh()}
    window.addEventListener('focus',sync)
    return ()=>window.removeEventListener('focus',sync)
  },[refresh])
  const revision=details?.user===user?details?.value.photo_revision:null
  useEffect(()=>{
    if(!user||!revision)return
    const controller=new AbortController()
    let url:string|undefined
    void downloadProfilePhoto(user,controller.signal).then(data=>{
      if(controller.signal.aborted)return
      url=URL.createObjectURL(data)
      setPhoto({user,revision,url})
    }).catch(()=>{
      if(!controller.signal.aborted)setPhoto({user,revision})
    })
    return ()=>{controller.abort();if(url)URL.revokeObjectURL(url)}
  },[revision,user,retry])
  const currentPhoto=photo?.user===user&&photo?.revision===revision?photo:null
  return {
    details:details?.user===user?details?.value:undefined,photo:currentPhoto?.url,refresh,
    loadingPhoto:loading||Boolean(revision&&!currentPhoto),photoError:loadError||Boolean(currentPhoto&&!currentPhoto.url),
    retryPhoto:()=>{void refresh();setPhoto(null);setRetry(value=>value+1)},
  }
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

export function ProfileAppearance({user,name,profile}: {user:string;name:string;profile:ReturnType<typeof useProfileExtras>}) {
  const fileInput=useRef<HTMLInputElement>(null)
  const pickerButton=useRef<HTMLButtonElement>(null)
  const previewRef=useRef<string|undefined>(undefined)
  const editorMounted=useRef(false)
  const [pending,setPending]=useState<{blob:Blob;url:string}|null>(null)
  const [photoError,setPhotoError]=useState('')
  const [photoMessage,setPhotoMessage]=useState('')
  const [work,setWork]=useState<'prepare'|'save'|'remove'|null>(null)
  const [statusError,setStatusError]=useState('')
  const [statusMessage,setStatusMessage]=useState('')
  const [statusBusy,setStatusBusy]=useState(false)
  function clearPreview(){
    if(previewRef.current)URL.revokeObjectURL(previewRef.current)
    previewRef.current=undefined
    setPending(null)
  }
  useEffect(()=>{
    editorMounted.current=true
    return ()=>{
      editorMounted.current=false
      if(previewRef.current)URL.revokeObjectURL(previewRef.current)
    }
  },[])
  function focusPicker(){
    window.requestAnimationFrame(()=>pickerButton.current?.focus())
  }
  async function preparePhoto(file:File){
    setWork('prepare');setPhotoError('');setPhotoMessage('')
    try {
      const blob=await encodePhoto(file)
      if(!editorMounted.current)return
      clearPreview()
      const url=URL.createObjectURL(blob)
      previewRef.current=url
      setPending({blob,url})
      setPhotoMessage('Preview ready. Save to use this photo.')
    } catch(error){setPhotoError(formatError(error,'Could not preview this image.'))}
    finally{setWork(null)}
  }
  async function savePhoto(blob?:Blob) {
    if(work)return
    setWork(blob?'save':'remove');setPhotoError('');setPhotoMessage('')
    try{
      const bucket=db!.storage.from('sectalk-avatars')
      const path=user+'.jpg'
      const result=blob ? await bucket.upload(path,await blob.arrayBuffer(),{upsert:true,contentType:'image/jpeg',cacheControl:'0'}) : await bucket.remove([path])
      if(result.error)throw result.error
      const saved=await db!.rpc('st_v5_profile_details_save',{p_status:null,p_refresh_photo:true})
      if(saved.error)throw saved.error
      await profile.refresh()
      clearPreview()
      setPhotoMessage(blob?'Profile photo updated.':'Profile photo removed.')
      focusPicker()
    }catch(error){setPhotoError(formatError(error,blob?'Could not save your profile photo.':'Could not remove your profile photo.'))}
    finally{setWork(null)}
  }
  async function saveStatus(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    if(statusBusy||work)return
    const status=String(new FormData(event.currentTarget).get('status'))
    setStatusBusy(true);setStatusError('');setStatusMessage('')
    const result=await db!.rpc('st_v5_profile_details_save',{p_status:status,p_refresh_photo:false})
    if(result.error)setStatusError(formatError(result.error,'Could not save status.'))
    else{await profile.refresh();setStatusMessage(status?'Status updated.':'Status cleared.')}
    setStatusBusy(false)
  }
  return <div className="panel release-panel release-section">
    <h2>Photo and text status</h2><p>Visible only to you and your accepted, unblocked contacts.</p>
    <div className="profile-photo-editor">
      <Avatar name={name} photo={pending?.url||profile.photo} className="profile-photo-preview"/>
      <div className="profile-photo-meta">
        <strong>{pending?'Photo preview':'Profile photo'}</strong>
        <small id="profile-photo-help">JPEG, PNG, or WebP up to 6 MiB. Your photo is cropped to a square.</small>
        <div className="profile-photo-actions">
          <button ref={pickerButton} type="button" className="secondary" disabled={!!work||statusBusy} aria-describedby="profile-photo-help"
            onClick={()=>fileInput.current?.click()}><Camera size={16} aria-hidden="true"/>{pending?'Choose another':profile.details?.photo_revision?'Change photo':'Add photo'}</button>
          <input ref={fileInput} type="file" hidden aria-label="Upload profile photo" disabled={!!work||statusBusy} accept="image/jpeg,image/png,image/webp" onChange={event=>{
            const file=event.target.files?.[0];event.target.value=''
            if(file)void preparePhoto(file)
          }}/>
          {pending ? <>
            <button type="button" className="primary" disabled={!!work||statusBusy} onClick={()=>void savePhoto(pending.blob)}><Check size={16} aria-hidden="true"/>Save photo</button>
            <button type="button" className="secondary" disabled={!!work||statusBusy} onClick={()=>{clearPreview();setPhotoError('');setPhotoMessage('Photo change discarded.');focusPicker()}}><X size={16} aria-hidden="true"/>Cancel</button>
          </> : profile.details?.photo_revision&&<button type="button" className="secondary" disabled={!!work||statusBusy} onClick={()=>void savePhoto()}><Trash2 size={16} aria-hidden="true"/>Remove photo</button>}
        </div>
        {(work||(!pending&&profile.loadingPhoto)||photoMessage)&&<small role="status">
          {work==='prepare'?'Preparing preview…':work==='save'?'Saving photo…':work==='remove'?'Removing photo…':photoMessage||'Loading profile photo…'}
        </small>}
        {photoError&&<small className="error" role="alert">{photoError}</small>}
        {!pending&&!photoError&&profile.photoError&&<small className="profile-photo-retry"><span role="alert">Could not load profile photo.</span>
          <button type="button" className="text-button" onClick={profile.retryPhoto}>Retry</button></small>}
      </div>
    </div>
    <form className="release-form profile-status" onSubmit={saveStatus}><label>Text status<input key={profile.details?.status_message??''} name="status" maxLength={140}
      placeholder="Add a short status" defaultValue={profile.details?.status_message||''}/></label>
      <button className="primary" disabled={statusBusy||!!work}>{statusBusy?'Saving status…':'Save status'}</button>
      {statusError&&<p role="alert" className="error">{statusError}</p>}
      {statusMessage&&<p role="status">{statusMessage}</p>}
    </form>
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
