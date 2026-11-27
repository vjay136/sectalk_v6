'use client'

import dynamic from 'next/dynamic'
import { useCallback, useEffect, useRef, useState } from 'react'
import { groupCommand,reportGroupPromotionFailure,type GroupState } from '../lib/group-call'
import { useGroupMesh } from '../lib/use-group-mesh'
import { cameraEffectsSupported, createCameraEffect, noCameraEffects, type CameraEffects } from '../lib/camera-effects'
import { GroupAudio, GroupVideo } from './group-call-sfu'
import { CameraEffectControls } from './call-panel'

const Shared=dynamic(()=>import('./group-call-sfu'),{ssr:false})
type Invite={id:string;owner:string;host_name:string;state:'invited'|'joined';video:boolean}
type Contact={id:string;name:string}

export function GroupCalls({user,contacts,inDirectCall}:{user:string;contacts:Contact[];inDirectCall:boolean}) {
  const [device]=useState(()=>crypto.randomUUID())
  const [invites,setInvites]=useState<Invite[]>([])
  const [selected,setSelected]=useState<string[]>([])
  const [active,setActive]=useState<GroupState|null>(null)
  const [source,setSource]=useState<MediaStream|null>(null)
  const [muted,setMuted]=useState(false)
  const [cameraOn,setCameraOn]=useState(false)
  const [effects,setEffects]=useState(noCameraEffects)
  const [effectPreview,setEffectPreview]=useState<MediaStream|null>(null)
  const [effectsBusy,setEffectsBusy]=useState(false)
  const [busy,setBusy]=useState(false)
  const [notice,setNotice]=useState('')
  const [sharedMedia,setSharedMedia]=useState(false)
  const [invited,setInvited]=useState<string[]>([])
  const activeRef=useRef<string|null>(null)
  const sourceRef=useRef<MediaStream|null>(null)
  const cameraTrack=useRef<MediaStreamTrack|null>(null)
  const cameraPublisher=useRef<((track:MediaStreamTrack)=>Promise<void>)|null>(null)
  const cameraEffect=useRef<{abort:AbortController;output?:Awaited<ReturnType<typeof createCameraEffect>>}|null>(null)
  const changingCamera=useRef(false)
  const mounted=useRef(false)
  const command=useCallback((action:string,call?:string,extra?:Record<string,unknown>)=>groupCommand(device,action,call,extra),[device])
  const activeId=active?.id
  const meshActive=Boolean(active?.mesh.includes(user))
  const mesh=useGroupMesh(meshActive?activeId ?? null:null,user,device,active?.mesh ?? [],source,Boolean(active?.video),command,cameraTrack)
  const groupName=useCallback((id:string)=>active?.names[id] || 'Participant',[active?.names])

  const clear=useCallback(()=>{
    cameraEffect.current?.abort.abort()
    cameraEffect.current=null
    cameraTrack.current=null
    setEffectPreview(null)
    setEffects(noCameraEffects)
    sourceRef.current?.getTracks().forEach(track=>track.stop())
    sourceRef.current=null
    activeRef.current=null
    setSource(null)
    setActive(null)
    setMuted(false)
    setCameraOn(false)
    setInvited([])
  },[])

  useEffect(()=>{
    const controller=new AbortController()
    void fetch('/api/group-calls',{cache:'no-store',signal:controller.signal})
      .then(response=>response.ok?response.json():null)
      .then(config=>{if (!controller.signal.aborted) setSharedMedia(config?.sfu===true)})
      .catch(()=>{})
    return ()=>controller.abort()
  },[])

  const refreshList=useCallback(async()=>{
    const list=await command('list')
    if (Array.isArray(list)) setInvites(list.filter(item=>item.state==='invited'))
  },[command])

  useEffect(()=>{
    mounted.current=true
    let disposed=false
    let timer:number|undefined
    async function update() {
      try {
        const call=activeRef.current
        if (call) {
          const state=await command('state',call) as GroupState|null
          if (!disposed && activeRef.current===call) {
            if (state) setActive(state)
            else {
              clear()
              setNotice('The group call ended or returned to the invitation.')
            }
          }
        } else if (!disposed) await refreshList()
      } catch {}
      if (!disposed) timer=window.setTimeout(()=>void update(),800)
    }
    void update()
    return ()=>{
      mounted.current=false
      disposed=true
      window.clearTimeout(timer)
      sourceRef.current?.getTracks().forEach(track=>track.stop())
      cameraEffect.current?.abort.abort()
      if (activeRef.current) void command('leave',activeRef.current).catch(()=>{})
    }
  },[clear,command,refreshList])

  const maxParticipants=sharedMedia?8:4
  const reservedContacts=new Set([...invited,...(active?.joined ?? []).filter(id=>id!==user)])
  const remainingInvites=maxParticipants-1-reservedContacts.size

  async function join(action:'create'|'accept',video:boolean,id?:string) {
    if (busy || activeRef.current || inDirectCall || (action==='create' && (!selected.length || selected.length>remainingInvites))) return
    setBusy(true)
    setNotice('')
    let capture:MediaStream|undefined
    try {
      capture=await navigator.mediaDevices.getUserMedia({audio:{echoCancellation:true,noiseSuppression:true,autoGainControl:true},video:false})
      if (!mounted.current) {
        capture.getTracks().forEach(track=>track.stop())
        return
      }
      if (video) {
        try {
          const videoStream=await navigator.mediaDevices.getUserMedia({audio:false,video:{width:{ideal:480},height:{ideal:360}}})
          for (const track of videoStream.getVideoTracks()) capture.addTrack(track)
        } catch { if (mounted.current) setNotice('Camera unavailable. Your microphone and incoming video are still available.') }
      }
      if (!mounted.current) {
        capture.getTracks().forEach(track=>track.stop())
        return
      }
      const state=await command(action,id,action==='create'?{p_targets:selected,p_video:video}:undefined) as GroupState|null
      if (!state) throw new Error('Group call unavailable')
      if (!mounted.current) {
        capture.getTracks().forEach(track=>track.stop())
        void command('leave',state.id).catch(()=>{})
        return
      }
      activeRef.current=state.id
      sourceRef.current=capture
      cameraTrack.current=capture.getVideoTracks()[0] ?? null
      setSource(capture)
      setCameraOn(capture.getVideoTracks().length>0)
      setActive(state)
      if (action==='create') setInvited(selected)
      setSelected([])
    } catch {
      capture?.getTracks().forEach(track=>track.stop())
      if (mounted.current) setNotice('Could not join the group call. Check your microphone or wait for the current handoff.')
    } finally { if (mounted.current) setBusy(false) }
  }
  async function decline(id:string) {
    try { await command('decline',id);await refreshList() }
    catch { setNotice('Could not decline this group call.') }
  }
  async function invite() {
    if (!active || !selected.length || selected.length>remainingInvites || busy) return
    setBusy(true)
    try {
      const state=await command('invite',active.id,{p_targets:selected}) as GroupState|null
      if (!state || activeRef.current!==active.id) return
      setActive(state)
      setInvited(previous=>[...previous,...selected])
      setSelected([])
    } catch { setNotice('Could not invite the selected contacts.') }
    finally { setBusy(false) }
  }
  async function leave() {
    const id=activeRef.current
    if (!id) return
    clear()
    try { await command('leave',id);await refreshList() }
    catch { setNotice('Your microphone is disconnected. Group membership could not be updated.') }
  }
  const ready=useCallback((generation:number)=>{
    if (activeId) void command('ready',activeId,{p_generation:generation}).catch(()=>{})
  },[activeId,command])
  const promotionFailed=useCallback((generation:number)=>{
    if (activeId && activeRef.current===activeId) {
      void reportGroupPromotionFailure(activeId,device,generation).then(()=>undefined,()=>undefined)
    }
  },[activeId,device])
  const reverse=active?.topology==='demoting'
  const generation=active?.generation
  const expectedPeers=(active?.mesh.length ?? 0)-1
  useEffect(()=>{
    if (reverse && generation!==undefined && mesh.connected===expectedPeers &&
      Object.values(mesh.remote).filter(media=>media.audio).length===expectedPeers) ready(generation)
  },[expectedPeers,generation,mesh.connected,mesh.remote,ready,reverse])
  function toggle() {
    const next=!muted
    for (const track of source?.getAudioTracks() ?? []) track.enabled=!next
    setMuted(next)
  }
  function toggleCamera() {
    const next=!cameraOn
    for (const track of source?.getVideoTracks() ?? []) track.enabled=next
    if (cameraTrack.current) cameraTrack.current.enabled=next
    setCameraOn(next)
  }
  async function applyEffects(next:CameraEffects) {
    const id=activeRef.current
    const camera=sourceRef.current?.getVideoTracks()[0]
    if (!id || !camera || changingCamera.current) return
    const previous=cameraTrack.current ?? camera
    const applied=cameraEffect.current
    const reset=next.filter==='natural' && next.decoration==='none'
    const pending=!reset && !applied ? {abort:new AbortController()} as NonNullable<typeof cameraEffect.current> : null
    if (pending) cameraEffect.current=pending
    changingCamera.current=true
    setEffectsBusy(true)
    try {
      if (pending) pending.output=await createCameraEffect(camera,next,pending.abort.signal)
      if (activeRef.current!==id) return
      if (!reset && applied?.output) applied.output.update(next)
      const output=pending?.output ?? (!reset ? applied?.output : undefined)
      const track=output?.track ?? camera
      if (previous!==track) {
        track.enabled=camera.enabled
        cameraTrack.current=track
        try {
          const results=await Promise.allSettled([mesh.replaceCamera(track),cameraPublisher.current?.(track)])
          if (results.some(result=>result.status==='rejected')) throw new Error('Could not publish group effect')
        } catch (error) {
          if (activeRef.current===id) {
            cameraTrack.current=previous
            await Promise.allSettled([mesh.replaceCamera(previous),cameraPublisher.current?.(previous)])
          }
          throw error
        }
      }
      if (activeRef.current!==id) return
      if (reset) { applied?.abort.abort();cameraEffect.current=null }
      setEffectPreview(output?.stream ?? null)
      setEffects(next)
    } catch {
      if (pending) {
        pending.abort.abort()
        if (cameraEffect.current===pending) cameraEffect.current=null
      }
      if (activeRef.current===id) setNotice('Could not change the group camera effect. Try again.')
    } finally {
      changingCamera.current=false
      if (mounted.current) setEffectsBusy(false)
    }
  }
  const candidateList=contacts.filter(contact=>!reservedContacts.has(contact.id))
  const mode=active?.video?'video':'audio'
  return <section className="release-section" aria-label="Group calls">
    <h2>Group calls</h2>
    {notice && <p role="status">{notice}</p>}
    {inDirectCall && <p>End the direct call before joining a group call.</p>}
    {!active && invites.map(invite=><div className="release-row" key={invite.id}>
      <p>{invite.host_name} invited you to group {invite.video?'video':'audio'}.</p>
      <button type="button" className="primary" disabled={busy||inDirectCall} onClick={()=>void join('accept',invite.video,invite.id)}>
        Join group {invite.video?'video':'audio'}
      </button>
      <button type="button" className="secondary" disabled={busy} onClick={()=>void decline(invite.id)}>Decline group invitation</button>
    </div>)}
    {(!active || active.owner===user) && candidateList.length>0 && <fieldset>
      <legend>Invite contacts</legend>
      <p>Up to {maxParticipants} people per call, including you.</p>
      {candidateList.map(contact=><label className="task-check" key={contact.id}>
        <input type="checkbox" checked={selected.includes(contact.id)} disabled={busy || selected.length>=remainingInvites&&!selected.includes(contact.id)}
          onChange={event=>setSelected(event.target.checked?[...selected,contact.id]:selected.filter(id=>id!==contact.id))}/>
        {contact.name}
      </label>)}
      {!active ? <>
        <button type="button" className="primary" disabled={busy||inDirectCall||!selected.length||selected.length>remainingInvites}
          onClick={()=>void join('create',false)}>Start group audio</button>
        <button type="button" className="secondary" disabled={busy||inDirectCall||!selected.length||selected.length>remainingInvites}
          onClick={()=>void join('create',true)}>Start group video</button>
      </>
        : <button type="button" className="secondary" disabled={busy||!selected.length||selected.length>remainingInvites}
          onClick={()=>void invite()}>Send group invitations</button>}
    </fieldset>}
    {active && <>
      <p role="status">{active.topology==='sfu'?'Group '+mode+' on shared media':
        active.topology==='promoting'?'Connecting shared group media':
        active.topology==='demoting'?'Connecting direct group peers':'Group '+mode+' on direct peers'}</p>
      <ul aria-label="Group roster">{active.joined.map(id=><li key={id}>{id===user?'You':groupName(id)}</li>)}</ul>
      <button type="button" className="secondary" onClick={toggle}>{muted?'Unmute group microphone':'Mute group microphone'}</button>
      {active.video && source?.getVideoTracks().length===1 && <>
        <button type="button" className="secondary" onClick={toggleCamera}>{cameraOn?'Turn group camera off':'Turn group camera on'}</button>
        <GroupVideo stream={effectPreview ?? source} visible={cameraOn} label="Your group camera"/>
        {cameraOn && (active.topology==='mesh' || active.topology==='sfu') && cameraEffectsSupported() &&
          <CameraEffectControls effects={effects} busy={effectsBusy} apply={next=>void applyEffects(next)}/>}
      </>}
      <button type="button" className="danger" onClick={()=>void leave()}>{active.owner===user?'End group ':'Leave group '}{mode}</button>
      {meshActive && <div data-group-route="mesh">
        {mesh.error && <p role="status">A direct media connection is not ready.</p>}
        {Object.entries(mesh.remote).map(([id,media])=><div key={id}>
          {media.audio && <GroupAudio stream={media.audio} label={'Group audio from '+groupName(id)} muted={reverse}/>}
          {media.video && <GroupVideo stream={media.video} label={'Group camera from '+groupName(id)} visible={!reverse}/>}
        </div>)}
      </div>}
      {source && active.topology!=='mesh' && <Shared key={active.sfuGeneration} call={active.id} device={device} generation={active.sfuGeneration}
        source={source} enabled={active.topology!=='promoting'} muted={muted} cameraOn={cameraOn} ready={ready} name={groupName}
        promotionFailed={promotionFailed} cameraTrack={cameraTrack} cameraPublisher={cameraPublisher}/>}
    </>}
  </section>
}
