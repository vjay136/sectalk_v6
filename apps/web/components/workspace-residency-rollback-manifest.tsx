'use client'

import {useCallback,useEffect,useState,type FormEvent} from 'react'
import {verifyAccountCredential} from '../lib/account-credential'
import {db,formatError} from '../lib/data'
import {workspaceFileRequest} from '../lib/workspace-files-client'

type ManifestState={
  state:'inactive'|'admission_required'|'review_required'|'ready'|'received'
  side?:'source'|'destination'
  digest?:string
  packetSha256?:string
  receivedAt?:string
  changeCount?:number
  packet?:{payload:string;signature:string}
}
type RetirementState={state:'inactive'|'review_required'|'admission_required'|'review_changed'|'ready'|'retired';
  retired?:boolean;receipt?:string;packet?:{payload:string;signature:string}}
type ReactivationState={state:'inactive'|'review_required'|'ready'|'reopened';receipt?:string}

export function WorkspaceResidencyRollbackManifest({workspace}:{workspace:string}) {
  const [manifest,setManifest]=useState<ManifestState>()
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [issued,setIssued]=useState(false)
  const [staged,setStaged]=useState('')
  const [retirement,setRetirement]=useState<RetirementState>()
  const [reactivation,setReactivation]=useState<ReactivationState>()
  const refresh=useCallback(async (signal?:AbortSignal)=>{
    const query=db!.rpc('st_v8_residency_rollback_manifest',{p_workspace:workspace})
    const result=await (signal?query.abortSignal(signal):query)
    if(signal?.aborted||result.error)return
    const next=result.data as ManifestState
    setManifest(next)
    if(next.side==='destination'){
      const token=db!.rpc('st_v8_residency_retire_destination',{p_workspace:workspace})
      const destination=await (signal?token.abortSignal(signal):token)
      if(!signal?.aborted&&!destination.error)setRetirement(destination.data as RetirementState)
    }else setRetirement(undefined)
    if(next.side==='source'&&next.state==='received'){
      const request=db!.rpc('st_v8_residency_reactivate_source',{p_workspace:workspace})
      const source=await (signal?request.abortSignal(signal):request)
      if(!signal?.aborted&&!source.error)setReactivation(source.data as ReactivationState)
    }else setReactivation(undefined)
  },[workspace])

  useEffect(()=>{
    const controller=new AbortController()
    void refresh(controller.signal)
    return ()=>controller.abort()
  },[refresh])

  async function verifyCredential(values:FormData) {
    const assurance=await db!.rpc('st_v7_sensitive_action_status',{p_kind:'room_role'})
    if(assurance.error)throw assurance.error
    if(assurance.data!=='verified'){
      const code=String(values.get('code')||'')
      if(!code)throw new Error('Enter a current authenticator code.')
      await verifyAccountCredential(code,true)
    }
  }

  async function stageFile(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if(busy||manifest?.state!=='received'||manifest.side!=='source')return
    const form=event.currentTarget
    const values=new FormData(form)
    setBusy(true);setError('');setStaged('')
    try {
      const packageFile=values.get('recovery-file')
      if(!(packageFile instanceof File)||!packageFile.size||packageFile.size>5600000){
        throw new Error('Choose a signed recovery file package containing a file up to 4 MiB.')
      }
      let file:File
      let id:string
      let rollbackProof:string
      try {
        const copy=JSON.parse(await packageFile.text())
        if(copy?.format!=='sectalk-residency-file-copy-v1'||typeof copy.contentBase64!=='string'||
          typeof copy.proof?.payload!=='string'||typeof copy.proof.signature!=='string')throw new Error()
        const proofBytes=new TextEncoder().encode(JSON.stringify({payload:copy.proof.payload,signature:copy.proof.signature}))
        if(proofBytes.length>4096)throw new Error()
        const claim=JSON.parse(copy.proof.payload)
        if(claim.workspace!==workspace||typeof claim.file!=='string'||
          !/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(claim.file))throw new Error()
        const bytes=Uint8Array.from(atob(copy.contentBase64),char=>char.charCodeAt(0))
        if(!bytes.length||bytes.length>4194304)throw new Error()
        id=claim.file
        file=new File([bytes],'recovery-copy',{type:'application/octet-stream'})
        rollbackProof=btoa(String.fromCharCode(...proofBytes)).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'')
      } catch { throw new Error('Choose a valid signed recovery file package for this workspace.') }
      await verifyCredential(values)
      const result=await workspaceFileRequest(workspace,'POST',{id,file,rollbackProof})
      const receipt=await result.json()
      if(receipt.state!=='staged'||receipt.file!==id)throw new Error('The recovery copy could not be verified in private staging.')
      form.reset()
      setStaged(id)
    } catch(cause){setError(formatError(cause,'Could not stage the rollback file.'))}
    finally{setBusy(false)}
  }

  async function retireDestination(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if(busy||!retirement||!['ready','retired'].includes(retirement.state))return
    const form=event.currentTarget
    const fields=new FormData(form)
    const confirmation=String(fields.get('workspace')||'')
    setBusy(true);setError('')
    try {
      if(confirmation!==workspace)throw new Error('Enter the exact workspace ID shown above.')
      await verifyCredential(fields)
      const result=await db!.rpc('st_v8_residency_retire_destination',{
        p_workspace:workspace,p_action:'issue',p_confirmation:confirmation,
      })
      if(result.error)throw result.error
      const next=result.data as RetirementState
      if(next.state!=='retired'||!next.packet)throw new Error('The destination retirement receipt could not be verified.')
      downloadPacket(next.packet,'sectalk-retired-destination-'+workspace+'.json')
      setRetirement({state:'retired',receipt:next.receipt})
      form.reset()
    }catch(cause){setError(formatError(cause,'Could not issue the destination retirement proof.'))}
    finally{setBusy(false)}
  }

  function downloadPacket(packet:{payload:string;signature:string},filename:string){
    const url=URL.createObjectURL(new Blob([JSON.stringify(packet)],{type:'application/json'}))
    const link=document.createElement('a')
    link.href=url
    link.download=filename
    link.click()
    window.setTimeout(()=>URL.revokeObjectURL(url),1000)
  }

  async function reopenSource(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if(busy||reactivation?.state!=='ready')return
    const form=event.currentTarget
    const fields=new FormData(form)
    const confirmation=String(fields.get('workspace')||'')
    setBusy(true);setError('')
    try {
      if(confirmation!==workspace)throw new Error('Enter the exact workspace ID shown above.')
      const file=fields.get('retirement')
      if(!(file instanceof File)||!file.size||file.size>3072)throw new Error('Choose the signed retirement proof JSON file.')
      let packet
      try{packet=JSON.parse(await file.text())}catch{throw new Error('Choose a valid retirement proof JSON file.')}
      await verifyCredential(fields)
      const result=await db!.rpc('st_v8_residency_reactivate_source',{
        p_workspace:workspace,p_action:'reopen',p_confirmation:confirmation,p_packet:packet,
      })
      if(result.error)throw result.error
      const next=result.data as ReactivationState
      if(next.state!=='reopened'||!next.receipt)throw new Error('The source reactivation receipt could not be verified.')
      setReactivation(next)
      form.reset()
    }catch(cause){setError(formatError(cause,'Could not reopen source writes.'))}
    finally{setBusy(false)}
  }

  async function transfer(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    if(busy||manifest?.state!=='ready')return
    const form=event.currentTarget
    const values=new FormData(form)
    const confirmation=String(values.get('workspace')||'')
    const issue=manifest.side==='destination'
    setBusy(true);setError('');setIssued(false)
    try {
      if(confirmation!==workspace)throw new Error('Enter the exact workspace ID shown above.')
      let packet
      if(!issue){
        const file=values.get('manifest')
        if(!(file instanceof File)||!file.size||file.size>4194304)throw new Error('Choose the signed manifest JSON file, up to 4 MB.')
        try{packet=JSON.parse(await file.text())}catch{throw new Error('Choose a valid signed manifest JSON file.')}
      }
      await verifyCredential(values)
      const result=await db!.rpc('st_v8_residency_rollback_manifest',{
        p_workspace:workspace,p_action:issue?'issue':'receive',p_confirmation:confirmation,p_packet:packet,
      })
      if(result.error)throw result.error
      const next=result.data as ManifestState
      if(issue&&next.packet){
        downloadPacket(next.packet,'sectalk-rollback-manifest-'+workspace+'.json')
        setIssued(true)
      }else setManifest(next)
      form.reset()
    } catch(cause){setError(formatError(cause,'Could not transfer the rollback manifest.'))}
    finally{setBusy(false)}
  }

  if(!manifest||manifest.state==='inactive')return null
  const destination=manifest.side==='destination'
  return <section className="release-section" aria-label="Rollback recovery manifest">
    <h4>Rollback recovery manifest</h4>
    {manifest.state==='admission_required'&&<p role="status">An approved recovery plan and transfer credential are required.</p>}
    {manifest.state==='review_required'&&<p role="status">The destination needs a current independent change review.</p>}
    {manifest.state==='received'&&<>
      <p role="status">The source verified the recovery manifest. Workspace writes remain held.</p>
      <p>{manifest.changeCount} reviewed {manifest.changeCount===1?'change':'changes'} · Review digest <code>{manifest.digest}</code></p>
      <p>Transfer digest <code>{manifest.packetSha256}</code></p>
      {!destination&&<form className="release-form" onSubmit={event=>void stageFile(event)}>
        <p>Stage a reviewed workspace file copy within five minutes of downloading it. Staged files stay private while rollback review continues.</p>
        <label>Signed recovery file<input name="recovery-file" type="file" accept=".json,application/json" required disabled={busy}/></label>
        <label>Authenticator code for file staging if prompted<input name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" disabled={busy}/></label>
        <button className="secondary" type="submit" disabled={busy}>Stage reviewed file copy</button>
      </form>}
      {staged&&<p role="status">File copy <code>{staged}</code> was staged in private storage. Workspace writes remain held.</p>}
    </>}
    {manifest.state==='received'&&!destination&&<section aria-label="Source reactivation">
      <h5>Source reactivation</h5>
      {reactivation?.state==='reopened'?<p role="status">Source write authority was restored. Destination writes remain retired.</p>:<>
        {reactivation?.state==='ready'?<form className="release-form" onSubmit={event=>void reopenSource(event)}>
          <p>Use the destination retirement proof within five minutes of downloading it. SecTalk rechecks the source sign-off before reopening writes.</p>
          <label>Confirm source reactivation workspace ID<input name="workspace" autoComplete="off" required disabled={busy}/></label>
          <label>Signed destination retirement proof<input name="retirement" type="file" accept=".json,application/json" required disabled={busy}/></label>
          <label>Authenticator code for source reactivation if prompted<input name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" disabled={busy}/></label>
          <button className="secondary" type="submit" disabled={busy}>Reopen source writes</button>
        </form>:<p>Complete independent source sign-off before reopening writes.</p>}
        <button className="secondary" disabled={busy} onClick={()=>void refresh()}>Refresh source reactivation status</button>
      </>}
    </section>}
    {manifest.state==='ready'&&<form className="release-form" onSubmit={event=>void transfer(event)}>
      <p>{destination?'Download the signed manifest and transfer it to the source owner within five minutes.':
        'Choose the signed manifest from the reviewed destination. Verification records the evidence while source writes stay held.'}</p>
      <p>Workspace ID <code>{workspace}</code></p>
      <label>Confirm recovery manifest workspace ID<input name="workspace" autoComplete="off" required disabled={busy}/></label>
      {!destination&&<label>Signed manifest file<input name="manifest" type="file" accept=".json,application/json" required disabled={busy}/></label>}
      <label>Authenticator code if prompted<input name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" disabled={busy}/></label>
      <button className="secondary" type="submit" disabled={busy}>{destination?'Download recovery manifest':'Verify recovery manifest'}</button>
    </form>}
    {issued&&<p role="status">The signed recovery manifest was prepared for download.</p>}
    {destination&&retirement&&(retirement.state==='ready'||retirement.state==='retired')&&
      <section aria-label="Destination retirement">
        <h5>Destination retirement</h5>
        <p>{retirement.state==='retired'?'Destination writes are durably retired. A new proof expires after five minutes.':
          'Retiring this installation keeps destination writes disabled. The proof binds retirement to the current independent change review.'}</p>
        {retirement.receipt&&<p role="status">Destination retirement receipt <code>{retirement.receipt}</code></p>}
        <form className="release-form" onSubmit={event=>void retireDestination(event)}>
          <label>Confirm destination retirement workspace ID<input name="workspace" autoComplete="off" required disabled={busy}/></label>
          <label>Authenticator code for destination retirement if prompted<input name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" disabled={busy}/></label>
          <button className="secondary" type="submit" disabled={busy}>{retirement.state==='retired'?'Download fresh retirement proof':'Retire destination and download proof'}</button>
        </form>
      </section>}
    {destination&&retirement?.retired&&retirement.state!=='retired'&&
      <p role="status">Destination writes remain retired. A current review and recovery credential are required to issue a proof.</p>}
    {manifest.state!=='received'&&<button className="secondary" disabled={busy} onClick={()=>void refresh()}>Refresh manifest status</button>}
    {error&&<p role="alert">{error}</p>}
  </section>
}
